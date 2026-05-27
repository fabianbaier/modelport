import { createHash, randomBytes, randomUUID } from "node:crypto";
import { createReadStream } from "node:fs";
import { mkdir } from "node:fs/promises";
import { createServer, type IncomingMessage, type Server, type ServerResponse } from "node:http";
import { tmpdir } from "node:os";
import { extname, join, resolve } from "node:path";
import {
  DEFAULT_SERVICE_ROLES,
  isRole,
  optionalString,
  parseHostPort,
  parseLocalBind,
  redactSecretLike,
  requireSlug,
  requireString,
  type Actor,
  type AuthSession,
  type AuditEvent,
  type Device,
  type HubState,
  type Invite,
  type Membership,
  type ModelDescriptor,
  type Role,
  type ServiceKind,
  type Team,
  type TunnelCredential,
  type TunnelDirection,
  type TunnelHost,
  type TunnelService,
  type TunnelSession,
  type User
} from "../../../packages/protocol/src/index.js";
import { JsonStore } from "./state.js";

const DEFAULT_PORT = 8787;
const DEFAULT_TUNNEL_HOST = "127.0.0.1";
const DEFAULT_TUNNEL_PORT = 2222;
const DEFAULT_TUNNEL_USER = "modelport";
const SESSION_COOKIE = "modelport_session";
const SESSION_TTL_DAYS = 30;

export interface HubServerOptions {
  dataDir: string;
  webDir: string;
  tunnelHost?: string;
  tunnelPort?: number;
  tunnelUser?: string;
  publicBaseUrl?: string;
  allowDevAuth?: boolean;
}

interface RequestContext {
  req: IncomingMessage;
  res: ServerResponse;
  url: URL;
  actor?: Actor;
  body: Record<string, unknown>;
}

interface HttpError extends Error {
  status?: number;
  code?: string;
}

function nowIso(): string {
  return new Date().toISOString();
}

function daysFromNow(days: number): string {
  return new Date(Date.now() + days * 24 * 60 * 60 * 1000).toISOString();
}

function minutesFromNow(minutes: number): string {
  return new Date(Date.now() + minutes * 60 * 1000).toISOString();
}

function id(prefix: string): string {
  return `${prefix}_${randomUUID().replaceAll("-", "")}`;
}

function sessionToken(): string {
  return `mp_${randomBytes(32).toString("base64url")}`;
}

function inviteToken(): string {
  return `invite_${randomBytes(32).toString("base64url")}`;
}

function tokenHash(token: string): string {
  return createHash("sha256").update(token).digest("base64url");
}

function userIdForEmail(email: string): string {
  return `dev_${createHash("sha256").update(email).digest("hex").slice(0, 16)}`;
}

function fingerprintForPublicKey(publicKey: string): string {
  return `SHA256:${createHash("sha256").update(publicKey).digest("base64url")}`;
}

function normalizeEmail(value: unknown): string {
  const email = requireString(value, "email").toLowerCase();
  if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email) || email.length > 254) {
    throw httpError(400, "invalid_email", "email must be a valid email address");
  }
  return email;
}

function isExpired(iso: string): boolean {
  return Date.parse(iso) <= Date.now();
}

function sanitizedInvite(invite: Invite): Omit<Invite, "token_hash"> {
  const { token_hash: _tokenHash, ...safeInvite } = invite;
  return safeInvite;
}

function httpError(status: number, code: string, message: string): HttpError {
  const err = new Error(message) as HttpError;
  err.status = status;
  err.code = code;
  return err;
}

function cookieValue(req: IncomingMessage, name: string): string | undefined {
  const raw = req.headers.cookie;
  if (!raw) {
    return undefined;
  }
  for (const part of raw.split(";")) {
    const [key, ...rest] = part.trim().split("=");
    if (key === name) {
      return decodeURIComponent(rest.join("="));
    }
  }
  return undefined;
}

function bearerToken(req: IncomingMessage): string | undefined {
  const auth = req.headers.authorization;
  if (!auth?.startsWith("Bearer ")) {
    return undefined;
  }
  return auth.slice("Bearer ".length).trim();
}

function tokenFromRequest(req: IncomingMessage): string | undefined {
  return bearerToken(req) || cookieValue(req, SESSION_COOKIE);
}

function devActorFromRequest(req: IncomingMessage, allowDevAuth: boolean): Actor | undefined {
  if (!allowDevAuth) {
    return undefined;
  }
  const token = bearerToken(req);
  if (token?.startsWith("dev:")) {
    const email = normalizeEmail(token.slice("dev:".length));
    return { user_id: userIdForEmail(email), email };
  }
  const header = req.headers["x-modelport-user"];
  if (typeof header === "string" && header.trim()) {
    const email = normalizeEmail(header);
    return { user_id: userIdForEmail(email), email };
  }
  if (process.env.NODE_ENV !== "production") {
    return { user_id: userIdForEmail("local@modelport.dev"), email: "local@modelport.dev" };
  }
  return undefined;
}

async function actorFromRequest(req: IncomingMessage, store: JsonStore, allowDevAuth: boolean): Promise<Actor | undefined> {
  const token = tokenFromRequest(req);
  if (token && !token.startsWith("dev:")) {
    const hash = tokenHash(token);
    const state = await store.read();
    const session = state.auth_sessions.find(
      (item) => item.token_hash === hash && item.status === "active" && !isExpired(item.expires_at)
    );
    const user = session
      ? state.users.find((item) => item.user_id === session.user_id && item.status === "active")
      : undefined;
    if (session && user) {
      return { user_id: user.user_id, email: user.email };
    }
  }
  return devActorFromRequest(req, allowDevAuth);
}

function requireActor(actor: Actor | undefined): Actor {
  if (!actor) {
    throw httpError(401, "auth_required", "sign in required");
  }
  return actor;
}

async function readBody(req: IncomingMessage): Promise<Record<string, unknown>> {
  if (req.method === "GET" || req.method === "HEAD") {
    return {};
  }
  const chunks: Buffer[] = [];
  for await (const chunk of req) {
    chunks.push(Buffer.isBuffer(chunk) ? chunk : Buffer.from(chunk));
  }
  if (chunks.length === 0) {
    return {};
  }
  const raw = Buffer.concat(chunks).toString("utf8");
  try {
    const parsed = JSON.parse(raw) as unknown;
    if (!parsed || typeof parsed !== "object" || Array.isArray(parsed)) {
      throw new Error("JSON body must be an object");
    }
    return parsed as Record<string, unknown>;
  } catch (error) {
    throw httpError(400, "invalid_json", (error as Error).message);
  }
}

function sendJson(res: ServerResponse, status: number, value: unknown, headers: Record<string, string> = {}): void {
  const data = JSON.stringify(value, null, 2);
  res.writeHead(status, {
    "content-type": "application/json; charset=utf-8",
    "cache-control": "no-store",
    "access-control-allow-origin": "*",
    "access-control-allow-headers": "authorization, content-type, x-modelport-user",
    "access-control-allow-methods": "GET,POST,OPTIONS",
    ...headers
  });
  res.end(`${data}\n`);
}

function sendNoContent(res: ServerResponse, headers: Record<string, string> = {}): void {
  res.writeHead(204, {
    "access-control-allow-origin": "*",
    "access-control-allow-headers": "authorization, content-type, x-modelport-user",
    "access-control-allow-methods": "GET,POST,OPTIONS",
    ...headers
  });
  res.end();
}

function requestOrigin(req: IncomingMessage, publicBaseUrl?: string): string {
  if (publicBaseUrl) {
    return publicBaseUrl.replace(/\/+$/, "");
  }
  const forwardedProto = req.headers["x-forwarded-proto"];
  const proto =
    typeof forwardedProto === "string" && forwardedProto.trim()
      ? forwardedProto.split(",")[0].trim()
      : "http";
  const forwardedHost = req.headers["x-forwarded-host"];
  const host =
    typeof forwardedHost === "string" && forwardedHost.trim()
      ? forwardedHost.split(",")[0].trim()
      : req.headers.host || "127.0.0.1";
  return `${proto}://${host}`;
}

function sessionCookie(req: IncomingMessage, token: string): string {
  const forwardedProto = req.headers["x-forwarded-proto"];
  const isSecure =
    process.env.MODELPORT_COOKIE_SECURE === "1" ||
    (typeof forwardedProto === "string" && forwardedProto.split(",")[0].trim() === "https");
  return `${SESSION_COOKIE}=${encodeURIComponent(token)}; Path=/; HttpOnly; SameSite=Lax; Max-Age=${
    SESSION_TTL_DAYS * 24 * 60 * 60
  }${isSecure ? "; Secure" : ""}`;
}

function clearSessionCookie(): string {
  return `${SESSION_COOKIE}=; Path=/; HttpOnly; SameSite=Lax; Max-Age=0`;
}

function addAudit(state: HubState, actor: Actor, event: Omit<AuditEvent, "event_id" | "actor_user_id" | "created_at">): void {
  state.audit.push({
    event_id: id("audit"),
    actor_user_id: actor.user_id,
    created_at: nowIso(),
    ...event
  });
}

function findMembership(state: HubState, teamId: string, actor: Actor): Membership | undefined {
  return state.memberships.find(
    (item) => item.team_id === teamId && item.user_id === actor.user_id && item.status === "active"
  );
}

function requireTeamAccess(state: HubState, teamId: string, actor: Actor, roles?: Role[]): Membership {
  const membership = findMembership(state, teamId, actor);
  if (!membership) {
    throw httpError(403, "team_forbidden", "caller is not an active member of this team");
  }
  if (roles && !roles.includes(membership.role)) {
    throw httpError(403, "role_forbidden", "caller role is not allowed for this action");
  }
  return membership;
}

function findTeamByIdOrSlug(state: HubState, value: string, actor: Actor): Team {
  const team = state.teams.find((item) => item.team_id === value || item.slug === value);
  if (!team || team.status !== "active") {
    throw httpError(404, "team_not_found", "team not found");
  }
  requireTeamAccess(state, team.team_id, actor);
  return team;
}

function requireService(state: HubState, serviceIdOrName: string, teamId: string, actor: Actor): TunnelService {
  requireTeamAccess(state, teamId, actor);
  const service = state.services.find(
    (item) =>
      item.team_id === teamId &&
      item.status !== "revoked" &&
      (item.service_id === serviceIdOrName || item.name === serviceIdOrName)
  );
  if (!service) {
    throw httpError(404, "service_not_found", "service not found");
  }
  const membership = requireTeamAccess(state, teamId, actor);
  if (!service.acl.roles.includes(membership.role)) {
    throw httpError(403, "service_forbidden", "caller role is not allowed for this service");
  }
  return service;
}

function getOrCreateUser(state: HubState, email: string): User {
  const userId = userIdForEmail(email);
  const existing = state.users.find((item) => item.user_id === userId || item.email === email);
  if (existing) {
    existing.last_seen_at = nowIso();
    existing.status = "active";
    return existing;
  }
  const created: User = {
    user_id: userId,
    email,
    created_at: nowIso(),
    last_seen_at: nowIso(),
    status: "active"
  };
  state.users.push(created);
  return created;
}

function createSession(state: HubState, user: User, token: string): AuthSession {
  const session: AuthSession = {
    token_hash: tokenHash(token),
    user_id: user.user_id,
    created_at: nowIso(),
    last_seen_at: nowIso(),
    expires_at: daysFromNow(SESSION_TTL_DAYS),
    status: "active"
  };
  state.auth_sessions.push(session);
  return session;
}

function deviceForActor(state: HubState, actor: Actor, publicKey?: string, name?: string, platform?: string): Device {
  const existing = state.devices.find(
    (item) => item.user_id === actor.user_id && item.public_key === publicKey && item.status === "active"
  );
  if (existing) {
    existing.last_seen_at = nowIso();
    return existing;
  }
  if (!publicKey) {
    throw httpError(400, "device_required", "device public_key is required");
  }
  const device: Device = {
    device_id: id("dev"),
    user_id: actor.user_id,
    public_key: publicKey,
    fingerprint: fingerprintForPublicKey(publicKey),
    platform: platform || process.platform,
    name: name || "modelport-cli",
    first_seen_at: nowIso(),
    last_seen_at: nowIso(),
    status: "active"
  };
  state.devices.push(device);
  addAudit(state, actor, {
    kind: "device_registered",
    message: `Registered device ${device.name}`,
    metadata: { device_id: device.device_id, fingerprint: device.fingerprint }
  });
  return device;
}

function serviceModels(input: unknown): ModelDescriptor[] {
  if (!Array.isArray(input)) {
    return [];
  }
  return input
    .map((item) => {
      if (typeof item === "string") {
        return { id: item };
      }
      if (item && typeof item === "object" && typeof (item as { id?: unknown }).id === "string") {
        return {
          id: (item as { id: string }).id,
          display_name: optionalString((item as { display_name?: unknown }).display_name)
        };
      }
      return undefined;
    })
    .filter((item): item is ModelDescriptor => Boolean(item));
}

function allocateHubBind(state: HubState): string {
  const used = new Set([
    ...state.services.map((item) => item.current_hub_bind).filter(Boolean),
    ...state.sessions.map((item) => item.hub_bind).filter(Boolean)
  ]);
  for (let port = 49152; port <= 60999; port += 1) {
    const bind = `127.0.0.1:${port}`;
    if (!used.has(bind)) {
      return bind;
    }
  }
  throw httpError(503, "hub_bind_exhausted", "no hub loopback ports available");
}

function routeParts(pathname: string): string[] {
  return pathname.split("/").filter(Boolean);
}

function contentType(pathname: string): string {
  switch (extname(pathname)) {
    case ".css":
      return "text/css; charset=utf-8";
    case ".js":
      return "application/javascript; charset=utf-8";
    case ".svg":
      return "image/svg+xml";
    default:
      return "text/html; charset=utf-8";
  }
}

function serveStatic(webDir: string, req: IncomingMessage, res: ServerResponse, url: URL): boolean {
  if (req.method !== "GET" && req.method !== "HEAD") {
    return false;
  }
  const pathname = url.pathname === "/" ? "/index.html" : url.pathname;
  if (pathname.startsWith("/api/") || pathname.includes("..")) {
    return false;
  }
  const filePath = resolve(join(webDir, pathname));
  if (!filePath.startsWith(resolve(webDir))) {
    return false;
  }
  const stream = createReadStream(filePath);
  stream.on("error", () => {
    if (url.pathname === "/") {
      sendJson(res, 404, { error: { code: "dashboard_missing", message: "dashboard files not found" } });
    } else {
      sendJson(res, 404, { error: { code: "not_found", message: "not found" } });
    }
  });
  res.writeHead(200, { "content-type": contentType(pathname) });
  if (req.method === "HEAD") {
    res.end();
  } else {
    stream.pipe(res);
  }
  return true;
}

async function handleApi(
  ctx: RequestContext,
  store: JsonStore,
  opts: Required<Pick<HubServerOptions, "tunnelHost" | "tunnelPort" | "tunnelUser">> &
    Pick<HubServerOptions, "publicBaseUrl">
): Promise<void> {
  const { req, res, url, body } = ctx;
  const parts = routeParts(url.pathname);
  const method = req.method || "GET";

  if (method === "OPTIONS") {
    sendNoContent(res);
    return;
  }

  if (method === "GET" && url.pathname === "/healthz") {
    sendJson(res, 200, { ok: true, service: "modelport-hub" });
    return;
  }

  if (method === "POST" && url.pathname === "/api/v1/auth/signup") {
    const token = sessionToken();
    const auth = await store.mutate((state) => {
      const user = getOrCreateUser(state, normalizeEmail(body.email));
      const session = createSession(state, user, token);
      addAudit(state, { user_id: user.user_id, email: user.email }, {
        kind: "user_signed_in",
        message: `Signed in ${user.email}`,
        metadata: { session_expires_at: session.expires_at }
      });
      return { user, session };
    });
    sendJson(res, 201, { user: auth.user, token, expires_at: auth.session.expires_at }, { "set-cookie": sessionCookie(req, token) });
    return;
  }

  if (method === "POST" && url.pathname === "/api/v1/auth/logout") {
    const token = tokenFromRequest(req);
    if (token) {
      const hash = tokenHash(token);
      await store.mutate((state) => {
        for (const session of state.auth_sessions) {
          if (session.token_hash === hash) {
            session.status = "revoked";
          }
        }
      });
    }
    sendNoContent(res, { "set-cookie": clearSessionCookie() });
    return;
  }

  if (method === "GET" && url.pathname === "/api/v1/me") {
    const actor = requireActor(ctx.actor);
    sendJson(res, 200, { actor });
    return;
  }

  const actor = requireActor(ctx.actor);

  if (method === "GET" && url.pathname === "/api/v1/teams") {
    const state = await store.read();
    const teamIds = new Set(
      state.memberships
        .filter((item) => item.user_id === actor.user_id && item.status === "active")
        .map((item) => item.team_id)
    );
    sendJson(res, 200, { teams: state.teams.filter((item) => teamIds.has(item.team_id) && item.status === "active") });
    return;
  }

  if (method === "POST" && url.pathname === "/api/v1/teams") {
    const team = await store.mutate((state) => {
      const slug = requireSlug(body.slug, "slug");
      if (state.teams.some((item) => item.slug === slug && item.status === "active")) {
        throw httpError(409, "team_slug_exists", "team slug already exists");
      }
      const created: Team = {
        team_id: id("team"),
        slug,
        display_name: optionalString(body.display_name) || slug,
        created_by_user_id: actor.user_id,
        created_at: nowIso(),
        status: "active"
      };
      state.teams.push(created);
      state.memberships.push({
        team_id: created.team_id,
        user_id: actor.user_id,
        email: actor.email,
        role: "owner",
        status: "active",
        joined_at: nowIso()
      });
      addAudit(state, actor, {
        team_id: created.team_id,
        kind: "team_created",
        message: `Created team ${created.slug}`,
        metadata: { team_id: created.team_id, slug: created.slug }
      });
      return created;
    });
    sendJson(res, 201, { team });
    return;
  }

  if (method === "POST" && parts[0] === "api" && parts[2] === "teams" && parts[4] === "invites") {
    const rawToken = inviteToken();
    const invite = await store.mutate((state) => {
      const team = findTeamByIdOrSlug(state, parts[3], actor);
      requireTeamAccess(state, team.team_id, actor, ["owner", "admin"]);
      const roleRaw = optionalString(body.role) || "member";
      if (!isRole(roleRaw) || roleRaw === "owner") {
        throw httpError(400, "invalid_role", "invite role must be admin, member, or viewer");
      }
      const email = normalizeEmail(body.email);
      const created: Invite = {
        invite_id: id("invite"),
        team_id: team.team_id,
        email,
        role: roleRaw,
        token_hint: rawToken.slice(-8),
        token_hash: tokenHash(rawToken),
        status: "created",
        created_at: nowIso(),
        expires_at: daysFromNow(7)
      };
      state.invites.push(created);
      addAudit(state, actor, {
        team_id: team.team_id,
        kind: "invite_created",
        message: `Invited ${email}`,
        metadata: { invite_id: created.invite_id, role: created.role, token_hint: created.token_hint }
      });
      return created;
    });
    const acceptUrl = `${requestOrigin(req, opts.publicBaseUrl)}/?invite=${encodeURIComponent(rawToken)}`;
    sendJson(res, 201, { invite: sanitizedInvite(invite), token: rawToken, accept_url: acceptUrl });
    return;
  }

  if (method === "GET" && parts[0] === "api" && parts[2] === "teams" && parts[4] === "invites") {
    const state = await store.read();
    const team = findTeamByIdOrSlug(state, parts[3], actor);
    requireTeamAccess(state, team.team_id, actor, ["owner", "admin"]);
    sendJson(res, 200, {
      invites: state.invites.filter((item) => item.team_id === team.team_id).map((item) => sanitizedInvite(item))
    });
    return;
  }

  if (method === "POST" && url.pathname === "/api/v1/invites/accept") {
    const accepted = await store.mutate((state) => {
      const rawToken = requireString(body.token, "token");
      const invite = state.invites.find((item) => item.token_hash === tokenHash(rawToken));
      if (!invite || invite.status === "revoked") {
        throw httpError(404, "invite_not_found", "invite not found");
      }
      if (invite.status === "accepted") {
        throw httpError(409, "invite_already_accepted", "invite already accepted");
      }
      if (invite.status === "expired" || isExpired(invite.expires_at)) {
        invite.status = "expired";
        throw httpError(410, "invite_expired", "invite expired");
      }
      if (normalizeEmail(invite.email) !== actor.email) {
        throw httpError(403, "invite_email_mismatch", "sign in with the invited email address");
      }
      const team = state.teams.find((item) => item.team_id === invite.team_id && item.status === "active");
      if (!team) {
        throw httpError(404, "team_not_found", "team not found");
      }
      const existing = state.memberships.find((item) => item.team_id === invite.team_id && item.user_id === actor.user_id);
      if (existing) {
        existing.status = "active";
        existing.role = invite.role;
      } else {
        state.memberships.push({
          team_id: invite.team_id,
          user_id: actor.user_id,
          email: actor.email,
          role: invite.role,
          status: "active",
          joined_at: nowIso()
        });
      }
      invite.status = "accepted";
      invite.accepted_by_user_id = actor.user_id;
      invite.accepted_at = nowIso();
      addAudit(state, actor, {
        team_id: invite.team_id,
        kind: "invite_accepted",
        message: `${actor.email} joined ${team.slug}`,
        metadata: { invite_id: invite.invite_id, role: invite.role }
      });
      return { team, membership: state.memberships.find((item) => item.team_id === invite.team_id && item.user_id === actor.user_id) };
    });
    sendJson(res, 200, accepted);
    return;
  }

  if (method === "GET" && parts[0] === "api" && parts[2] === "teams" && parts[4] === "members") {
    const state = await store.read();
    const team = findTeamByIdOrSlug(state, parts[3], actor);
    sendJson(res, 200, { members: state.memberships.filter((item) => item.team_id === team.team_id) });
    return;
  }

  if (method === "POST" && url.pathname === "/api/v1/devices") {
    const device = await store.mutate((state) =>
      deviceForActor(
        state,
        actor,
        requireString(body.public_key, "public_key"),
        optionalString(body.name),
        optionalString(body.platform)
      )
    );
    sendJson(res, 201, { device });
    return;
  }

  if (method === "GET" && url.pathname === "/api/v1/devices") {
    const state = await store.read();
    sendJson(res, 200, { devices: state.devices.filter((item) => item.user_id === actor.user_id) });
    return;
  }

  if (method === "POST" && url.pathname === "/api/v1/tunnel/hosts") {
    const host = await store.mutate((state) => {
      const team = findTeamByIdOrSlug(state, requireString(body.team_id, "team_id"), actor);
      const publicKey = optionalString(body.public_key);
      const device = deviceForActor(state, actor, publicKey, optionalString(body.device_name), optionalString(body.platform));
      const name = requireSlug(body.name, "name");
      const existing = state.hosts.find((item) => item.team_id === team.team_id && item.name === name && item.status !== "revoked");
      if (existing) {
        existing.last_seen_at = nowIso();
        existing.status = "online";
        return existing;
      }
      const created: TunnelHost = {
        host_id: id("host"),
        team_id: team.team_id,
        owner_user_id: actor.user_id,
        owner_device_id: device.device_id,
        name,
        status: "online",
        last_seen_at: nowIso()
      };
      state.hosts.push(created);
      addAudit(state, actor, {
        team_id: team.team_id,
        kind: "host_registered",
        message: `Registered host ${name}`,
        metadata: { host_id: created.host_id, device_id: device.device_id }
      });
      return created;
    });
    sendJson(res, 201, { host });
    return;
  }

  if (method === "GET" && url.pathname === "/api/v1/tunnel/hosts") {
    const state = await store.read();
    const team = findTeamByIdOrSlug(state, requireString(url.searchParams.get("team_id"), "team_id"), actor);
    sendJson(res, 200, { hosts: state.hosts.filter((item) => item.team_id === team.team_id && item.status !== "revoked") });
    return;
  }

  if (method === "POST" && url.pathname === "/api/v1/tunnel/services") {
    const service = await store.mutate((state) => {
      const team = findTeamByIdOrSlug(state, requireString(body.team_id, "team_id"), actor);
      const hostId = requireString(body.host_id, "host_id");
      const host = state.hosts.find((item) => item.team_id === team.team_id && item.host_id === hostId && item.status !== "revoked");
      if (!host) {
        throw httpError(404, "host_not_found", "host not found");
      }
      const name = requireSlug(body.name || host.name, "name");
      const upstream = redactSecretLike(parseHostPort(requireString(body.upstream_hint, "upstream_hint"), "upstream_hint"));
      const kind = (optionalString(body.kind) || "openai_compatible") as ServiceKind;
      if (kind !== "openai_compatible") {
        throw httpError(400, "invalid_service_kind", "only openai_compatible is supported");
      }
      const existing = state.services.find((item) => item.team_id === team.team_id && item.host_id === hostId && item.name === name);
      if (existing) {
        existing.upstream_hint = upstream;
        existing.models = serviceModels(body.models);
        existing.status = "online";
        existing.last_health = { status: "healthy", checked_at: nowIso() };
        return existing;
      }
      const created: TunnelService = {
        service_id: id("svc"),
        team_id: team.team_id,
        host_id: host.host_id,
        name,
        kind,
        upstream_hint: upstream,
        models: serviceModels(body.models),
        acl: { roles: DEFAULT_SERVICE_ROLES },
        status: "online",
        last_health: { status: "healthy", checked_at: nowIso() }
      };
      state.services.push(created);
      addAudit(state, actor, {
        team_id: team.team_id,
        kind: "service_registered",
        message: `Registered service ${name}`,
        metadata: { service_id: created.service_id, host_id: host.host_id, models: created.models.map((item) => item.id) }
      });
      return created;
    });
    sendJson(res, 201, { service });
    return;
  }

  if (method === "GET" && url.pathname === "/api/v1/tunnel/services") {
    const state = await store.read();
    const team = findTeamByIdOrSlug(state, requireString(url.searchParams.get("team_id"), "team_id"), actor);
    sendJson(res, 200, {
      services: state.services.filter((item) => item.team_id === team.team_id && item.status !== "revoked")
    });
    return;
  }

  if (method === "POST" && url.pathname === "/api/v1/tunnel/ssh-credentials:issue") {
    const credential = await store.mutate((state) => {
      const team = findTeamByIdOrSlug(state, requireString(body.team_id, "team_id"), actor);
      const service = requireService(state, requireString(body.service_id, "service_id"), team.team_id, actor);
      const direction = requireString(body.direction, "direction") as TunnelDirection;
      if (direction !== "serve" && direction !== "connect") {
        throw httpError(400, "invalid_direction", "direction must be serve or connect");
      }
      const device = deviceForActor(
        state,
        actor,
        requireString(body.public_key, "public_key"),
        optionalString(body.device_name),
        optionalString(body.platform)
      );
      const issuedAt = nowIso();
      const expiresAt = minutesFromNow(15);
      const hubBind = direction === "serve" ? allocateHubBind(state) : service.current_hub_bind;
      if (direction === "connect" && !hubBind) {
        throw httpError(409, "service_offline", "service has no active hub bind");
      }
      const credential: TunnelCredential = {
        credential_id: id("cred"),
        team_id: team.team_id,
        service_id: service.service_id,
        direction,
        user_id: actor.user_id,
        device_id: device.device_id,
        public_key_fingerprint: device.fingerprint,
        principals: [
          `team:${team.team_id}`,
          `user:${actor.user_id}`,
          `device:${device.device_id}`,
          `service:${service.service_id}`,
          `purpose:${direction}`
        ],
        restrictions: {
          no_pty: true,
          no_shell: true,
          no_agent_forwarding: true,
          no_x11_forwarding: true,
          ...(direction === "serve" ? { permit_listen: hubBind } : { permit_open: hubBind })
        },
        ssh: {
          host: opts.tunnelHost,
          port: opts.tunnelPort,
          username: opts.tunnelUser,
          ...(direction === "serve" ? { hub_bind: hubBind, upstream: service.upstream_hint } : { open_target: hubBind })
        },
        issued_at: issuedAt,
        expires_at: expiresAt
      };
      state.credentials.push(credential);
      addAudit(state, actor, {
        team_id: team.team_id,
        kind: "ssh_credential_issued",
        message: `Issued ${direction} credential for ${service.name}`,
        metadata: { credential_id: credential.credential_id, service_id: service.service_id, direction }
      });
      return credential;
    });
    sendJson(res, 201, { credential });
    return;
  }

  if (method === "POST" && url.pathname === "/api/v1/tunnel/sessions") {
    const session = await store.mutate((state) => {
      const team = findTeamByIdOrSlug(state, requireString(body.team_id, "team_id"), actor);
      const credentialId = requireString(body.credential_id, "credential_id");
      const credential = state.credentials.find((item) => item.credential_id === credentialId && item.team_id === team.team_id);
      if (!credential) {
        throw httpError(404, "credential_not_found", "credential not found");
      }
      if (credential.user_id !== actor.user_id) {
        throw httpError(403, "credential_forbidden", "credential belongs to another user");
      }
      const service = requireService(state, credential.service_id, team.team_id, actor);
      const session: TunnelSession = {
        session_id: id("tun"),
        team_id: team.team_id,
        service_id: service.service_id,
        direction: credential.direction,
        user_id: actor.user_id,
        device_id: credential.device_id,
        credential_id: credential.credential_id,
        hub_bind: optionalString(body.hub_bind) || credential.ssh.hub_bind,
        local_bind: optionalString(body.local_bind),
        started_at: nowIso(),
        last_heartbeat_at: nowIso(),
        expires_at: credential.expires_at,
        closed_at: null,
        close_reason: null
      };
      if (session.local_bind) {
        session.local_bind = parseLocalBind(session.local_bind);
      }
      if (credential.direction === "serve") {
        service.current_hub_bind = session.hub_bind;
        service.status = "online";
      }
      state.sessions.push(session);
      addAudit(state, actor, {
        team_id: team.team_id,
        kind: "tunnel_session_opened",
        message: `Opened ${credential.direction} session for ${service.name}`,
        metadata: { session_id: session.session_id, service_id: service.service_id, direction: credential.direction }
      });
      return session;
    });
    sendJson(res, 201, { session });
    return;
  }

  if (method === "GET" && url.pathname === "/api/v1/tunnel/sessions") {
    const state = await store.read();
    const team = findTeamByIdOrSlug(state, requireString(url.searchParams.get("team_id"), "team_id"), actor);
    sendJson(res, 200, { sessions: state.sessions.filter((item) => item.team_id === team.team_id) });
    return;
  }

  if (method === "POST" && parts[0] === "api" && parts[2] === "tunnel" && parts[3] === "sessions" && parts[5] === "heartbeat") {
    const session = await store.mutate((state) => {
      const session = state.sessions.find((item) => item.session_id === parts[4]);
      if (!session) {
        throw httpError(404, "session_not_found", "session not found");
      }
      requireTeamAccess(state, session.team_id, actor);
      session.last_heartbeat_at = nowIso();
      return session;
    });
    sendJson(res, 200, { session });
    return;
  }

  if (method === "POST" && parts[0] === "api" && parts[2] === "tunnel" && parts[3] === "sessions" && parts[5] === "close") {
    const session = await store.mutate((state) => {
      const session = state.sessions.find((item) => item.session_id === parts[4]);
      if (!session) {
        throw httpError(404, "session_not_found", "session not found");
      }
      requireTeamAccess(state, session.team_id, actor);
      session.closed_at = nowIso();
      session.close_reason = optionalString(body.reason) || "client_closed";
      const service = state.services.find((item) => item.service_id === session.service_id);
      if (service && session.direction === "serve" && service.current_hub_bind === session.hub_bind) {
        service.current_hub_bind = undefined;
        service.status = "offline";
      }
      addAudit(state, actor, {
        team_id: session.team_id,
        kind: "tunnel_session_closed",
        message: `Closed ${session.direction} session`,
        metadata: { session_id: session.session_id, reason: session.close_reason }
      });
      return session;
    });
    sendJson(res, 200, { session });
    return;
  }

  if (method === "GET" && url.pathname === "/api/v1/audit") {
    const state = await store.read();
    const team = findTeamByIdOrSlug(state, requireString(url.searchParams.get("team_id"), "team_id"), actor);
    sendJson(res, 200, { audit: state.audit.filter((item) => item.team_id === team.team_id) });
    return;
  }

  throw httpError(404, "not_found", "not found");
}

export function createHubServer(options: HubServerOptions): Server {
  const tunnelHost = options.tunnelHost || process.env.MODELPORT_TUNNEL_HOST || DEFAULT_TUNNEL_HOST;
  const tunnelPort = Number(options.tunnelPort || process.env.MODELPORT_TUNNEL_PORT || DEFAULT_TUNNEL_PORT);
  const tunnelUser = options.tunnelUser || process.env.MODELPORT_TUNNEL_USER || DEFAULT_TUNNEL_USER;
  const publicBaseUrl = options.publicBaseUrl || process.env.MODELPORT_PUBLIC_BASE_URL;
  const allowDevAuth =
    options.allowDevAuth ??
    (process.env.MODELPORT_DEV_AUTH ? process.env.MODELPORT_DEV_AUTH === "1" : process.env.NODE_ENV !== "production");
  const store = new JsonStore(options.dataDir);

  return createServer(async (req, res) => {
    try {
      const url = new URL(req.url || "/", "http://127.0.0.1");
      if (!url.pathname.startsWith("/api/") && url.pathname !== "/healthz") {
        if (serveStatic(options.webDir, req, res, url)) {
          return;
        }
      }
      const ctx: RequestContext = {
        req,
        res,
        url,
        actor: await actorFromRequest(req, store, allowDevAuth),
        body: await readBody(req)
      };
      await handleApi(ctx, store, { tunnelHost, tunnelPort, tunnelUser, publicBaseUrl });
    } catch (error) {
      const err = error as HttpError;
      sendJson(res, err.status || 500, {
        error: {
          code: err.code || "internal_error",
          message: err.message || "internal error"
        }
      });
    }
  });
}

export async function startHubServer(): Promise<Server> {
  const dataDir = process.env.MODELPORT_DATA_DIR || join(tmpdir(), "modelport-hub");
  const webDir = process.env.MODELPORT_WEB_DIR || resolve(process.cwd(), "apps/hub-web");
  const port = Number(process.env.PORT || DEFAULT_PORT);
  await mkdir(dataDir, { recursive: true });
  const server = createHubServer({ dataDir, webDir });
  await new Promise<void>((resolveListen) => server.listen(port, resolveListen));
  console.log(`modelport hub listening on http://127.0.0.1:${port}`);
  console.log(`modelport data dir ${dataDir}`);
  return server;
}

if (import.meta.url === `file://${process.argv[1]}`) {
  startHubServer().catch((error) => {
    console.error(error);
    process.exit(1);
  });
}
