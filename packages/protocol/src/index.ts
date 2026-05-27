export type Role = "owner" | "admin" | "member" | "viewer";
export type RecordStatus = "active" | "revoked";
export type OnlineStatus = "online" | "offline" | "revoked";
export type ServiceKind = "openai_compatible";
export type TunnelDirection = "serve" | "connect";

export interface Actor {
  user_id: string;
  email: string;
}

export interface Team {
  team_id: string;
  slug: string;
  display_name: string;
  created_by_user_id: string;
  created_at: string;
  status: RecordStatus;
}

export interface User {
  user_id: string;
  email: string;
  created_at: string;
  last_seen_at: string;
  status: RecordStatus;
}

export interface AuthSession {
  token_hash: string;
  user_id: string;
  created_at: string;
  last_seen_at: string;
  expires_at: string;
  status: RecordStatus;
}

export interface Membership {
  team_id: string;
  user_id: string;
  email: string;
  role: Role;
  status: RecordStatus;
  joined_at: string;
}

export interface Invite {
  invite_id: string;
  team_id: string;
  email: string;
  role: Role;
  token_hint: string;
  token_hash?: string;
  status: "created" | "accepted" | "revoked" | "expired";
  created_at: string;
  expires_at: string;
  accepted_by_user_id?: string;
  accepted_at?: string;
}

export interface Device {
  device_id: string;
  user_id: string;
  public_key: string;
  fingerprint: string;
  platform: string;
  name: string;
  first_seen_at: string;
  last_seen_at: string;
  status: RecordStatus;
}

export interface TunnelHost {
  host_id: string;
  team_id: string;
  owner_user_id: string;
  owner_device_id: string;
  name: string;
  status: OnlineStatus;
  last_seen_at: string;
}

export interface ModelDescriptor {
  id: string;
  display_name?: string;
}

export interface TunnelService {
  service_id: string;
  team_id: string;
  host_id: string;
  name: string;
  kind: ServiceKind;
  upstream_hint: string;
  models: ModelDescriptor[];
  acl: { roles: Role[] };
  status: OnlineStatus;
  current_hub_bind?: string;
  last_health: {
    status: "healthy" | "unknown" | "unhealthy";
    checked_at: string;
  };
}

export interface TunnelCredential {
  credential_id: string;
  team_id: string;
  service_id: string;
  direction: TunnelDirection;
  user_id: string;
  device_id: string;
  public_key_fingerprint: string;
  principals: string[];
  restrictions: {
    no_pty: true;
    no_shell: true;
    no_agent_forwarding: true;
    no_x11_forwarding: true;
    permit_listen?: string;
    permit_open?: string;
  };
  ssh: {
    host: string;
    port: number;
    username: string;
    hub_bind?: string;
    upstream?: string;
    open_target?: string;
  };
  issued_at: string;
  expires_at: string;
}

export interface TunnelSession {
  session_id: string;
  team_id: string;
  service_id: string;
  direction: TunnelDirection;
  user_id: string;
  device_id: string;
  credential_id: string;
  hub_bind?: string;
  local_bind?: string;
  started_at: string;
  last_heartbeat_at: string;
  expires_at: string;
  closed_at: string | null;
  close_reason: string | null;
}

export interface AuditEvent {
  event_id: string;
  team_id?: string;
  actor_user_id: string;
  kind: string;
  message: string;
  metadata: Record<string, unknown>;
  created_at: string;
}

export interface HubState {
  schema_version: 1;
  users: User[];
  auth_sessions: AuthSession[];
  teams: Team[];
  memberships: Membership[];
  invites: Invite[];
  devices: Device[];
  hosts: TunnelHost[];
  services: TunnelService[];
  credentials: TunnelCredential[];
  sessions: TunnelSession[];
  audit: AuditEvent[];
}

export const DEFAULT_SERVICE_ROLES: Role[] = ["owner", "admin", "member"];

export function emptyState(): HubState {
  return {
    schema_version: 1,
    users: [],
    auth_sessions: [],
    teams: [],
    memberships: [],
    invites: [],
    devices: [],
    hosts: [],
    services: [],
    credentials: [],
    sessions: [],
    audit: []
  };
}

export function isRole(value: string): value is Role {
  return ["owner", "admin", "member", "viewer"].includes(value);
}

export function requireSlug(value: unknown, field: string): string {
  if (typeof value !== "string") {
    throw new Error(`${field} must be a string`);
  }
  const slug = value.trim();
  if (!/^[a-z0-9][a-z0-9-]{0,62}[a-z0-9]$/.test(slug)) {
    throw new Error(`${field} must be a slug of 2-64 lowercase letters, numbers, or dashes`);
  }
  return slug;
}

export function requireString(value: unknown, field: string): string {
  if (typeof value !== "string" || value.trim() === "") {
    throw new Error(`${field} must be a non-empty string`);
  }
  return value.trim();
}

export function optionalString(value: unknown): string | undefined {
  return typeof value === "string" && value.trim() !== "" ? value.trim() : undefined;
}

export function parseLocalBind(value: string): string {
  const bind = value.trim();
  if (!/^(127\.0\.0\.1|\[::1\]|localhost):[0-9]{1,5}$/.test(bind)) {
    throw new Error("local bind must be loopback, for example 127.0.0.1:11434");
  }
  const port = Number(bind.slice(bind.lastIndexOf(":") + 1));
  if (!Number.isInteger(port) || port < 0 || port > 65535) {
    throw new Error("local bind port must be between 0 and 65535");
  }
  return bind;
}

export function parseHostPort(value: string, field = "address"): string {
  const address = value.trim();
  if (!/^[a-zA-Z0-9_.-]+:[0-9]{1,5}$/.test(address)) {
    throw new Error(`${field} must be host:port`);
  }
  const port = Number(address.slice(address.lastIndexOf(":") + 1));
  if (!Number.isInteger(port) || port <= 0 || port > 65535) {
    throw new Error(`${field} port must be between 1 and 65535`);
  }
  return address;
}

export function redactSecretLike(value: string): string {
  return value
    .replace(/\/\/([^/@:]+):([^/@]+)@/g, "//<redacted>:<redacted>@")
    .replace(/(sk-[A-Za-z0-9_-]{8,})/g, "<redacted-token>")
    .replace(/(gh[pousr]_[A-Za-z0-9_]{12,})/g, "<redacted-token>")
    .replace(/Bearer\s+[A-Za-z0-9._-]{12,}/gi, "Bearer <redacted-token>");
}
