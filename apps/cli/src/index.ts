#!/usr/bin/env node
import { spawn } from "node:child_process";
import { createDevConfig, loadConfig, saveConfig } from "./config.js";
import {
  parseHostPort,
  parseLocalBind,
  requireSlug,
  type Team,
  type TunnelCredential,
  type TunnelService
} from "../../../packages/protocol/src/index.js";
import { buildConnectSshCommand, buildServeSshCommand, type SshCommand } from "../../../packages/tunnel/src/ssh.js";

interface ParsedArgs {
  command: string;
  positionals: string[];
  flags: Map<string, string[]>;
  json: boolean;
}

function parseArgs(argv: string[]): ParsedArgs {
  const flags = new Map<string, string[]>();
  const positionals: string[] = [];
  let command = "";
  for (let index = 0; index < argv.length; index += 1) {
    const token = argv[index];
    if (token === "--json") {
      flags.set("json", ["true"]);
      continue;
    }
    if (token.startsWith("--")) {
      const key = token.slice(2);
      const next = argv[index + 1];
      const value = !next || next.startsWith("--") ? "true" : next;
      if (value !== "true") {
        index += 1;
      }
      flags.set(key, [...(flags.get(key) || []), value]);
      continue;
    }
    if (!command) {
      command = token;
    } else {
      positionals.push(token);
    }
  }
  return { command, positionals, flags, json: flags.has("json") };
}

function flag(args: ParsedArgs, name: string): string | undefined {
  return args.flags.get(name)?.at(-1);
}

function flagAll(args: ParsedArgs, name: string): string[] {
  return args.flags.get(name) || [];
}

function requireFlag(args: ParsedArgs, name: string): string {
  const value = flag(args, name);
  if (!value || value === "true") {
    throw new Error(`missing --${name}`);
  }
  return value;
}

function print(args: ParsedArgs, human: string, jsonValue: unknown): void {
  if (args.json) {
    console.log(JSON.stringify(jsonValue, null, 2));
  } else {
    console.log(human);
  }
}

async function api<T>(path: string, init: RequestInit = {}): Promise<T> {
  const config = await loadConfig();
  const url = new URL(path, config.hub_url);
  const response = await fetch(url, {
    ...init,
    headers: {
      "content-type": "application/json",
      authorization: `Bearer dev:${config.user_email}`,
      ...(init.headers || {})
    }
  });
  const body = (await response.json()) as T & { error?: { message?: string } };
  if (!response.ok) {
    throw new Error(body.error?.message || `request failed: ${response.status}`);
  }
  return body;
}

async function resolveTeam(teamRef: string): Promise<Team> {
  const data = await api<{ teams: Team[] }>("/api/v1/teams");
  const team = data.teams.find((item) => item.team_id === teamRef || item.slug === teamRef);
  if (!team) {
    throw new Error(`team ${teamRef} not found`);
  }
  return team;
}

async function resolveService(team: Team, serviceRef: string): Promise<TunnelService> {
  const data = await api<{ services: TunnelService[] }>(`/api/v1/tunnel/services?team_id=${team.team_id}`);
  const service = data.services.find((item) => item.service_id === serviceRef || item.name === serviceRef);
  if (!service) {
    throw new Error(`service ${serviceRef} not found`);
  }
  return service;
}

function maybeRun(command: SshCommand, execute: boolean): void {
  if (!execute) {
    return;
  }
  const child = spawn(command.bin, command.args, { stdio: "inherit" });
  child.on("exit", (code) => process.exit(code || 0));
}

async function login(args: ParsedArgs): Promise<void> {
  const hub = requireFlag(args, "hub");
  const user = requireFlag(args, "user");
  const config = await createDevConfig(hub, user);
  await saveConfig(config);
  print(args, `Logged in to ${config.hub_url} as ${config.user_email}`, { status: "ok", config });
}

async function status(args: ParsedArgs): Promise<void> {
  const config = await loadConfig();
  const me = await api<{ actor: { user_id: string; email: string } }>("/api/v1/me");
  print(args, `modelport ${config.hub_url}\nuser ${me.actor.email}\ndevice ${config.device_name}`, {
    hub_url: config.hub_url,
    actor: me.actor,
    device_name: config.device_name
  });
}

async function team(args: ParsedArgs): Promise<void> {
  const subcommand = args.positionals[0];
  if (subcommand === "create") {
    const slug = requireSlug(args.positionals[1], "slug");
    const displayName = flag(args, "display-name") || slug;
    const data = await api<{ team: Team }>("/api/v1/teams", {
      method: "POST",
      body: JSON.stringify({ slug, display_name: displayName })
    });
    print(args, `Created team ${data.team.slug}`, data);
    return;
  }
  if (subcommand === "invite") {
    const teamRef = args.positionals[1];
    const email = args.positionals[2];
    if (!teamRef || !email) {
      throw new Error("usage: modelport team invite <team> <email> [--role member]");
    }
    const team = await resolveTeam(teamRef);
    const data = await api<{ invite: unknown }>(`/api/v1/teams/${team.team_id}/invites`, {
      method: "POST",
      body: JSON.stringify({ email, role: flag(args, "role") || "member" })
    });
    print(args, `Invited ${email} to ${team.slug}`, data);
    return;
  }
  if (subcommand === "members") {
    const teamRef = args.positionals[1];
    if (!teamRef) {
      throw new Error("usage: modelport team members <team>");
    }
    const team = await resolveTeam(teamRef);
    const data = await api<{ members: Array<{ email: string; role: string; status: string }> }>(
      `/api/v1/teams/${team.team_id}/members`
    );
    print(
      args,
      data.members.map((member) => `${member.email}\t${member.role}\t${member.status}`).join("\n") || "No members",
      data
    );
    return;
  }
  throw new Error("usage: modelport team <create|invite|members>");
}

async function serve(args: ParsedArgs): Promise<void> {
  const config = await loadConfig();
  const team = await resolveTeam(requireFlag(args, "team"));
  const name = requireSlug(requireFlag(args, "name"), "name");
  const upstream = parseHostPort(requireFlag(args, "upstream"), "upstream");
  const models = flagAll(args, "model").map((model) => ({ id: model }));
  const hostData = await api<{ host: { host_id: string } }>("/api/v1/tunnel/hosts", {
    method: "POST",
    body: JSON.stringify({
      team_id: team.team_id,
      name,
      public_key: config.public_key,
      device_name: config.device_name,
      platform: config.platform
    })
  });
  const serviceData = await api<{ service: TunnelService }>("/api/v1/tunnel/services", {
    method: "POST",
    body: JSON.stringify({
      team_id: team.team_id,
      host_id: hostData.host.host_id,
      name,
      upstream_hint: upstream,
      models
    })
  });
  const credentialData = await api<{ credential: TunnelCredential }>("/api/v1/tunnel/ssh-credentials:issue", {
    method: "POST",
    body: JSON.stringify({
      team_id: team.team_id,
      service_id: serviceData.service.service_id,
      direction: "serve",
      public_key: config.public_key,
      device_name: config.device_name,
      platform: config.platform
    })
  });
  const credential = credentialData.credential;
  const sessionData = await api<{ session: unknown }>("/api/v1/tunnel/sessions", {
    method: "POST",
    body: JSON.stringify({
      team_id: team.team_id,
      credential_id: credential.credential_id,
      hub_bind: credential.ssh.hub_bind
    })
  });
  const sshCommand = buildServeSshCommand({
    sshHost: credential.ssh.host,
    sshPort: credential.ssh.port,
    username: credential.ssh.username,
    hubBind: credential.ssh.hub_bind || "127.0.0.1:0",
    upstream
  });
  print(
    args,
    `Registered ${name}\nSSH command:\n${sshCommand.display}\n\nRun with --execute to start ssh from this CLI.`,
    { service: serviceData.service, credential, session: sessionData.session, ssh: sshCommand }
  );
  maybeRun(sshCommand, flag(args, "execute") === "true");
}

async function listServices(args: ParsedArgs): Promise<void> {
  const team = await resolveTeam(requireFlag(args, "team"));
  const data = await api<{ services: TunnelService[] }>(`/api/v1/tunnel/services?team_id=${team.team_id}`);
  const human =
    data.services
      .map((service) => {
        const models = service.models.map((model) => model.id).join(",") || "no-models";
        return `${service.name}\t${service.status}\t${service.current_hub_bind || "offline"}\t${models}`;
      })
      .join("\n") || "No services";
  print(args, human, data);
}

async function connect(args: ParsedArgs): Promise<void> {
  const config = await loadConfig();
  const serviceRef = args.positionals[0];
  if (!serviceRef) {
    throw new Error("usage: modelport connect <service> --team <team> --local 127.0.0.1:11434");
  }
  const team = await resolveTeam(requireFlag(args, "team"));
  const service = await resolveService(team, serviceRef);
  const localBind = parseLocalBind(requireFlag(args, "local"));
  const credentialData = await api<{ credential: TunnelCredential }>("/api/v1/tunnel/ssh-credentials:issue", {
    method: "POST",
    body: JSON.stringify({
      team_id: team.team_id,
      service_id: service.service_id,
      direction: "connect",
      public_key: config.public_key,
      device_name: config.device_name,
      platform: config.platform
    })
  });
  const credential = credentialData.credential;
  const sessionData = await api<{ session: unknown }>("/api/v1/tunnel/sessions", {
    method: "POST",
    body: JSON.stringify({ team_id: team.team_id, credential_id: credential.credential_id, local_bind: localBind })
  });
  const sshCommand = buildConnectSshCommand({
    sshHost: credential.ssh.host,
    sshPort: credential.ssh.port,
    username: credential.ssh.username,
    localBind,
    openTarget: credential.ssh.open_target || service.current_hub_bind || "127.0.0.1:0"
  });
  const baseUrl = `http://${localBind}/v1`;
  print(
    args,
    `Connected ${service.name}\nOPENAI_BASE_URL=${baseUrl}\nSSH command:\n${sshCommand.display}\n\nRun with --execute to start ssh from this CLI.`,
    { service, credential, session: sessionData.session, local_base_url: baseUrl, ssh: sshCommand }
  );
  maybeRun(sshCommand, flag(args, "execute") === "true");
}

async function envCommand(args: ParsedArgs): Promise<void> {
  const local = parseLocalBind(requireFlag(args, "local"));
  const baseUrl = `http://${local}/v1`;
  print(args, `export OPENAI_BASE_URL=${baseUrl}`, { OPENAI_BASE_URL: baseUrl });
}

function usage(): string {
  return `modelport

Usage:
  modelport login --hub <url> --user <email>
  modelport status
  modelport team create <slug> [--display-name <name>]
  modelport team invite <team> <email> [--role member]
  modelport team members <team>
  modelport serve --team <team> --name <host> --upstream 127.0.0.1:8000 [--model id] [--execute]
  modelport ls --team <team>
  modelport connect <service> --team <team> --local 127.0.0.1:11434 [--execute]
  modelport env <service> --local 127.0.0.1:11434
`;
}

export async function main(argv = process.argv.slice(2)): Promise<void> {
  const args = parseArgs(argv);
  switch (args.command) {
    case "login":
      await login(args);
      return;
    case "status":
      await status(args);
      return;
    case "team":
      await team(args);
      return;
    case "serve":
      await serve(args);
      return;
    case "ls":
      await listServices(args);
      return;
    case "connect":
      await connect(args);
      return;
    case "env":
      await envCommand(args);
      return;
    case "help":
    case "":
      console.log(usage());
      return;
    default:
      throw new Error(`unknown command ${args.command}\n${usage()}`);
  }
}

if (import.meta.url === `file://${process.argv[1]}`) {
  main().catch((error) => {
    console.error(`modelport: ${(error as Error).message}`);
    process.exit(1);
  });
}
