import { parseHostPort, parseLocalBind } from "../../protocol/src/index.js";

export interface SshCommand {
  bin: "ssh";
  args: string[];
  display: string;
}

export interface ServeCommandInput {
  sshHost: string;
  sshPort: number;
  username: string;
  hubBind: string;
  upstream: string;
  identityFile?: string;
}

export interface ConnectCommandInput {
  sshHost: string;
  sshPort: number;
  username: string;
  localBind: string;
  openTarget: string;
  identityFile?: string;
}

function shellQuote(value: string): string {
  if (/^[A-Za-z0-9_./:@=-]+$/.test(value)) {
    return value;
  }
  return `'${value.replace(/'/g, "'\\''")}'`;
}

function render(bin: string, args: string[]): string {
  return [bin, ...args].map(shellQuote).join(" ");
}

function commonArgs(input: { sshHost: string; sshPort: number; username: string; identityFile?: string }): string[] {
  const args = [
    "-N",
    "-o",
    "ExitOnForwardFailure=yes",
    "-o",
    "ServerAliveInterval=15",
    "-o",
    "ServerAliveCountMax=2",
    "-p",
    String(input.sshPort)
  ];
  if (input.identityFile) {
    args.push("-i", input.identityFile);
  }
  args.push(`${input.username}@${input.sshHost}`);
  return args;
}

export function buildServeSshCommand(input: ServeCommandInput): SshCommand {
  const hubBind = parseLocalBind(input.hubBind);
  const upstream = parseHostPort(input.upstream, "upstream");
  const args = commonArgs(input);
  args.splice(1, 0, "-R", `${hubBind}:${upstream}`);
  return { bin: "ssh", args, display: render("ssh", args) };
}

export function buildConnectSshCommand(input: ConnectCommandInput): SshCommand {
  const localBind = parseLocalBind(input.localBind);
  const openTarget = parseLocalBind(input.openTarget);
  const args = commonArgs(input);
  args.splice(1, 0, "-L", `${localBind}:${openTarget}`);
  return { bin: "ssh", args, display: render("ssh", args) };
}
