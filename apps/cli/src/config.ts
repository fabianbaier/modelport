import { randomBytes } from "node:crypto";
import { mkdir, readFile, writeFile } from "node:fs/promises";
import { homedir, hostname, platform } from "node:os";
import { dirname, join } from "node:path";

export interface CliConfig {
  hub_url: string;
  user_email: string;
  public_key: string;
  device_name: string;
  platform: string;
}

export function configPath(): string {
  return join(process.env.MODELPORT_HOME || join(homedir(), ".modelport"), "config.json");
}

export async function loadConfig(): Promise<CliConfig> {
  try {
    const parsed = JSON.parse(await readFile(configPath(), "utf8")) as CliConfig;
    if (!parsed.hub_url || !parsed.user_email || !parsed.public_key) {
      throw new Error("config is missing hub_url, user_email, or public_key");
    }
    return parsed;
  } catch (error) {
    if ((error as NodeJS.ErrnoException).code === "ENOENT") {
      throw new Error("not logged in; run modelport login --hub <url> --user <email>");
    }
    throw error;
  }
}

export async function saveConfig(config: CliConfig): Promise<void> {
  const path = configPath();
  await mkdir(dirname(path), { recursive: true, mode: 0o700 });
  await writeFile(path, `${JSON.stringify(config, null, 2)}\n`, { mode: 0o600 });
}

async function defaultPublicKey(): Promise<string> {
  if (process.env.MODELPORT_PUBLIC_KEY) {
    return process.env.MODELPORT_PUBLIC_KEY;
  }
  try {
    return (await readFile(join(homedir(), ".ssh", "id_ed25519.pub"), "utf8")).trim();
  } catch {
    return `modelport-dev ${randomBytes(32).toString("base64")}`;
  }
}

export async function createDevConfig(hubUrl: string, userEmail: string): Promise<CliConfig> {
  return {
    hub_url: hubUrl.replace(/\/+$/, ""),
    user_email: userEmail,
    public_key: await defaultPublicKey(),
    device_name: hostname(),
    platform: platform()
  };
}
