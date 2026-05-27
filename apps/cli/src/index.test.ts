import assert from "node:assert/strict";
import { execFile } from "node:child_process";
import { mkdtemp } from "node:fs/promises";
import type { AddressInfo } from "node:net";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { promisify } from "node:util";
import test from "node:test";
import { createHubServer } from "../../hub-api/src/server.js";

const execFileAsync = promisify(execFile);

async function withHub<T>(fn: (baseUrl: string, env: NodeJS.ProcessEnv) => Promise<T>): Promise<T> {
  const dataDir = await mkdtemp(join(tmpdir(), "modelport-cli-hub-"));
  const homeDir = await mkdtemp(join(tmpdir(), "modelport-cli-home-"));
  const server = createHubServer({
    dataDir,
    webDir: resolve("apps/hub-web"),
    tunnelHost: "hub.local",
    tunnelPort: 2222,
    tunnelUser: "modelport"
  });
  await new Promise<void>((resolveListen) => server.listen(0, resolveListen));
  const address = server.address() as AddressInfo;
  try {
    return await fn(`http://127.0.0.1:${address.port}`, {
      ...process.env,
      MODELPORT_HOME: homeDir,
      MODELPORT_PUBLIC_KEY: "ssh-ed25519 AAAATEST cli"
    });
  } finally {
    await new Promise<void>((resolveClose) => server.close(() => resolveClose()));
  }
}

async function runCli(env: NodeJS.ProcessEnv, args: string[]): Promise<string> {
  const cliPath = fileURLToPath(new URL("./index.js", import.meta.url));
  const { stdout } = await execFileAsync(process.execPath, [cliPath, ...args], { env });
  return stdout.trim();
}

test("CLI registers and connects a model service", async () => {
  await withHub(async (baseUrl, env) => {
    await runCli(env, ["login", "--hub", baseUrl, "--user", "alice@example.com"]);
    await runCli(env, ["team", "create", "team-acme"]);
    const serveRaw = await runCli(env, [
      "serve",
      "--team",
      "team-acme",
      "--name",
      "gpu-box",
      "--upstream",
      "127.0.0.1:8000",
      "--model",
      "local-llm",
      "--json"
    ]);
    const serve = JSON.parse(serveRaw) as { service: { name: string }; ssh: { display: string } };
    assert.equal(serve.service.name, "gpu-box");
    assert.match(serve.ssh.display, /-R 127\.0\.0\.1:/);

    const connectRaw = await runCli(env, [
      "connect",
      "gpu-box",
      "--team",
      "team-acme",
      "--local",
      "127.0.0.1:11434",
      "--json"
    ]);
    const connect = JSON.parse(connectRaw) as { local_base_url: string; ssh: { display: string } };
    assert.equal(connect.local_base_url, "http://127.0.0.1:11434/v1");
    assert.match(connect.ssh.display, /-L 127\.0\.0\.1:11434:127\.0\.0\.1:/);
  });
});
