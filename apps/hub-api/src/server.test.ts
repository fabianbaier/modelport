import assert from "node:assert/strict";
import { mkdtemp } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";
import test from "node:test";
import { createHubServer } from "./server.js";
import type { AddressInfo } from "node:net";

async function withHub<T>(fn: (baseUrl: string) => Promise<T>): Promise<T> {
  const dataDir = await mkdtemp(join(tmpdir(), "modelport-test-"));
  const server = createHubServer({
    dataDir,
    webDir: resolve("apps/hub-web"),
    tunnelHost: "hub.local",
    tunnelPort: 2222,
    tunnelUser: "modelport"
  });
  await new Promise<void>((resolveListen) => server.listen(0, resolveListen));
  const address = server.address();
  assert.equal(typeof address, "object");
  assert.ok(address);
  const baseUrl = `http://127.0.0.1:${(address as AddressInfo).port}`;
  try {
    return await fn(baseUrl);
  } finally {
    await new Promise<void>((resolveClose) => server.close(() => resolveClose()));
  }
}

async function request<T>(baseUrl: string, path: string, user: string, body?: unknown): Promise<T> {
  const response = await fetch(new URL(path, baseUrl), {
    method: body ? "POST" : "GET",
    headers: {
      "content-type": "application/json",
      authorization: `Bearer dev:${user}`
    },
    body: body ? JSON.stringify(body) : undefined
  });
  const json = (await response.json()) as T & { error?: { code?: string; message?: string } };
  if (!response.ok) {
    throw new Error(`${response.status} ${json.error?.code}: ${json.error?.message}`);
  }
  return json;
}

test("hub registers a service and issues purpose-bound SSH credentials", async () => {
  await withHub(async (baseUrl) => {
    const created = await request<{ team: { team_id: string } }>(baseUrl, "/api/v1/teams", "alice@example.com", {
      slug: "team-acme",
      display_name: "Team Acme"
    });
    const teamId = created.team.team_id;

    const host = await request<{ host: { host_id: string } }>(baseUrl, "/api/v1/tunnel/hosts", "alice@example.com", {
      team_id: teamId,
      name: "gpu-box",
      public_key: "ssh-ed25519 AAAATEST alice",
      device_name: "alice-mac"
    });

    const service = await request<{ service: { service_id: string } }>(
      baseUrl,
      "/api/v1/tunnel/services",
      "alice@example.com",
      {
        team_id: teamId,
        host_id: host.host.host_id,
        name: "gpu-box",
        upstream_hint: "127.0.0.1:8000",
        models: [{ id: "local-llm" }]
      }
    );

    const serveCred = await request<{
      credential: {
        credential_id: string;
        direction: string;
        restrictions: { no_shell: boolean; permit_listen: string };
        ssh: { hub_bind: string };
      };
    }>(baseUrl, "/api/v1/tunnel/ssh-credentials:issue", "alice@example.com", {
      team_id: teamId,
      service_id: service.service.service_id,
      direction: "serve",
      public_key: "ssh-ed25519 AAAATEST alice"
    });

    assert.equal(serveCred.credential.direction, "serve");
    assert.equal(serveCred.credential.restrictions.no_shell, true);
    assert.match(serveCred.credential.restrictions.permit_listen, /^127\.0\.0\.1:/);

    await request(baseUrl, "/api/v1/tunnel/sessions", "alice@example.com", {
      team_id: teamId,
      credential_id: serveCred.credential.credential_id,
      hub_bind: serveCred.credential.ssh.hub_bind
    });

    const connectCred = await request<{
      credential: {
        direction: string;
        restrictions: { permit_open: string };
        ssh: { open_target: string };
      };
    }>(baseUrl, "/api/v1/tunnel/ssh-credentials:issue", "alice@example.com", {
      team_id: teamId,
      service_id: service.service.service_id,
      direction: "connect",
      public_key: "ssh-ed25519 AAAATEST alice"
    });

    assert.equal(connectCred.credential.direction, "connect");
    assert.equal(connectCred.credential.restrictions.permit_open, serveCred.credential.ssh.hub_bind);
    assert.equal(connectCred.credential.ssh.open_target, serveCred.credential.ssh.hub_bind);
  });
});

test("hub rejects cross-team service discovery", async () => {
  await withHub(async (baseUrl) => {
    const created = await request<{ team: { team_id: string } }>(baseUrl, "/api/v1/teams", "alice@example.com", {
      slug: "team-acme"
    });
    await assert.rejects(
      () =>
        request(
          baseUrl,
          `/api/v1/tunnel/services?team_id=${encodeURIComponent(created.team.team_id)}`,
          "bob@example.com"
        ),
      /403 team_forbidden/
    );
  });
});
