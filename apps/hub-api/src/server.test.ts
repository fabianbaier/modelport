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

async function signup(baseUrl: string, email: string): Promise<string> {
  const response = await fetch(new URL("/api/v1/auth/signup", baseUrl), {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify({ email })
  });
  const json = (await response.json()) as { token?: string; error?: { message?: string } };
  if (!response.ok || !json.token) {
    throw new Error(json.error?.message || `signup failed: ${response.status}`);
  }
  return json.token;
}

async function requestToken<T>(baseUrl: string, path: string, token: string, body?: unknown): Promise<T> {
  const response = await fetch(new URL(path, baseUrl), {
    method: body ? "POST" : "GET",
    headers: {
      "content-type": "application/json",
      authorization: `Bearer ${token}`
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

test("public auth signs users in and accepts invite links", async () => {
  const dataDir = await mkdtemp(join(tmpdir(), "modelport-public-test-"));
  const server = createHubServer({
    dataDir,
    webDir: resolve("apps/hub-web"),
    tunnelHost: "hub.local",
    tunnelPort: 2222,
    tunnelUser: "modelport",
    allowDevAuth: false,
    publicBaseUrl: "https://modelport.example"
  });
  await new Promise<void>((resolveListen) => server.listen(0, resolveListen));
  const address = server.address();
  assert.equal(typeof address, "object");
  assert.ok(address);
  const baseUrl = `http://127.0.0.1:${(address as AddressInfo).port}`;
  try {
    const ownerToken = await signup(baseUrl, "owner@example.com");
    await assert.rejects(
      () => request(baseUrl, "/api/v1/teams", "owner@example.com"),
      /401 auth_required/
    );
    const created = await requestToken<{ team: { team_id: string } }>(baseUrl, "/api/v1/teams", ownerToken, {
      slug: "team-public"
    });
    const invite = await requestToken<{ accept_url: string; token: string }>(
      baseUrl,
      `/api/v1/teams/${created.team.team_id}/invites`,
      ownerToken,
      { email: "teammate@example.com", role: "member" }
    );
    assert.match(invite.accept_url, /^https:\/\/modelport\.example\/\?invite=invite_/);

    const teammateToken = await signup(baseUrl, "teammate@example.com");
    const accepted = await requestToken<{ team: { slug: string } }>(
      baseUrl,
      "/api/v1/invites/accept",
      teammateToken,
      { token: invite.token }
    );
    assert.equal(accepted.team.slug, "team-public");
    const teams = await requestToken<{ teams: Array<{ slug: string }> }>(baseUrl, "/api/v1/teams", teammateToken);
    assert.deepEqual(teams.teams.map((team) => team.slug), ["team-public"]);
  } finally {
    await new Promise<void>((resolveClose) => server.close(() => resolveClose()));
  }
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
