# Product Direction

Modelport is the independent OSS implementation of the lightweight model
tunnel described in the amesh PRD research.

The product boundary is intentionally small:

- `modelport` owns the standalone CLI, hosted/self-hosted hub, tunnel broker,
  dashboard, team/device/session model, and OpenAI-compatible ergonomics.
- `amesh` remains the enterprise mesh/control plane for WireGuard, enrollment,
  resident agents, fleet policy, audit, and model registry.
- A later enterprise adapter may connect modelport to amesh identity, audit,
  model-serving rows, and private-route policies.

The day-one implementation in this repo is a working vertical slice rather
than the whole future system:

- file-backed hub state for teams, devices, hosts, services, sessions,
  credentials, and audit;
- CLI flows for login, team setup, service registration, discovery, and local
  tunnel command generation;
- static dashboard for human inspection;
- tests for access control and command restrictions.

Next slices:

1. Replace dev bearer identity with OAuth 2.1-aligned PKCE and device-code
   flows.
2. Add a real SSH CA or purpose-built SSH broker that enforces the restrictions
   currently represented in issued credentials.
3. Add live tunnel heartbeats and disconnect detection.
4. Add opencode profile helpers.
5. Add optional amesh adapter package.
