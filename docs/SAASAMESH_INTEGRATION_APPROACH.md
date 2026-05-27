# Combining saasamesh and modelport

## Goal

Modelport should become the BYOM access plane: teams bring their own
OpenAI-compatible model servers, register them with a hub, and let members use
`modelport connect` to expose an approved team model on local loopback for tools
such as opencode.

## Round 1: Product Fit

`saasamesh` has the stronger dashboard and harness story. It covers signup,
groups, invites, admin/member roles, server inventory, GPU metadata, endpoint
validation, and an opencode bootstrap script.

`modelport` has the stronger tunnel product shape. It already has a standalone
CLI, team/device/service/session records, service discovery, and explicit
`serve`/`connect` flows for reverse SSH.

Decision: keep modelport as the product and codebase, then pull saasamesh's
dashboard, harness, GPU inventory, and opencode ergonomics into it.

## Round 2: Security Fit

`saasamesh` asks admins to paste private SSH keys into the SaaS. That is not the
right trust boundary for BYOM. A compromised SaaS should not become a private key
vault for every GPU server.

`modelport` keeps private keys local and stores public keys/fingerprints. Its
credential objects already separate `serve` and `connect`, constrain loopback
binds, and model the restrictions a real SSH broker needs to enforce.

Decision: do not copy private key upload. Modelport should generate or reuse
local client keys, register public keys, and issue short-lived restricted SSH
certificates or authorized-key entries.

## Round 3: Runtime Fit

`saasamesh` is Cloudflare Worker-native, which is excellent for SaaS signup and
dashboards but cannot run a raw SSH broker. The repo also documents that Workers
cannot open raw SSH connections.

`modelport` is a Node service and can run alongside an SSH broker on a VM. That
is a better fit for reverse SSH tunnels, broker-side authorized key management,
and live session cleanup.

Decision: use a normal VM/container deployment for the broker path. A future
Cloudflare Worker can front the pure web/API surface, but the tunnel broker
belongs in a process that can manage SSH.

## Recommended Architecture

1. Web hub
   - Signup, sessions, teams, invites, roles.
   - Dashboard styled like the saasamesh operator console.
   - Team model inventory, GPU metadata, audit, active sessions.

2. CLI
   - `modelport login`
   - `modelport team create|invite|members`
   - `modelport serve --team acme --name gpu-a1 --upstream 127.0.0.1:8000 --execute`
   - `modelport connect gpu-a1 --team acme --local 127.0.0.1:11434 --execute`
   - `modelport opencode gpu-a1 --team acme`

3. Broker
   - Public SSH endpoint on a dedicated port.
   - Hub-issued short-lived credentials.
   - `serve` credentials get `permitlisten` only for the assigned hub-loopback
     port.
   - `connect` credentials get `permitopen` only for the chosen service's
     current hub-loopback port.
   - No shell, no PTY, no agent forwarding, no X11 forwarding.

4. Harness and opencode
   - Borrow saasamesh's curlable harness idea, but make it call `modelport`
     rather than downloading server SSH private keys.
   - Store opencode provider config pointing to the local bind, for example
     `http://127.0.0.1:11434/v1`.
   - Add model selection when a team exposes multiple services.

5. Inventory
   - Add `/v1/models` validation.
   - Add optional GPU reports from the serving host.
   - Keep endpoint and GPU metadata in the hub, but never persist model-provider
     secrets or private SSH keys.

## First Implementation Slice

Build the broker loop next:

1. Add broker key management and a `modelport` SSH user on the hub.
2. Generate per-session client keypairs in the CLI or reuse a configured local
   key.
3. Add hub APIs for issuing and revoking short-lived broker authorizations.
4. Make `modelport serve --execute` open the reverse SSH tunnel.
5. Make `modelport connect --execute` open the local loopback forward.
6. Add `modelport opencode` to write the local OpenAI-compatible provider.

This combines the best of both repos: saasamesh's operator-grade SaaS polish and
opencode onboarding with modelport's safer public-key, team-scoped tunnel model.
