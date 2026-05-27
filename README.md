# modelport

Share a local OpenAI-compatible model server with your team without asking
anyone to join a VPN.

```bash
modelport serve --team team-acme --name gpu-box --upstream 127.0.0.1:8000
modelport connect gpu-box --team team-acme --local 127.0.0.1:11434
export OPENAI_BASE_URL=http://127.0.0.1:11434/v1
```

This repository contains the first shippable slice of the product:

- a TypeScript hub API with file-backed JSON state;
- a static dashboard served by the hub;
- a `modelport` CLI for login, teams, serving, listing, connecting, and
  environment output;
- shared protocol types and tunnel command builders;
- tests covering API policy and SSH command restrictions.

The MVP intentionally does not depend on amesh. A future adapter can map
modelport teams, audit events, and model-serving rows into amesh for enterprise
deployments.

## Quickstart

Install dependencies and build:

```bash
npm install
npm run build
```

Start a local hub:

```bash
MODELPORT_DATA_DIR=.modelport npm start
```

In another terminal:

```bash
npm link
modelport login --hub http://127.0.0.1:8787 --user alice@example.com
modelport team create team-acme
modelport serve --team team-acme --name gpu-box --upstream 127.0.0.1:8000 --model local-llm
modelport ls --team team-acme
modelport connect gpu-box --team team-acme --local 127.0.0.1:11434
```

The current CLI prints restricted OpenSSH commands and records sessions in the
hub. A production tunnel broker/SSH CA is the next hardening slice.

## Security posture

The first implementation keeps the core PRD invariants visible in code:

- private SSH keys are never uploaded;
- hub credentials are short-lived and purpose-bound;
- serve and connect credentials have different principals and restrictions;
- reverse listeners are hub-loopback only;
- client forwards bind to local loopback by default;
- team membership is checked before service discovery and credential issuance;
- audit records are metadata-only.

## Repository layout

```text
apps/hub-api/       Node HTTP API and JSON store
apps/hub-web/       Static dashboard
apps/cli/           modelport CLI
packages/protocol/  Shared data contracts and validation helpers
packages/tunnel/    OpenSSH command builders
docs/               Product and implementation notes
```

## Commands

```bash
npm run build
npm test
npm run verify
```
