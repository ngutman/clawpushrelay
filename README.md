# clawpushrelay

`clawpushrelay` is a standalone APNs relay for official OpenClaw iOS builds. It owns production
APNs credentials, verifies App Attest + App Store receipt proof during registration, stores APNs
tokens encrypted at rest, and gives the OpenClaw gateway opaque relay handles for alert and wake
pushes.

## Endpoints

- `POST /v1/push/challenge`
- `POST /v1/push/register`
- `POST /v1/push/send`
- `GET /healthz`

## Security Model

- `register` accepts only `production` / `official` registrations.
- `register` rejects requests when App Attest verification fails.
- `register` rejects requests when Apple receipt validation fails.
- `send` rejects requests without the configured gateway bearer token.
- APNs tokens are encrypted at rest.
- Relay handles are returned once to the client and stored server-side only as SHA-256 hashes.

## Required Environment

Copy `.env.example` and fill in real values before running.

### Core

- `CLAWPUSHRELAY_HOST`
  Default: `127.0.0.1`
- `CLAWPUSHRELAY_PORT`
  Default: `8787`
- `CLAWPUSHRELAY_TRUST_PROXY`
  Default: `false`
  Set `true` or a comma-separated allowlist when running behind a reverse proxy so rate limits and
  request IPs use forwarded headers correctly.
- `CLAWPUSHRELAY_STATE_DIR`
  Default: `./data`
- `CLAWPUSHRELAY_ENCRYPTION_KEY`
  32-byte relay state key, encoded as base64/base64url or 64-char hex.
- `CLAWPUSHRELAY_GATEWAY_BEARER_TOKEN`
  Bearer token required on `POST /v1/push/send`.
- `CLAWPUSHRELAY_ALLOWED_BUNDLE_IDS`
  Comma-separated allowlist. Default: `ai.openclaw.client`
- `CLAWPUSHRELAY_APPLE_TEAM_ID`
  Apple team identifier used for App Attest verification.
- `CLAWPUSHRELAY_APP_ATTEST_ALLOW_DEVELOPMENT`
  Optional. Set to `true` only in non-production test environments.

### APNs

- `CLAWPUSHRELAY_APNS_TEAM_ID`
- `CLAWPUSHRELAY_APNS_KEY_ID`
- `CLAWPUSHRELAY_APNS_PRIVATE_KEY_P8` or `CLAWPUSHRELAY_APNS_PRIVATE_KEY_PATH`

### Receipt Validation

- `CLAWPUSHRELAY_APPLE_RECEIPT_SHARED_SECRET`
  Optional. Only needed if your app’s receipt validation flow requires the shared secret.

## OpenClaw Wiring

The relay sits between the iOS app and the OpenClaw gateway, so both sides need matching
configuration.

### Gateway

Set these in the OpenClaw gateway environment:

- `OPENCLAW_APNS_RELAY_BASE_URL=https://relay.example.com`
- `OPENCLAW_APNS_RELAY_AUTH_TOKEN=<same value as CLAWPUSHRELAY_GATEWAY_BEARER_TOKEN>`

### Official iOS builds

Set this when preparing TestFlight or App Store builds:

- `OPENCLAW_PUSH_RELAY_BASE_URL=https://relay.example.com`

Local Xcode installs should continue using direct APNs registration and do not need relay config.

## Local Development

```bash
pnpm install
pnpm test
pnpm typecheck
pnpm dev
```

## Production Run

Build and run the compiled service:

```bash
pnpm install --frozen-lockfile
pnpm build
pnpm start
```

Recommended smoke checks:

```bash
curl -fsS http://127.0.0.1:8787/healthz
pnpm test
pnpm typecheck
```

`GET /healthz` is a process-level probe only. It does not prove that Apple receipt validation,
App Attest verification, or APNs delivery are currently succeeding.

## Docker

Build:

```bash
docker build -t clawpushrelay .
```

Run:

```bash
docker run --rm \
  -p 8787:8787 \
  --env-file .env.local \
  -e CLAWPUSHRELAY_HOST=0.0.0.0 \
  -v "$(pwd)/data:/app/data" \
  clawpushrelay
```

## Deployment Notes

- Use HTTPS in front of the relay for all internet-facing traffic.
- Put the relay behind a reverse proxy or load balancer that preserves client IPs, and configure
  `CLAWPUSHRELAY_TRUST_PROXY` accordingly.
- Persist `CLAWPUSHRELAY_STATE_DIR`; losing it invalidates stored App Attest keys and relay
  registrations.
- Back up `relay-state.json` like application state, not like source code.
- Rotate `CLAWPUSHRELAY_ENCRYPTION_KEY`, `CLAWPUSHRELAY_GATEWAY_BEARER_TOKEN`, and the APNs auth
  key deliberately. Rotating the encryption key without re-encrypting state will invalidate stored
  registrations.

## Deployment Checklist

Before exposing the relay publicly:

- Create a dedicated DNS name and terminate TLS in front of the relay.
- Generate and store `CLAWPUSHRELAY_ENCRYPTION_KEY` and `CLAWPUSHRELAY_GATEWAY_BEARER_TOKEN` in
  your secret manager.
- Configure `CLAWPUSHRELAY_TRUST_PROXY` so request IPs and rate limits reflect real clients.
- Mount persistent storage for `CLAWPUSHRELAY_STATE_DIR`.
- Confirm the APNs auth key and Apple Team IDs match the shipping iOS app bundle ID.
- Confirm the gateway is configured with the same relay base URL and bearer token.
- Run the smoke checks below after every deploy.

## Smoke Checklist

- `curl -fsS https://relay.example.com/healthz`
- `pnpm test`
- `pnpm typecheck`
- Trigger one end-to-end registration from a TestFlight build.
- Trigger one end-to-end `push.test` send from the gateway.

## Operations Notes

- Keep the service single-writer. The local JSON state file is not safe for multi-process or
  multi-host writes.
- Keep the reverse proxy idle timeout above the relay request timeout budget.
- Monitor `401` registration failures separately from `503` receipt verification failures; they
  indicate different operator actions.
- Treat `relay-state.json` as durable application state. Restore it with the same encryption key
  that was used when it was written.

## Scaling And Topology Constraints

This implementation is designed for a single writable instance with persistent local state.

- Challenges are in-memory only.
- Rate limiting is in-memory only.
- State is stored in a local JSON file.

That means:

- run a single relay instance, or
- use sticky sessions and accept that rate limits and challenges remain instance-local.

Do not horizontally scale this service behind a stateless load balancer unless you first move
challenge/rate-limit/state storage to shared infrastructure.

## State Model

State is stored in `CLAWPUSHRELAY_STATE_DIR/relay-state.json` and includes:

- App Attest key records
- Active/stale relay registrations
- APNs delivery metadata

Challenges are short-lived and stored in memory only.
