# clawpushrelay

`clawpushrelay` is a Convex-backed APNs relay for official OpenClaw iOS builds. It owns
production APNs credentials, verifies App Attest plus App Store receipt proof during
registration, stores APNs tokens encrypted at rest, and returns opaque relay handles plus
scoped send grants to the OpenClaw gateway for alert and wake pushes.

## Endpoints

- `POST /v1/push/challenge`
- `POST /v1/push/register`
- `POST /v1/push/send`
- `GET /healthz`

## Runtime Shape

- Convex HTTP actions expose the public API.
- Convex tables store challenges, registrations, App Attest keys, and rate-limit events.
- Convex Node actions handle App Attest, Apple receipt validation, APNs JWT creation, and APNs
  HTTP/2 sends.
- A Convex cron prunes expired challenges and rate-limit rows.

## Required Convex Env Vars

Set these on the Convex deployment, not in application code:

- `RELAY_ENC_KEY`
  32-byte encryption key encoded as base64/base64url or 64-char hex.
- `RELAY_ALLOWED_BUNDLE_IDS`
  Comma-separated allowlist. Default intended value: `ai.openclaw.client`.
- `APPLE_TEAM_ID`
  Apple team identifier used for App Attest verification.
- `APP_ATTEST_ALLOW_DEV`
  Optional. Set `true` only for non-production App Attest testing.
- `APNS_TEAM_ID`
- `APNS_KEY_ID`
- `APNS_P8`
  APNs auth key contents as a single string. Escaped `\n` sequences are normalized at runtime.
  Quoted dotenv-style values are also accepted.
- `APPLE_RECEIPT_SECRET`
  Optional. Only needed if your receipt validation flow requires the shared secret.
- `HANDLE_TTL_MS`
  Optional. Default: `2592000000`.
- `CHALLENGE_TTL_MS`
  Optional. Default: `300000`.
- `RATE_LIMIT_WINDOW_MS`
  Optional. Default: `60000`.
- `CHALLENGE_RATE_LIMIT_MAX`
  Optional. Default: `30`.
- `REGISTER_RATE_LIMIT_MAX`
  Optional. Default: `10`.
- `SEND_RATE_LIMIT_MAX`
  Optional. Default: `120`.

See `.env.example` for a template.

## Local Development

```bash
bun install
bun run dev
bun test
bun run typecheck
```

`bun run dev` will prompt you to create or select a Convex project the first time. After the
deployment exists, set the required env vars with `convex env set` or in the Convex dashboard.

## Deploying

Use Convex as the primary deployment target:

```bash
bun run convex:deploy
```

For the full bootstrap, env, custom-domain, and smoke-test flow, see
[docs/convex-deployment-runbook.md](/Users/guti/projects/clawpushrelay/docs/convex-deployment-runbook.md).

## OpenClaw Wiring

Set these in the OpenClaw gateway environment:

- `OPENCLAW_APNS_RELAY_BASE_URL=https://relay.example.com`

Set this in official iOS builds:

- `OPENCLAW_PUSH_RELAY_BASE_URL=https://relay.example.com`

Local Xcode installs should continue using direct APNs registration and do not need relay config.

## Security Notes

- `register` accepts only `production` / `official` registrations.
- `register` rejects requests when App Attest verification fails.
- `register` rejects requests when Apple receipt validation fails.
- successful registration returns a per-registration send grant that the app forwards to the paired gateway.
- `send` rejects requests without the current registration's send grant.
- APNs tokens are encrypted at rest.
- Relay handles are stored server-side only as SHA-256 hashes.

## Verification

Run these before and after deployment changes:

```bash
bun test
bun run typecheck
```

Recommended smoke checks against a deployed environment:

- `curl -fsS https://relay.example.com/healthz`
- complete one real registration flow from an official iOS build
- trigger one real `push.test` send from the gateway

## Docs

- [docs/convex-deployment-runbook.md](/Users/guti/projects/clawpushrelay/docs/convex-deployment-runbook.md)
- [docs/convex-implementation-plan.md](/Users/guti/projects/clawpushrelay/docs/convex-implementation-plan.md)
- [docs/convex-refactor-spec.md](/Users/guti/projects/clawpushrelay/docs/convex-refactor-spec.md)
- [docs/aws-deployment-spec.md](/Users/guti/projects/clawpushrelay/docs/aws-deployment-spec.md)
  This is now a legacy containerized deployment note, not the primary path.
