# Convex Deployment Runbook

This is the primary deployment path for `clawpushrelay`.

## 1. Bootstrap the Convex project

From the repo root:

```bash
bun install
bun run dev
```

The first run will prompt you to create or select a Convex project and deployment. After that,
Convex will maintain the local project linkage and `convex/_generated`.

## 2. Set deployment env vars

Set these in Convex:

- `RELAY_ENC_KEY`
- `RELAY_ALLOWED_BUNDLE_IDS`
- `APPLE_TEAM_ID`
- `APP_ATTEST_ALLOW_DEV`
- `APNS_TEAM_ID`
- `APNS_KEY_ID`
- `APNS_P8`
- `APPLE_RECEIPT_SECRET`
- `HANDLE_TTL_MS`
- `CHALLENGE_TTL_MS`
- `RATE_LIMIT_WINDOW_MS`
- `CHALLENGE_RATE_LIMIT_MAX`
- `REGISTER_RATE_LIMIT_MAX`
- `SEND_RATE_LIMIT_MAX`

Use [.env.example](/Users/guti/projects/clawpushrelay/.env.example) as the value template.

## 3. Validate locally

```bash
bun test
bun run typecheck
```

## 4. Deploy

```bash
bun run convex:deploy
```

## 5. Attach DNS and HTTPS

Use Convex custom domains for the relay base URL. Convex manages HTTPS termination for the
custom domain once DNS is configured in your DNS provider.

Target URL shape:

- `https://relay.example.com`

Then wire:

- iOS app: `OPENCLAW_PUSH_RELAY_BASE_URL=https://relay.example.com`
- gateway: `OPENCLAW_APNS_RELAY_BASE_URL=https://relay.example.com`

## 6. Smoke checks

- `curl -fsS https://relay.example.com/healthz`
- complete one official-build registration
- complete one gateway send

## 7. Operational notes

- Convex cron pruning handles expired challenges and rate-limit rows.
- App Attest and APNs logic run in Convex Node actions, so cold starts can add some latency to
  register/send flows.
- Registration mints a per-registration send grant, so the gateway no longer needs a shared relay
  auth secret.
- Manual end-to-end verification still requires a real Convex deployment; local tests only cover
  stubbed Apple dependencies and APNs transport.
