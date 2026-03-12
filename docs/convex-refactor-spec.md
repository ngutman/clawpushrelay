# Convex Refactor Spec

Historical note: this spec was written before the legacy `src/` Fastify runtime was deleted.
References to `src/...` describe the removed implementation and are kept as historical context.

This document specifies how to refactor `clawpushrelay` from a single-process Fastify service into a Convex-backed service while preserving the current public API and security model.

## Decision Summary

Convex is a simpler operational target than AWS for this service, but only after a real refactor.

- Simpler operations: no ALB, no EC2, no EBS, no Docker deploy pipeline
- Built-in HTTPS on `*.convex.site`
- Custom domain support with managed SSL on Convex Pro
- Persistent database replaces the local JSON state file

This is not a lift-and-shift. The current Fastify server cannot be deployed to Convex unchanged.

## Goals

- Preserve the existing HTTP contract:
  - `POST /v1/push/challenge`
  - `POST /v1/push/register`
  - `POST /v1/push/send`
  - `GET /healthz`
- Preserve current security properties:
  - official production-only registration
  - App Attest verification
  - App Store receipt validation
  - bearer token on `/v1/push/send`
  - APNs token encryption at rest
  - relay handles returned once and stored only as hashes
- Remove filesystem persistence and process-local state
- Keep gateway and iOS configuration unchanged except for the base URL

## Non-Goals

- No protocol changes for the iOS client or gateway
- No new admin UI
- No background queue redesign for push delivery in the first pass
- No multi-tenant generalization

## Why The Current Design Must Change

The current service depends on process-local and filesystem state:

- local durable state file: [src/state-store.ts](/Users/guti/projects/clawpushrelay/src/state-store.ts#L21)
- in-memory challenges: [src/challenges.ts](/Users/guti/projects/clawpushrelay/src/challenges.ts#L4)
- in-memory rate limiting: [src/rate-limit.ts](/Users/guti/projects/clawpushrelay/src/rate-limit.ts#L5)
- Node-only APNs transport over HTTP/2: [src/apns.ts](/Users/guti/projects/clawpushrelay/src/apns.ts#L1)
- Fastify route wiring: [src/app.ts](/Users/guti/projects/clawpushrelay/src/app.ts#L12)

Convex HTTP actions do not have Node.js-specific APIs, but they can call actions, and actions can run in Node.js. That boundary drives the target design.

## Target Convex Architecture

### Public Surface

Expose the same endpoints via `convex/http.ts` using Convex `httpAction`s:

- `POST /v1/push/challenge`
- `POST /v1/push/register`
- `POST /v1/push/send`
- `GET /healthz`

### Runtime Split

Use three layers:

- `httpAction` layer
  - request parsing
  - response formatting
  - route registration
  - calling internal mutations and actions
- internal queries and mutations
  - all database reads and writes
  - challenge issuance and consumption
  - rate-limit bookkeeping
  - registration state transitions
- Node actions in `"use node"` files
  - App Attest verification
  - APNs JWT signing
  - APNs HTTP/2 send
  - AES-GCM encryption and decryption

Reasoning:

- Convex docs state that HTTP actions run in the same environment as queries and mutations and do not have access to Node.js APIs.
- Convex docs also state that actions can run in Node.js with `"use node"` and should be called with `ctx.runAction` only when crossing runtimes.

That maps well to this service:

- HTTP endpoints stay in `httpAction`
- crypto, `node:http2`, and `node-app-attest` move to Node actions
- state moves to Convex tables

## Proposed File Layout

```text
convex/
  http.ts
  schema.ts
  crons.ts
  relay/
    config.ts
    validators.ts
    types.ts
    hashes.ts
    http.ts
    internal.ts
    registerNode.ts
    sendNode.ts
    receiptAction.ts
```

File responsibilities:

- `convex/http.ts`
  - define `HttpRouter`
  - mount the four public routes
- `convex/schema.ts`
  - Convex table definitions and indexes
- `convex/crons.ts`
  - recurring cleanup for expired challenges and stale rate-limit rows
- `convex/relay/config.ts`
  - load and validate env vars
  - parse comma-separated bundle list
  - parse numeric knobs
- `convex/relay/validators.ts`
  - zod request validation copied from current service
- `convex/relay/hashes.ts`
  - pure SHA-256 and base64url helpers that do not require Node-only runtime
- `convex/relay/internal.ts`
  - internal queries and mutations for all state transitions
- `convex/relay/registerNode.ts`
  - Node action for App Attest verification, receipt validation, encryption, and registration upsert
- `convex/relay/sendNode.ts`
  - Node action for lookup, decrypt, APNs send, and send-result persistence
- `convex/relay/receiptAction.ts`
  - optional non-Node action if we want receipt validation isolated from the register action

## Data Model

Replace `relay-state.json` with Convex tables.

### `challenges`

Fields:

- `challengeId: string`
- `challenge: string`
- `createdAtMs: number`
- `expiresAtMs: number`
- `consumedAtMs?: number`

Indexes:

- `by_challenge_id`
- `by_expires_at`

Notes:

- Keep one-time consumption semantics.
- A challenge is valid only if present, not consumed, and not expired.

### `app_attest_keys`

Fields:

- `keyId: string`
- `installationId: string`
- `bundleId: string`
- `environment: "production"`
- `publicKey: string`
- `signCount: number`
- `attestedAtMs: number`
- `lastAssertedAtMs: number`
- `revokedAtMs?: number`

Indexes:

- `by_key_id`
- `by_installation_bundle_environment`

### `registrations`

Fields:

- `registrationId: string`
- `installationId: string`
- `bundleId: string`
- `environment: "production"`
- `distribution: "official"`
- `apnsTopic: string`
- `apnsTokenCiphertext: string`
- `apnsTokenHash: string`
- `tokenSuffix: string`
- `relayHandleHash: string`
- `relayHandleExpiresAtMs: number`
- `appAttestKeyId: string`
- `proofType: "receipt"`
- `receiptEnvironment: string`
- `appVersion: string`
- `status: "active" | "stale" | "revoked"`
- `createdAtMs: number`
- `updatedAtMs: number`
- `lastRegisteredAtMs: number`
- `lastSentAtMs?: number`
- `lastApnsStatus?: number`
- `lastApnsReason?: string`

Indexes:

- `by_relay_handle_hash`
- `by_installation_bundle_environment_status`
- `by_app_attest_key_id`
- `by_handle_expiry`

Notes:

- Preserve the current invariant that only one active registration exists per `installationId + bundleId + environment`.
- On successful registration, previous active registrations for the same tuple become `stale`.

### `rate_limit_events`

Fields:

- `scope: "challenge" | "register" | "send"`
- `subjectHash: string`
- `createdAtMs: number`
- `expiresAtMs: number`

Indexes:

- `by_scope_subject_created_at`
- `by_expires_at`

Notes:

- This table replaces the current in-memory sliding window.
- `subjectHash` should be derived from request IP or auth principal. Hash it before storage.
- This is acceptable for the expected low request volume of the relay.
- If request volume later grows materially, replace this with bucketed counters or a dedicated rate-limiter component.

## Environment Variables

Do not reuse the current env names verbatim. Convex environment variable names are limited to 40 characters, and at least these current names exceed that limit:

- `CLAWPUSHRELAY_APP_ATTEST_ALLOW_DEVELOPMENT` length 42
- `CLAWPUSHRELAY_APPLE_RECEIPT_SHARED_SECRET` length 41

Use this Convex-specific mapping instead:

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

Gateway sends should authenticate with a registration-scoped send grant minted by `register`,
not a deployment-wide shared bearer token.
- `REGISTER_RATE_LIMIT_MAX`
- `SEND_RATE_LIMIT_MAX`

Notes:

- `APNS_P8` should fit within Convex's 8KB env value limit.
- Continue storing the APNs private key as a single multiline string with `\n` replacement handling.
- Keep `RELAY_ENC_KEY` stable across redeploys.

## Request Flows

### `POST /v1/push/challenge`

Target flow:

1. `httpAction` parses request metadata.
2. Internal mutation enforces rate limit for the client IP.
3. Internal mutation inserts a challenge row with TTL.
4. Response returns `challengeId`, `challenge`, `createdAtMs`, `expiresAtMs`.

Behavioral parity:

- still unauthenticated
- still rate limited by client IP
- still one-time challenge consumption on register

### `POST /v1/push/register`

Target flow:

1. `httpAction` validates JSON with the existing zod schema.
2. Internal mutation enforces rate limit and consumes the challenge atomically.
3. Node action:
   - loads config from `process.env`
   - fetches the existing App Attest key record by `keyId`
   - verifies App Attest using `node-app-attest`
   - validates the App Store receipt
   - encrypts the APNs token with AES-GCM
   - generates a new opaque relay handle
4. Internal mutation:
   - upserts the App Attest key record
   - marks any prior active registration for the same installation tuple as `stale`
   - inserts the new active registration
5. Return the same response shape as today.

Behavioral parity:

- `environment` must remain `production`
- `distribution` must remain `official`
- bundle ID must be in the allowlist
- App Attest failures remain `401`
- Apple receipt service failures remain `503`

### `POST /v1/push/send`

Target flow:

1. `httpAction` checks `Authorization: Bearer`.
2. `httpAction` validates JSON with the existing send schema.
3. Internal mutation enforces rate limit.
4. Node action:
   - hashes the provided relay handle
   - fetches the registration by `relayHandleHash`
   - rejects missing, stale, revoked, or expired registrations
   - decrypts the APNs token
   - sends the push over APNs HTTP/2
5. Internal mutation records the APNs result and marks the registration stale on:
   - `410`
   - `400` with `BadDeviceToken`
6. Return the same response body and HTTP status as today.

Behavioral parity:

- no queue introduced in the first pass
- still synchronous
- still bearer-token protected

### `GET /healthz`

Target flow:

- trivial `httpAction` returning `{ ok: true }`

Keep this as a process/deployment health probe only. It should not call Apple or APNs.

## Internal Function Design

Use a small set of coarse-grained internal functions instead of many tiny calls.

Recommended internal mutations:

- `issueChallenge`
- `consumeChallengeAndCheckRegisterRateLimit`
- `checkChallengeRateLimit`
- `checkSendRateLimit`
- `upsertVerifiedRegistration`
- `markRegistrationStatus`
- `recordSendResult`
- `pruneExpiredChallenges`
- `pruneExpiredRateLimitEvents`

Recommended internal queries:

- `getAppAttestKeyByKeyId`
- `getRegistrationForSendByHandleHash`

Reasoning:

- Convex recommends that `ctx.runAction` only be used when crossing JS runtimes.
- Actions should batch database work through a few internal queries and mutations, not many tiny round trips.

## Cryptography

Preserve the current wire and storage behavior where possible:

- keep relay handles opaque random tokens
- keep only `relayHandleHash` in storage
- keep APNs token encryption format compatible with the current AES-256-GCM format if migration matters
- keep token suffix and token hash behavior unchanged

Recommended implementation choice:

- copy the existing crypto helpers with minimal changes
- move Node-dependent encryption helpers into a `"use node"` module
- keep pure hashing helpers in a runtime-neutral module

## DNS And HTTPS On Convex

Deployment options:

- simplest: use the default `https://<deployment>.convex.site`
- production: attach `relay.example.com` as a Convex custom domain

For a custom domain:

- Convex custom domains require the Pro plan
- Convex shows the DNS records to create
- Convex mints SSL after verification

This removes the AWS ALB + ACM + Route 53 alias setup entirely. If your DNS is already in Route 53, you would only create the records Convex requests there.

## Testing Plan

Keep three layers of tests.

### Pure unit tests

Test:

- validators
- hashing helpers
- payload validation
- config parsing

### Function-level tests

Test internal mutations and queries for:

- challenge issue and consume semantics
- stale-on-replace registration logic
- stale-on-APNs-terminal-error logic
- rate limit enforcement

### End-to-end HTTP tests

Run HTTP-level tests against Convex endpoints for:

- challenge -> register -> send happy path
- invalid challenge
- invalid bearer token
- App Attest failure
- receipt service unavailable
- expired handle

Reuse the current route behavior from [src/app.test.ts](/Users/guti/projects/clawpushrelay/src/app.test.ts#L110) as the parity baseline.

## Migration Plan

### Phase 0: Feasibility Spike

Do this before the full rewrite:

1. Prove `node-app-attest` works in a Convex `"use node"` action.
2. Prove APNs send via `node:http2` works in a Convex `"use node"` action.
3. Confirm the APNs private key fits comfortably in `APNS_P8`.

Go/no-go criteria:

- App Attest verification succeeds against a real or representative test payload.
- APNs send reaches Apple and returns a real APNs response.

### Phase 1: Convex Scaffolding

1. Add Convex to the repo.
2. Create `schema.ts`, `http.ts`, and relay modules.
3. Add env parsing and validation.

### Phase 2: State Migration

1. Implement tables and indexes.
2. Replace challenge and rate-limit memory stores with mutations.
3. Replace `relay-state.json` access with Convex queries and mutations.

### Phase 3: Registration Path

1. Implement `/v1/push/challenge`.
2. Implement `/v1/push/register`.
3. Verify parity with current tests and a real device registration.

### Phase 4: Send Path

1. Implement `/v1/push/send`.
2. Verify parity with current tests and a real gateway send.

### Phase 5: Cleanup And Cutover

1. Add cron-based pruning of expired challenges and rate-limit rows.
2. Deploy to a Convex production deployment.
3. Test first on `*.convex.site`.
4. Attach the production custom domain.
5. Point iOS and gateway at the Convex URL.

## Data Migration

If production state already exists in `relay-state.json`, add a one-off importer script that:

1. reads the existing JSON file
2. inserts rows into `app_attest_keys` and `registrations`
3. preserves ciphertext values without re-encrypting if the format stays unchanged

If production is not live yet, skip migration and start with an empty Convex database.

## Risks

### Runtime compatibility risk

The largest technical risk is Node runtime compatibility for:

- `node-app-attest`
- `node:http2`

That is why Phase 0 exists.

### Action latency

Node actions can cold start. Registration and send latency will likely increase slightly compared to a warm single-process server. This is acceptable for the relay but should be measured.

### Action retry semantics

Convex actions and HTTP actions are not automatically retried. This matches the current service model reasonably well, but client retry behavior remains important.

### Rate limiter scale

The table-backed rate limiter is fine for this relay's expected traffic. It is not the right design for a high-throughput public API.

## Open Questions

- Do we need to migrate existing `relay-state.json`, or is production still empty?
- Should `send` remain synchronous forever, or should it later become a durable queued workflow?
- Do we want to keep exact sliding-window semantics, or is a simpler fixed-window limiter acceptable?
- Do we want to expose the Convex default domain first and add the custom domain only after end-to-end validation?

## Recommended Next Step

Do Phase 0 first. If the App Attest and APNs spikes both succeed in Convex Node actions, proceed with the full rewrite. If either fails, stop and keep the containerized deployment path.

## References

- Convex HTTP actions: https://docs.convex.dev/functions/http-actions
- Convex actions and `"use node"`: https://docs.convex.dev/functions/actions
- Convex internal functions: https://docs.convex.dev/functions/internal-functions
- Convex environment variables: https://docs.convex.dev/production/environment-variables
- Convex custom domains: https://docs.convex.dev/production/hosting/custom
- Convex scheduled functions: https://docs.convex.dev/scheduling/scheduled-functions
- Convex cron jobs: https://docs.convex.dev/scheduling/cron-jobs
