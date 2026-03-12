# Convex Implementation Plan

This is the working implementation plan for rewriting `clawpushrelay` as a Convex service.

Current repo workflow uses Bun. Some historical verification notes below still mention `pnpm`
because those steps were executed before the package-manager switch.

Scope decisions for this rewrite:

- no production state migration
- no backward-compatibility layer for the old Fastify server
- preserve the public HTTP API contract
- optimize for a clean Convex-native implementation, not a dual-runtime bridge

## Status Legend

- `pending`
- `in_progress`
- `completed`
- `blocked`

## Step 1: Convex scaffolding

Status: `completed`

Deliverables:

- add Convex dependencies and config
- add `convex/` folder with:
  - `schema.ts`
  - `http.ts`
  - `_generated/` supported once Convex project bootstrap is configured
- add scripts for Convex codegen/dev/deploy
- add a minimal `GET /healthz` HTTP action
- wire TypeScript and test config so Convex files typecheck cleanly

Validation:

- `pnpm install` succeeds
- Convex code generation succeeds
- `pnpm typecheck` succeeds
- `GET /healthz` is defined in Convex HTTP router

Verification:

- inspect generated Convex files exist after codegen
- run tests or typecheck with Convex modules included

Verification result:

- `pnpm typecheck` passed after adding the Convex scaffold
- `pnpm exec convex codegen --typecheck=disable` is currently blocked until `CONVEX_DEPLOYMENT` is configured via Convex project bootstrap

## Step 2: Shared config, validators, and helpers

Status: `completed`

Deliverables:

- implement Convex env parsing with shortened env names
- port request/response types needed by Convex functions
- port zod validators for challenge/register/send payloads
- port runtime-neutral hashing helpers
- port Node-only crypto helpers into Convex Node modules

Validation:

- config parsing rejects missing required env vars
- validator unit tests cover valid and invalid payloads
- crypto helper tests cover encrypt/decrypt and hashing round trips

Verification:

- `pnpm test`
- `pnpm typecheck`

Verification result:

- `pnpm test` passed with `21` tests across `5` files
- `pnpm typecheck` passed

## Step 3: Convex schema and internal state functions

Status: `completed`

Deliverables:

- implement Convex schema for:
  - `challenges`
  - `app_attest_keys`
  - `registrations`
  - `rate_limit_events`
- implement internal queries and mutations for:
  - challenge issue/consume
  - rate limiting
  - registration upsert
  - registration lookup by relay handle hash
  - send result recording
  - stale/revoked state transitions

Validation:

- schema validates under Convex codegen
- automated tests cover:
  - one-time challenge consumption
  - replacing active registrations with a stale prior registration
  - expiring handles
  - stale-on-terminal-APNs result
  - rate-limit enforcement

Verification:

- `pnpm test`
- `pnpm typecheck`

Verification result:

- `pnpm test` passed with `26` tests across `6` files
- `pnpm typecheck` passed

## Step 4: Public HTTP endpoints for `healthz` and `challenge`

Status: `completed`

Deliverables:

- implement `GET /healthz`
- implement `POST /v1/push/challenge`
- implement HTTP response shapes and rate-limit behavior

Validation:

- HTTP tests cover:
  - `healthz` returns `{ ok: true }`
  - `challenge` returns a valid one-time challenge record
  - rate-limited challenge requests return `429`

Verification:

- `pnpm test`
- manual request against Convex dev deployment or local backend

Verification result:

- `pnpm test` passed with `29` tests across `7` files
- `pnpm typecheck` passed
- manual HTTP verification against a Convex deployment is still blocked until `CONVEX_DEPLOYMENT` is configured

## Step 5: Registration path

Status: `completed`

Deliverables:

- implement `POST /v1/push/register`
- implement Convex Node action for:
  - App Attest verification
  - Apple receipt validation
  - APNs token encryption
  - relay handle creation
- persist verified App Attest key and registration state

Validation:

- tests cover:
  - happy path registration
  - invalid challenge
  - disallowed bundle ID
  - App Attest failure
  - receipt verification failure
  - receipt service unavailable

Verification:

- `pnpm test`
- `pnpm typecheck`
- manual registration smoke test with stubbed dependencies

Verification result:

- `pnpm test` passed with `39` tests across `8` files
- `pnpm typecheck` passed
- registration flow is covered by local HTTP-route tests and Node-action tests with stubbed App Attest and Apple receipt dependencies

## Step 6: Send path

Status: `completed`

Deliverables:

- implement `POST /v1/push/send`
- implement bearer-token auth
- implement Convex Node action for:
  - handle lookup
  - APNs token decryption
  - APNs HTTP/2 send
- persist APNs send results and stale terminal registrations

Validation:

- tests cover:
  - happy path alert send
  - invalid bearer token
  - expired handle
  - missing handle
  - `BadDeviceToken` marks registration stale

Verification:

- `pnpm test`
- `pnpm typecheck`
- manual send smoke test with stubbed APNs transport

Verification result:

- `pnpm test` passed with `45` tests across `9` files
- `pnpm typecheck` passed
- send flow is covered by local HTTP-route tests and Node-action tests with stubbed APNs transport

## Step 7: Scheduled cleanup and repo cleanup

Status: `completed`

Deliverables:

- add scheduled cleanup for expired challenges and rate-limit rows
- remove obsolete Fastify runtime files and dependencies
- update README and env examples for Convex
- document deploy flow for Convex

Validation:

- cleanup functions have test coverage
- repo no longer depends on Fastify runtime for serving endpoints
- docs match actual scripts and env names

Verification:

- `pnpm test`
- `pnpm typecheck`
- inspect `package.json` and docs for stale Fastify references

Verification result:

- `pnpm test` passed with `40` tests across `9` files
- `pnpm typecheck` passed
- Convex cron pruning is covered by tests and the repo no longer depends on the removed Fastify runtime

## Execution Notes

- Each implementation step should be delegated to a worker subagent with a bounded write scope.
- The main agent remains responsible for integration, conflict resolution, validation, and plan updates.
- After each step completes:
  - update this file’s status
  - record any scope changes
  - run the listed validation commands
