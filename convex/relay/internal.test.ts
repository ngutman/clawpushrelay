import { describe, expect, it } from "vitest";
import type { ChallengeRecord, RelayRegistrationRecord } from "./types.js";
import {
  applySendResultToRegistration,
  buildChallengeRecord,
  buildRegistrationPatchesForInsert,
  consumeChallengeRecord,
  consumeRateLimit,
  expireRegistrationIfNeeded,
} from "./internal.js";

function makeRegistration(
  overrides: Partial<RelayRegistrationRecord> = {},
): RelayRegistrationRecord {
  return {
    registrationId: "reg-1",
    installationId: "install-1",
    bundleId: "ai.openclaw.client",
    environment: "production",
    distribution: "official",
    apnsTopic: "ai.openclaw.client",
    apnsTokenCiphertext: "ciphertext",
    apnsTokenHash: "token-hash",
    tokenSuffix: "90abcdef",
    relayHandleHash: "handle-hash",
    relayHandleExpiresAtMs: 10_000,
    appAttestKeyId: "key-1",
    proofType: "receipt",
    receiptEnvironment: "Production",
    appVersion: "2026.3.12",
    status: "active",
    createdAtMs: 1_000,
    updatedAtMs: 1_000,
    lastRegisteredAtMs: 1_000,
    ...overrides,
  };
}

describe("challenge state helpers", () => {
  it("builds and consumes a challenge once", () => {
    const record = buildChallengeRecord({
      challengeId: "challenge-1",
      challenge: "opaque-challenge",
      nowMs: 1_000,
      ttlMs: 5_000,
    });

    expect(record).toEqual<ChallengeRecord>({
      challengeId: "challenge-1",
      challenge: "opaque-challenge",
      createdAtMs: 1_000,
      expiresAtMs: 6_000,
    });

    const firstConsume = consumeChallengeRecord(record, 1_500);
    expect(firstConsume.consumed).toBe(true);
    expect(firstConsume.record?.consumedAtMs).toBe(1_500);

    const secondConsume = consumeChallengeRecord(firstConsume.record, 1_600);
    expect(secondConsume.consumed).toBe(false);
  });
});

describe("rate limit state helpers", () => {
  it("denies when the sliding window is full", () => {
    const first = consumeRateLimit([], {
      scope: "register",
      subjectHash: "ip-hash",
      nowMs: 1_000,
      windowMs: 60_000,
      limit: 2,
    });
    expect(first.allowed).toBe(true);
    const second = consumeRateLimit([first.nextEvent!], {
      scope: "register",
      subjectHash: "ip-hash",
      nowMs: 2_000,
      windowMs: 60_000,
      limit: 2,
    });
    expect(second.allowed).toBe(true);

    const third = consumeRateLimit([first.nextEvent!, second.nextEvent!], {
      scope: "register",
      subjectHash: "ip-hash",
      nowMs: 3_000,
      windowMs: 60_000,
      limit: 2,
    });
    expect(third.allowed).toBe(false);
    expect(third.remaining).toBe(0);
  });
});

describe("registration state helpers", () => {
  it("marks prior active registrations stale on replacement", () => {
    const existing = makeRegistration();
    const next = makeRegistration({
      registrationId: "reg-2",
      relayHandleHash: "handle-hash-2",
      updatedAtMs: 2_000,
      createdAtMs: 2_000,
      lastRegisteredAtMs: 2_000,
    });

    const result = buildRegistrationPatchesForInsert([existing], next);
    expect(result.stalePatches).toEqual([
      {
        relayHandleHash: "handle-hash",
        patch: {
          status: "stale",
          updatedAtMs: 2_000,
        },
      },
    ]);
    expect(result.nextRecord).toEqual(next);
  });

  it("marks expired handles stale", () => {
    const current = makeRegistration({
      relayHandleExpiresAtMs: 2_000,
      updatedAtMs: 1_500,
    });

    const result = expireRegistrationIfNeeded(current, 3_000);
    expect(result.expired).toBe(true);
    expect(result.record).toMatchObject({
      status: "stale",
      updatedAtMs: 3_000,
      lastApnsReason: "expired",
    });
  });

  it("marks terminal APNs errors stale", () => {
    const current = makeRegistration();

    const result = applySendResultToRegistration(current, {
      status: 400,
      reason: "BadDeviceToken",
      nowMs: 4_000,
    });

    expect(result).toMatchObject({
      status: "stale",
      lastSentAtMs: 4_000,
      lastApnsStatus: 400,
      lastApnsReason: "BadDeviceToken",
      updatedAtMs: 4_000,
    });
  });
});
