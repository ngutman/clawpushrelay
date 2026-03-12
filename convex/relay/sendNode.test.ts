import { getFunctionName } from "convex/server";
import { afterEach, describe, expect, it, vi } from "vitest";
import { apnsTokenSuffix, normalizeApnsToken } from "./hashes.js";
import { encryptString, hashSha256Sync, parseEncryptionKey } from "./nodeCrypto.js";
import { sendPush } from "./sendNode.js";
import type { RelayRegistrationRecord, RelaySendResult, SendRequestBody } from "./types.js";

const REQUIRED_ENV: Record<string, string> = {
  RELAY_ENC_KEY: Buffer.alloc(32, 7).toString("base64"),
  RELAY_GATEWAY_TOKEN: "relay-token",
  RELAY_ALLOWED_BUNDLE_IDS: "ai.openclaw.client",
  APPLE_TEAM_ID: "TEAM123",
  APNS_TEAM_ID: "TEAM123",
  APNS_KEY_ID: "KEY123",
  APNS_P8: "-----BEGIN PRIVATE KEY-----\\nabc\\n-----END PRIVATE KEY-----",
};

const ORIGINAL_ENV = new Map<string, string | undefined>(
  Object.keys(REQUIRED_ENV).map((key) => [key, process.env[key]]),
);

function setRequiredEnv(overrides: Record<string, string> = {}): void {
  for (const [key, value] of Object.entries(REQUIRED_ENV)) {
    process.env[key] = value;
  }
  for (const [key, value] of Object.entries(overrides)) {
    process.env[key] = value;
  }
}

function restoreEnv(): void {
  for (const [key, value] of ORIGINAL_ENV) {
    if (value === undefined) {
      delete process.env[key];
      continue;
    }
    process.env[key] = value;
  }
}

function makeSendRequest(overrides: Partial<SendRequestBody> = {}): SendRequestBody {
  return {
    relayHandle: "relay-handle-1",
    pushType: "alert",
    priority: 10,
    payload: {
      aps: {
        alert: {
          title: "Wake",
          body: "Ping",
        },
      },
    },
    ...overrides,
  };
}

function makeRegistration(
  overrides: Partial<RelayRegistrationRecord> = {},
): RelayRegistrationRecord {
  const relayHandle = "relay-handle-1";
  const apnsToken = normalizeApnsToken("1234567890ABCDEF1234567890ABCDEF");
  const key = parseEncryptionKey(REQUIRED_ENV.RELAY_ENC_KEY);

  return {
    registrationId: "reg-1",
    installationId: "install-1",
    bundleId: "ai.openclaw.client",
    environment: "production",
    distribution: "official",
    apnsTopic: "ai.openclaw.client",
    apnsTokenCiphertext: encryptString(apnsToken, key),
    apnsTokenHash: hashSha256Sync(apnsToken),
    tokenSuffix: apnsTokenSuffix(apnsToken),
    relayHandleHash: hashSha256Sync(relayHandle),
    relayHandleExpiresAtMs: 1_700_086_400_000,
    appAttestKeyId: "key-1",
    proofType: "receipt",
    receiptEnvironment: "Production",
    appVersion: "2026.3.12",
    status: "active",
    createdAtMs: 1_700_000_000_000,
    updatedAtMs: 1_700_000_000_000,
    lastRegisteredAtMs: 1_700_000_000_000,
    ...overrides,
  };
}

describe("sendPush", () => {
  afterEach(() => {
    restoreEnv();
    vi.restoreAllMocks();
  });

  it("sends a push and records the APNs result", async () => {
    setRequiredEnv();
    const request = makeSendRequest();
    const registration = makeRegistration();
    const runQuery = vi.fn().mockResolvedValue(registration);
    const runMutation = vi.fn().mockResolvedValue(undefined);
    const sendResult: RelaySendResult = {
      ok: true,
      status: 200,
      apnsId: "apns-1",
      environment: "production",
      tokenSuffix: registration.tokenSuffix,
    };
    const sendSpy = vi.fn().mockResolvedValue(sendResult);

    const result = await sendPush(
      { runQuery, runMutation },
      { request },
      {
        now: () => 1_700_000_000_000,
        makeApnsSender: () => ({
          send: sendSpy,
        }),
      },
    );

    expect(result).toEqual(sendResult);
    expect(runQuery).toHaveBeenCalledTimes(1);
    expect(getFunctionName(runQuery.mock.calls[0]![0])).toBe(
      "relay/internal:getRegistrationByRelayHandleHashInternal",
    );
    expect(runQuery.mock.calls[0]![1]).toEqual({
      relayHandleHash: registration.relayHandleHash,
    });

    expect(sendSpy).toHaveBeenCalledTimes(1);
    expect(sendSpy.mock.calls[0]![0]).toMatchObject({
      token: normalizeApnsToken("1234567890ABCDEF1234567890ABCDEF"),
      topic: registration.apnsTopic,
      payload: request.payload,
      pushType: request.pushType,
      priority: request.priority,
    });

    expect(runMutation).toHaveBeenCalledTimes(1);
    expect(getFunctionName(runMutation.mock.calls[0]![0])).toBe(
      "relay/internal:recordSendResultInternal",
    );
    expect(runMutation.mock.calls[0]![1]).toEqual({
      relayHandleHash: registration.relayHandleHash,
      result: sendResult,
      nowMs: 1_700_000_000_000,
    });
  });

  it("returns Unregistered for a missing relay handle", async () => {
    setRequiredEnv();
    const runQuery = vi.fn().mockResolvedValue(null);
    const runMutation = vi.fn();

    const result = await sendPush(
      { runQuery, runMutation },
      { request: makeSendRequest() },
      {
        now: () => 1_700_000_000_000,
      },
    );

    expect(result).toEqual({
      ok: false,
      status: 410,
      reason: "Unregistered",
      environment: "production",
      tokenSuffix: "unknown",
    });
    expect(runMutation).not.toHaveBeenCalled();
  });

  it("expires an active handle that is past its TTL", async () => {
    setRequiredEnv();
    const registration = makeRegistration({
      relayHandleExpiresAtMs: 1_699_999_999_000,
    });
    const runQuery = vi.fn().mockResolvedValue(registration);
    const runMutation = vi.fn().mockResolvedValue(undefined);
    const sendSpy = vi.fn();

    const result = await sendPush(
      { runQuery, runMutation },
      { request: makeSendRequest() },
      {
        now: () => 1_700_000_000_000,
        makeApnsSender: () => ({
          send: sendSpy,
        }),
      },
    );

    expect(result).toEqual({
      ok: false,
      status: 410,
      reason: "Unregistered",
      environment: registration.environment,
      tokenSuffix: registration.tokenSuffix,
    });
    expect(sendSpy).not.toHaveBeenCalled();
    expect(runMutation).toHaveBeenCalledTimes(1);
    expect(getFunctionName(runMutation.mock.calls[0]![0])).toBe(
      "relay/internal:expireRegistrationIfNeededInternal",
    );
    expect(runMutation.mock.calls[0]![1]).toEqual({
      relayHandleHash: registration.relayHandleHash,
      nowMs: 1_700_000_000_000,
    });
  });

  it("records terminal APNs results so BadDeviceToken can stale the registration", async () => {
    setRequiredEnv();
    const request = makeSendRequest();
    const registration = makeRegistration();
    const runQuery = vi.fn().mockResolvedValue(registration);
    const runMutation = vi.fn().mockResolvedValue(undefined);
    const sendResult: RelaySendResult = {
      ok: false,
      status: 400,
      reason: "BadDeviceToken",
      environment: "production",
      tokenSuffix: registration.tokenSuffix,
    };
    const sendSpy = vi.fn().mockResolvedValue(sendResult);

    const result = await sendPush(
      { runQuery, runMutation },
      { request },
      {
        now: () => 1_700_000_000_000,
        makeApnsSender: () => ({
          send: sendSpy,
        }),
      },
    );

    expect(result).toEqual(sendResult);
    expect(runMutation).toHaveBeenCalledTimes(1);
    expect(getFunctionName(runMutation.mock.calls[0]![0])).toBe(
      "relay/internal:recordSendResultInternal",
    );
    expect(runMutation.mock.calls[0]![1]).toEqual({
      relayHandleHash: registration.relayHandleHash,
      result: sendResult,
      nowMs: 1_700_000_000_000,
    });
  });
});
