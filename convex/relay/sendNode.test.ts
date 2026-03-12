import { generateKeyPairSync, sign as signPayload } from "node:crypto";
import { getFunctionName } from "convex/server";
import { afterEach, describe, expect, it, vi } from "vitest";
import {
  buildGatewaySignaturePayload,
  deriveGatewayDeviceId,
  publicKeyRawBase64UrlFromPem,
} from "./gatewayAuth.js";
import { apnsTokenSuffix, normalizeApnsToken } from "./hashes.js";
import { encryptString, hashSha256Sync, parseEncryptionKey } from "./nodeCrypto.js";
import { sendPush } from "./sendNode.js";
import type {
  RelayRegistrationRecord,
  RelaySendResult,
  SendGatewayAuth,
  SendRequestBody,
} from "./types.js";

const REQUIRED_ENV: Record<string, string> = {
  RELAY_ENC_KEY: Buffer.alloc(32, 7).toString("base64"),
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
  const sendGrant = "send-grant-1";
  const key = parseEncryptionKey(REQUIRED_ENV.RELAY_ENC_KEY);
  const { publicKey } = generateKeyPairSync("ed25519");
  const publicKeyPem = publicKey.export({ format: "pem", type: "spki" }).toString();
  const gatewayPublicKey = publicKeyRawBase64UrlFromPem(publicKeyPem);
  const gatewayDeviceId = deriveGatewayDeviceId(gatewayPublicKey);
  if (!gatewayDeviceId) {
    throw new Error("failed to derive gateway device id");
  }

  return {
    registrationId: "reg-1",
    installationId: "install-1",
    bundleId: "ai.openclaw.client",
    environment: "production",
    distribution: "official",
    gatewayDeviceId,
    gatewayPublicKey,
    apnsTopic: "ai.openclaw.client",
    apnsTokenCiphertext: encryptString(apnsToken, key),
    apnsTokenHash: hashSha256Sync(apnsToken),
    tokenSuffix: apnsTokenSuffix(apnsToken),
    relayHandleHash: hashSha256Sync(relayHandle),
    sendGrantHash: hashSha256Sync(sendGrant),
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

function makeGatewayIdentity() {
  const { publicKey, privateKey } = generateKeyPairSync("ed25519");
  const publicKeyPem = publicKey.export({ format: "pem", type: "spki" }).toString();
  const gatewayPublicKey = publicKeyRawBase64UrlFromPem(publicKeyPem);
  const gatewayDeviceId = deriveGatewayDeviceId(gatewayPublicKey);
  if (!gatewayDeviceId) {
    throw new Error("failed to derive gateway device id");
  }
  return {
    deviceId: gatewayDeviceId,
    publicKey: gatewayPublicKey,
    privateKeyPem: privateKey.export({ format: "pem", type: "pkcs8" }).toString(),
  };
}

function signGatewayAuth(params: {
  request: SendRequestBody;
  gatewayIdentity: ReturnType<typeof makeGatewayIdentity>;
  signedAtMs: number;
}): { rawBody: string; gatewayAuth: SendGatewayAuth } {
  const rawBody = JSON.stringify(params.request);
  const payload = buildGatewaySignaturePayload({
    gatewayDeviceId: params.gatewayIdentity.deviceId,
    signedAtMs: params.signedAtMs,
    bodyText: rawBody,
  });
  const signature = signPayload(
    null,
    Buffer.from(payload, "utf8"),
    params.gatewayIdentity.privateKeyPem,
  )
    .toString("base64")
    .replaceAll("+", "-")
    .replaceAll("/", "_")
    .replace(/=+$/g, "");
  return {
    rawBody,
    gatewayAuth: {
      deviceId: params.gatewayIdentity.deviceId,
      signature,
      signedAtMs: params.signedAtMs,
    },
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
    const gatewayIdentity = makeGatewayIdentity();
    const registration = makeRegistration({
      gatewayDeviceId: gatewayIdentity.deviceId,
      gatewayPublicKey: gatewayIdentity.publicKey,
    });
    const signed = signGatewayAuth({
      request,
      gatewayIdentity,
      signedAtMs: 1_700_000_000_000,
    });
    const runQuery = vi.fn().mockResolvedValue(registration);
    const runMutation = vi
      .fn()
      .mockResolvedValueOnce({ allowed: true, remaining: 119 })
      .mockResolvedValue(undefined);
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
      { request, sendGrant: "send-grant-1", gatewayAuth: signed.gatewayAuth, rawBody: signed.rawBody },
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

    expect(runMutation).toHaveBeenCalledTimes(2);
    expect(getFunctionName(runMutation.mock.calls[0]![0])).toBe(
      "relay/internal:consumeSendRateLimitInternal",
    );
    expect(runMutation.mock.calls[0]![1]).toEqual({
      subjectHash: hashSha256Sync(`${registration.gatewayDeviceId}:${registration.relayHandleHash}`),
      nowMs: 1_700_000_000_000,
      windowMs: 60_000,
      limit: 120,
    });
    expect(getFunctionName(runMutation.mock.calls[1]![0])).toBe(
      "relay/internal:recordSendResultInternal",
    );
    expect(runMutation.mock.calls[1]![1]).toEqual({
      relayHandleHash: registration.relayHandleHash,
      result: sendResult,
      nowMs: 1_700_000_000_000,
    });
  });

  it("returns Unregistered for a missing relay handle", async () => {
    setRequiredEnv();
    const gatewayIdentity = makeGatewayIdentity();
    const signed = signGatewayAuth({
      request: makeSendRequest(),
      gatewayIdentity,
      signedAtMs: 1_700_000_000_000,
    });
    const runQuery = vi.fn().mockResolvedValue(null);
    const runMutation = vi.fn();

    const result = await sendPush(
      { runQuery, runMutation },
      {
        request: makeSendRequest(),
        sendGrant: "send-grant-1",
        gatewayAuth: signed.gatewayAuth,
        rawBody: signed.rawBody,
      },
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
    const gatewayIdentity = makeGatewayIdentity();
    const registration = makeRegistration({
      gatewayDeviceId: gatewayIdentity.deviceId,
      gatewayPublicKey: gatewayIdentity.publicKey,
      relayHandleExpiresAtMs: 1_699_999_999_000,
    });
    const request = makeSendRequest();
    const signed = signGatewayAuth({
      request,
      gatewayIdentity,
      signedAtMs: 1_700_000_000_000,
    });
    const runQuery = vi.fn().mockResolvedValue(registration);
    const runMutation = vi
      .fn()
      .mockResolvedValueOnce({ allowed: true, remaining: 119 })
      .mockResolvedValue(undefined);
    const sendSpy = vi.fn();

    const result = await sendPush(
      { runQuery, runMutation },
      { request, sendGrant: "send-grant-1", gatewayAuth: signed.gatewayAuth, rawBody: signed.rawBody },
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
    expect(runMutation).toHaveBeenCalledTimes(2);
    expect(getFunctionName(runMutation.mock.calls[0]![0])).toBe(
      "relay/internal:consumeSendRateLimitInternal",
    );
    expect(getFunctionName(runMutation.mock.calls[1]![0])).toBe(
      "relay/internal:expireRegistrationIfNeededInternal",
    );
    expect(runMutation.mock.calls[1]![1]).toEqual({
      relayHandleHash: registration.relayHandleHash,
      nowMs: 1_700_000_000_000,
    });
  });

  it("records terminal APNs results so BadDeviceToken can stale the registration", async () => {
    setRequiredEnv();
    const request = makeSendRequest();
    const gatewayIdentity = makeGatewayIdentity();
    const registration = makeRegistration({
      gatewayDeviceId: gatewayIdentity.deviceId,
      gatewayPublicKey: gatewayIdentity.publicKey,
    });
    const signed = signGatewayAuth({
      request,
      gatewayIdentity,
      signedAtMs: 1_700_000_000_000,
    });
    const runQuery = vi.fn().mockResolvedValue(registration);
    const runMutation = vi
      .fn()
      .mockResolvedValueOnce({ allowed: true, remaining: 119 })
      .mockResolvedValue(undefined);
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
      { request, sendGrant: "send-grant-1", gatewayAuth: signed.gatewayAuth, rawBody: signed.rawBody },
      {
        now: () => 1_700_000_000_000,
        makeApnsSender: () => ({
          send: sendSpy,
        }),
      },
    );

    expect(result).toEqual(sendResult);
    expect(runMutation).toHaveBeenCalledTimes(2);
    expect(getFunctionName(runMutation.mock.calls[1]![0])).toBe(
      "relay/internal:recordSendResultInternal",
    );
    expect(runMutation.mock.calls[1]![1]).toEqual({
      relayHandleHash: registration.relayHandleHash,
      result: sendResult,
      nowMs: 1_700_000_000_000,
    });
  });

  it("rejects sends with the wrong grant", async () => {
    setRequiredEnv();
    const gatewayIdentity = makeGatewayIdentity();
    const registration = makeRegistration({
      gatewayDeviceId: gatewayIdentity.deviceId,
      gatewayPublicKey: gatewayIdentity.publicKey,
    });
    const request = makeSendRequest();
    const signed = signGatewayAuth({
      request,
      gatewayIdentity,
      signedAtMs: 1_700_000_000_000,
    });
    const runQuery = vi.fn().mockResolvedValue(registration);
    const runMutation = vi.fn();

    const result = await sendPush(
      { runQuery, runMutation },
      { request, sendGrant: "wrong-grant", gatewayAuth: signed.gatewayAuth, rawBody: signed.rawBody },
      {
        now: () => 1_700_000_000_000,
      },
    );

    expect(result).toEqual({
      unauthorized: true,
      message: "missing or invalid relay send grant",
    });
    expect(runMutation).not.toHaveBeenCalled();
  });

  it("rejects sends from a different gateway identity", async () => {
    setRequiredEnv();
    const ownerGateway = makeGatewayIdentity();
    const attackerGateway = makeGatewayIdentity();
    const request = makeSendRequest();
    const registration = makeRegistration({
      gatewayDeviceId: ownerGateway.deviceId,
      gatewayPublicKey: ownerGateway.publicKey,
    });
    const signed = signGatewayAuth({
      request,
      gatewayIdentity: attackerGateway,
      signedAtMs: 1_700_000_000_000,
    });
    const runQuery = vi.fn().mockResolvedValue(registration);
    const runMutation = vi.fn();

    const result = await sendPush(
      { runQuery, runMutation },
      { request, sendGrant: "send-grant-1", gatewayAuth: signed.gatewayAuth, rawBody: signed.rawBody },
      {
        now: () => 1_700_000_000_000,
      },
    );

    expect(result).toEqual({
      unauthorized: true,
      message: "gateway device id mismatch",
    });
    expect(runMutation).not.toHaveBeenCalled();
  });

  it("rate limits authenticated send bursts per gateway/device binding", async () => {
    setRequiredEnv();
    const gatewayIdentity = makeGatewayIdentity();
    const request = makeSendRequest();
    const registration = makeRegistration({
      gatewayDeviceId: gatewayIdentity.deviceId,
      gatewayPublicKey: gatewayIdentity.publicKey,
    });
    const signed = signGatewayAuth({
      request,
      gatewayIdentity,
      signedAtMs: 1_700_000_000_000,
    });
    const runQuery = vi.fn().mockResolvedValue(registration);
    const runMutation = vi
      .fn()
      .mockResolvedValueOnce({ allowed: false, remaining: 0 })
      .mockResolvedValue(undefined);
    const sendSpy = vi.fn();

    const result = await sendPush(
      { runQuery, runMutation },
      { request, sendGrant: "send-grant-1", gatewayAuth: signed.gatewayAuth, rawBody: signed.rawBody },
      {
        now: () => 1_700_000_000_000,
        makeApnsSender: () => ({
          send: sendSpy,
        }),
      },
    );

    expect(result).toEqual({
      ok: false,
      status: 429,
      reason: "rate limit exceeded",
      environment: "production",
      tokenSuffix: registration.tokenSuffix,
    });
    expect(sendSpy).not.toHaveBeenCalled();
  });
});
