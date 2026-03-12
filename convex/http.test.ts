import { generateKeyPairSync, sign as signPayload } from "node:crypto";
import { getFunctionName } from "convex/server";
import { afterEach, describe, expect, it, vi } from "vitest";
import http from "./http.js";
import {
  buildGatewaySignaturePayload,
  deriveGatewayDeviceId,
  publicKeyRawBase64UrlFromPem,
} from "./relay/gatewayAuth.js";
import { hashSha256 } from "./relay/hashes.js";
import type {
  RegisterRequestBody,
  RegisterResponseBody,
  RelaySendResult,
  SendRequestBody,
} from "./relay/types.js";

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

type TestableHttpHandler = {
  _handler: (ctx: unknown, request: Request) => Promise<Response>;
};

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

function lookupHandler(path: string, method: "GET" | "POST") {
  const match = http.lookup(path, method);
  expect(match).not.toBeNull();
  return match![0] as unknown as TestableHttpHandler;
}

function makeRegisterPayload(
  overrides: Partial<RegisterRequestBody> = {},
): RegisterRequestBody {
  const { publicKey } = generateKeyPairSync("ed25519");
  const publicKeyPem = publicKey.export({ format: "pem", type: "spki" }).toString();
  const gatewayPublicKey = publicKeyRawBase64UrlFromPem(publicKeyPem);
  const gatewayDeviceId = deriveGatewayDeviceId(gatewayPublicKey);
  if (!gatewayDeviceId) {
    throw new Error("failed to derive gateway device id");
  }
  return {
    challengeId: "challenge-1",
    installationId: "install-1",
    bundleId: "ai.openclaw.client",
    environment: "production",
    distribution: "official",
    gateway: {
      deviceId: gatewayDeviceId,
      publicKey: gatewayPublicKey,
    },
    appVersion: "2026.3.12",
    apnsToken: "1234567890abcdef1234567890abcdef",
    appAttest: {
      keyId: "key-1",
      assertion: "assertion",
      clientDataHash: "client-data-hash",
      signedPayloadBase64: "eyJmb28iOiJiYXIifQ==",
      attestationObject: "attestation",
    },
    receipt: {
      base64: "receipt",
    },
    ...overrides,
  };
}

function makeSendPayload(overrides: Partial<SendRequestBody> = {}): SendRequestBody {
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

function makeGatewayHeaders(params: {
  body: SendRequestBody;
  gatewayIdentity: ReturnType<typeof makeGatewayIdentity>;
  signedAtMs: number;
}) {
  const rawBody = JSON.stringify(params.body);
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
    headers: {
      authorization: "Bearer send-grant-1",
      "x-openclaw-gateway-device-id": params.gatewayIdentity.deviceId,
      "x-openclaw-gateway-signature": signature,
      "x-openclaw-gateway-signed-at-ms": String(params.signedAtMs),
    },
  };
}

describe("convex HTTP routes", () => {
  afterEach(() => {
    restoreEnv();
    vi.restoreAllMocks();
  });

  it("serves GET /healthz", async () => {
    const handler = lookupHandler("/healthz", "GET");

    const response = await handler._handler({} as never, new Request("https://relay.test/healthz"));

    expect(response.status).toBe(200);
    expect(response.headers.get("content-type")).toBe("application/json");
    expect(await response.json()).toEqual({ ok: true });
  });

  it("serves POST /v1/push/challenge", async () => {
    setRequiredEnv();
    vi.spyOn(Date, "now").mockReturnValue(1_700_000_000_000);

    const handler = lookupHandler("/v1/push/challenge", "POST");
    const runMutation = vi.fn(async (_mutation, args: Record<string, unknown>) => ({
      allowed: true,
      remaining: 29,
      challenge: {
        challengeId: args.challengeId as string,
        challenge: args.challenge as string,
        createdAtMs: args.nowMs as number,
        expiresAtMs: (args.nowMs as number) + (args.ttlMs as number),
      },
    }));

    const response = await handler._handler(
      { runMutation } as never,
      new Request("https://relay.test/v1/push/challenge", {
        method: "POST",
        headers: {
          "x-forwarded-for": "203.0.113.8, 10.0.0.1",
        },
      }),
    );

    const body = (await response.json()) as {
      challengeId: string;
      challenge: string;
      createdAtMs: number;
      expiresAtMs: number;
    };

    expect(response.status).toBe(200);
    expect(response.headers.get("cache-control")).toBe("no-store");
    expect(body.challengeId).toBeTruthy();
    expect(body.challenge).toBeTruthy();
    expect(body.createdAtMs).toBe(1_700_000_000_000);
    expect(body.expiresAtMs).toBe(1_700_000_300_000);

    expect(runMutation).toHaveBeenCalledTimes(1);
    const [mutationRef, args] = runMutation.mock.calls[0]!;
    expect(getFunctionName(mutationRef)).toBe(
      "relay/internal:issueChallengeAndConsumeRateLimitInternal",
    );
    expect(args).toMatchObject({
      nowMs: 1_700_000_000_000,
      ttlMs: 300_000,
      windowMs: 60_000,
      limit: 30,
    });
    expect(args.challengeId).toBe(body.challengeId);
    expect(args.challenge).toBe(body.challenge);
    expect(args.subjectHash).toBe(await hashSha256("203.0.113.8"));
  });

  it("returns 429 from POST /v1/push/challenge when rate limited", async () => {
    setRequiredEnv({
      CHALLENGE_RATE_LIMIT_MAX: "1",
    });

    const handler = lookupHandler("/v1/push/challenge", "POST");
    const runMutation = vi.fn(async () => ({
      allowed: false,
      remaining: 0,
      challenge: null,
    }));

    const response = await handler._handler(
      { runMutation } as never,
      new Request("https://relay.test/v1/push/challenge", {
        method: "POST",
        headers: {
          "x-real-ip": "198.51.100.7",
        },
      }),
    );

    expect(response.status).toBe(429);
    expect(await response.json()).toEqual({
      error: "rate_limited",
      message: "rate limit exceeded",
    });
    expect(runMutation).toHaveBeenCalledTimes(1);
  });

  it("serves POST /v1/push/register", async () => {
    setRequiredEnv();
    vi.spyOn(Date, "now").mockReturnValue(1_700_000_000_000);

    const handler = lookupHandler("/v1/push/register", "POST");
    const payload = makeRegisterPayload();
    const challenge = {
      challengeId: payload.challengeId,
      challenge: "opaque-challenge",
      createdAtMs: 1_700_000_000_000,
      expiresAtMs: 1_700_000_300_000,
    };
    const registered: RegisterResponseBody = {
      relayHandle: "relay-handle-1",
      sendGrant: "send-grant-1",
      expiresAtMs: 1_700_086_400_000,
      tokenSuffix: "90abcdef",
      status: "active",
    };
    const runMutation = vi
      .fn()
      .mockResolvedValueOnce({
        allowed: true,
        remaining: 9,
        challenge,
      });
    const runAction = vi.fn().mockResolvedValue({
      ok: true,
      response: registered,
    });

    const response = await handler._handler(
      { runMutation, runAction } as never,
      new Request("https://relay.test/v1/push/register", {
        method: "POST",
        headers: {
          "content-type": "application/json",
          "x-forwarded-for": "203.0.113.9, 10.0.0.1",
        },
        body: JSON.stringify(payload),
      }),
    );

    expect(response.status).toBe(200);
    expect(response.headers.get("cache-control")).toBe("no-store");
    expect(await response.json()).toEqual(registered);

    expect(runMutation).toHaveBeenCalledTimes(1);
    expect(getFunctionName(runMutation.mock.calls[0]![0])).toBe(
      "relay/internal:consumeChallengeAndRegisterRateLimitInternal",
    );
    expect(runMutation.mock.calls[0]![1]).toMatchObject({
      challengeId: "challenge-1",
      nowMs: 1_700_000_000_000,
      windowMs: 60_000,
      limit: 10,
      subjectHash: await hashSha256("203.0.113.9"),
    });

    expect(runAction).toHaveBeenCalledTimes(1);
    expect(getFunctionName(runAction.mock.calls[0]![0])).toBe(
      "relay/registerNode:verifyAndPersistRegistrationInternal",
    );
    expect(runAction.mock.calls[0]![1]).toEqual({
      challenge: "opaque-challenge",
      request: payload,
    });
  });

  it("returns invalid_challenge from POST /v1/push/register when the challenge is missing", async () => {
    setRequiredEnv();

    const handler = lookupHandler("/v1/push/register", "POST");
    const runMutation = vi
      .fn()
      .mockResolvedValueOnce({
        allowed: true,
        remaining: 9,
        challenge: null,
      });
    const runAction = vi.fn();

    const response = await handler._handler(
      { runMutation, runAction } as never,
      new Request("https://relay.test/v1/push/register", {
        method: "POST",
        headers: {
          "content-type": "application/json",
          "x-real-ip": "198.51.100.20",
        },
        body: JSON.stringify(makeRegisterPayload()),
      }),
    );

    expect(response.status).toBe(401);
    expect(response.headers.get("cache-control")).toBe("no-store");
    expect(await response.json()).toEqual({
      error: "invalid_challenge",
      message: "challenge missing or expired",
    });
    expect(runMutation).toHaveBeenCalledTimes(1);
    expect(runAction).not.toHaveBeenCalled();
  });

  it("rejects bundle IDs outside the allowlist on POST /v1/push/register", async () => {
    setRequiredEnv();

    const handler = lookupHandler("/v1/push/register", "POST");
    const runMutation = vi.fn().mockResolvedValue({
      allowed: true,
      remaining: 9,
    });
    const runAction = vi.fn();

    const response = await handler._handler(
      { runMutation, runAction } as never,
      new Request("https://relay.test/v1/push/register", {
        method: "POST",
        headers: {
          "content-type": "application/json",
        },
        body: JSON.stringify(makeRegisterPayload({ bundleId: "ai.openclaw.other" })),
      }),
    );

    expect(response.status).toBe(403);
    expect(await response.json()).toEqual({
      error: "bundle_not_allowed",
      message: "bundle id is not allowed",
    });
    expect(runMutation).not.toHaveBeenCalled();
    expect(runAction).not.toHaveBeenCalled();
  });

  it("returns unauthorized from POST /v1/push/register on App Attest failure", async () => {
    setRequiredEnv();

    const handler = lookupHandler("/v1/push/register", "POST");
    const runMutation = vi
      .fn()
      .mockResolvedValueOnce({
        allowed: true,
        remaining: 9,
        challenge: {
          challengeId: "challenge-1",
          challenge: "opaque-challenge",
          createdAtMs: 1_000,
          expiresAtMs: 2_000,
        },
      });
    const runAction = vi.fn().mockResolvedValue({
      ok: false,
      error: "unauthorized",
      message: "App Attest key binding mismatch",
    });

    const response = await handler._handler(
      { runMutation, runAction } as never,
      new Request("https://relay.test/v1/push/register", {
        method: "POST",
        headers: {
          "content-type": "application/json",
        },
        body: JSON.stringify(makeRegisterPayload()),
      }),
    );

    expect(response.status).toBe(401);
    expect(response.headers.get("cache-control")).toBe("no-store");
    expect(await response.json()).toEqual({
      error: "unauthorized",
      message: "App Attest key binding mismatch",
    });
  });

  it("returns unauthorized from POST /v1/push/register on receipt verification failure", async () => {
    setRequiredEnv();

    const handler = lookupHandler("/v1/push/register", "POST");
    const runMutation = vi
      .fn()
      .mockResolvedValueOnce({
        allowed: true,
        remaining: 9,
        challenge: {
          challengeId: "challenge-1",
          challenge: "opaque-challenge",
          createdAtMs: 1_000,
          expiresAtMs: 2_000,
        },
      });
    const runAction = vi.fn().mockResolvedValue({
      ok: false,
      error: "unauthorized",
      message: "receipt bundle id mismatch",
    });

    const response = await handler._handler(
      { runMutation, runAction } as never,
      new Request("https://relay.test/v1/push/register", {
        method: "POST",
        headers: {
          "content-type": "application/json",
        },
        body: JSON.stringify(makeRegisterPayload()),
      }),
    );

    expect(response.status).toBe(401);
    expect(response.headers.get("cache-control")).toBe("no-store");
    expect(await response.json()).toEqual({
      error: "unauthorized",
      message: "receipt bundle id mismatch",
    });
  });

  it("returns service unavailable from POST /v1/push/register when receipt verification is unavailable", async () => {
    setRequiredEnv();

    const handler = lookupHandler("/v1/push/register", "POST");
    const runMutation = vi
      .fn()
      .mockResolvedValueOnce({
        allowed: true,
        remaining: 9,
        challenge: {
          challengeId: "challenge-1",
          challenge: "opaque-challenge",
          createdAtMs: 1_000,
          expiresAtMs: 2_000,
        },
      });
    const runAction = vi.fn().mockResolvedValue({
      ok: false,
      error: "service_unavailable",
      message: "receipt verification unavailable",
    });

    const response = await handler._handler(
      { runMutation, runAction } as never,
      new Request("https://relay.test/v1/push/register", {
        method: "POST",
        headers: {
          "content-type": "application/json",
        },
        body: JSON.stringify(makeRegisterPayload()),
      }),
    );

    expect(response.status).toBe(503);
    expect(response.headers.get("cache-control")).toBe("no-store");
    expect(await response.json()).toEqual({
      error: "service_unavailable",
      message: "receipt verification unavailable",
    });
  });

  it("serves POST /v1/push/send", async () => {
    setRequiredEnv();
    vi.spyOn(Date, "now").mockReturnValue(1_700_000_000_000);

    const handler = lookupHandler("/v1/push/send", "POST");
    const payload = makeSendPayload();
    const gatewayIdentity = makeGatewayIdentity();
    const gatewayHeaders = makeGatewayHeaders({
      body: payload,
      gatewayIdentity,
      signedAtMs: 1_700_000_000_000,
    });
    const sendResult: RelaySendResult = {
      ok: true,
      status: 200,
      apnsId: "apns-1",
      environment: "production",
      tokenSuffix: "90abcdef",
    };
    const runMutation = vi.fn().mockResolvedValue({
      allowed: true,
      remaining: 119,
    });
    const runAction = vi.fn().mockResolvedValue(sendResult);

    const response = await handler._handler(
      { runMutation, runAction } as never,
      new Request("https://relay.test/v1/push/send", {
        method: "POST",
        headers: {
          "content-type": "application/json",
          "x-forwarded-for": "203.0.113.10, 10.0.0.1",
          ...gatewayHeaders.headers,
        },
        body: gatewayHeaders.rawBody,
      }),
    );

    expect(response.status).toBe(200);
    expect(await response.json()).toEqual(sendResult);

    expect(runMutation).toHaveBeenCalledTimes(1);
    expect(getFunctionName(runMutation.mock.calls[0]![0])).toBe(
      "relay/internal:consumeSendRateLimitInternal",
    );
    expect(runMutation.mock.calls[0]![1]).toMatchObject({
      nowMs: 1_700_000_000_000,
      windowMs: 60_000,
      limit: 120,
      subjectHash: await hashSha256("203.0.113.10"),
    });

    expect(runAction).toHaveBeenCalledTimes(1);
    expect(getFunctionName(runAction.mock.calls[0]![0])).toBe("relay/sendNode:sendPushInternal");
    expect(runAction.mock.calls[0]![1]).toEqual({
      request: payload,
      sendGrant: "send-grant-1",
      gatewayAuth: {
        deviceId: gatewayIdentity.deviceId,
        signature: gatewayHeaders.headers["x-openclaw-gateway-signature"],
        signedAtMs: 1_700_000_000_000,
      },
      rawBody: gatewayHeaders.rawBody,
    });
  });

  it("returns unauthorized from POST /v1/push/send when the send grant is missing", async () => {
    setRequiredEnv();
    vi.spyOn(Date, "now").mockReturnValue(1_700_000_000_000);

    const handler = lookupHandler("/v1/push/send", "POST");
    const runMutation = vi.fn().mockResolvedValue({
      allowed: true,
      remaining: 119,
    });
    const runAction = vi.fn();

    const response = await handler._handler(
      { runMutation, runAction } as never,
      new Request("https://relay.test/v1/push/send", {
        method: "POST",
        headers: {
          "content-type": "application/json",
          "x-real-ip": "198.51.100.22",
        },
        body: JSON.stringify(makeSendPayload()),
      }),
    );

    expect(response.status).toBe(401);
    expect(await response.json()).toEqual({
      error: "unauthorized",
      message: "missing or invalid relay send grant",
    });
    expect(runMutation).toHaveBeenCalledTimes(1);
    expect(getFunctionName(runMutation.mock.calls[0]![0])).toBe(
      "relay/internal:consumeSendRateLimitInternal",
    );
    expect(runAction).not.toHaveBeenCalled();
  });

  it("returns unauthorized from POST /v1/push/send when the send grant is invalid", async () => {
    setRequiredEnv();
    vi.spyOn(Date, "now").mockReturnValue(1_700_000_000_000);

    const handler = lookupHandler("/v1/push/send", "POST");
    const payload = makeSendPayload();
    const gatewayIdentity = makeGatewayIdentity();
    const gatewayHeaders = makeGatewayHeaders({
      body: payload,
      gatewayIdentity,
      signedAtMs: 1_700_000_000_000,
    });
    const runMutation = vi.fn().mockResolvedValue({
      allowed: true,
      remaining: 119,
    });
    const runAction = vi.fn().mockResolvedValue({
      unauthorized: true,
      message: "missing or invalid relay send grant",
    });

    const response = await handler._handler(
      { runMutation, runAction } as never,
      new Request("https://relay.test/v1/push/send", {
        method: "POST",
        headers: {
          "content-type": "application/json",
          "x-real-ip": "198.51.100.22",
          ...gatewayHeaders.headers,
          authorization: "Bearer wrong-grant",
        },
        body: gatewayHeaders.rawBody,
      }),
    );

    expect(response.status).toBe(401);
    expect(await response.json()).toEqual({
      error: "unauthorized",
      message: "missing or invalid relay send grant",
    });
    expect(runAction).toHaveBeenCalledTimes(1);
    expect(getFunctionName(runAction.mock.calls[0]![0])).toBe("relay/sendNode:sendPushInternal");
  });
});
