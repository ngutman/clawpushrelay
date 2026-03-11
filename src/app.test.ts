import fs from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import Fastify from "fastify";
import { afterEach, describe, expect, it } from "vitest";
import { ChallengeStore } from "./challenges.js";
import { SlidingWindowRateLimiter } from "./rate-limit.js";
import {
  ReceiptVerificationError,
  ReceiptVerificationServiceError,
} from "./receipt.js";
import { registerRelayRoutes } from "./routes.js";
import { RelayStateStore } from "./state-store.js";
import { parseEncryptionKey } from "./crypto.js";
import type { RelayConfig } from "./config.js";
import type { RegisterRequestBody } from "./types.js";

const tempDirs: string[] = [];

async function makeTempDir(): Promise<string> {
  const dir = await fs.mkdtemp(path.join(os.tmpdir(), "clawpushrelay-test-"));
  tempDirs.push(dir);
  return dir;
}

afterEach(async () => {
  while (tempDirs.length > 0) {
    const dir = tempDirs.pop();
    if (dir) {
      await fs.rm(dir, { recursive: true, force: true });
    }
  }
});

function makeConfig(stateDir: string): RelayConfig {
  return {
    host: "127.0.0.1",
    port: 8787,
    trustProxy: false,
    stateDir,
    encryptionKey: Buffer.alloc(32, 7).toString("base64"),
    gatewayBearerToken: "relay-token",
    allowedBundleIds: ["ai.openclaw.client"],
    appleTeamId: "TEAM123",
    appAttestAllowDevelopment: false,
    handleTtlMs: 60_000,
    challengeTtlMs: 60_000,
    rateLimitWindowMs: 60_000,
    challengeRateLimitMax: 100,
    registerRateLimitMax: 100,
    sendRateLimitMax: 100,
    apnsTeamId: "TEAM123",
    apnsKeyId: "KEY123",
    apnsPrivateKey: "-----BEGIN PRIVATE KEY-----\nabc\n-----END PRIVATE KEY-----",
    appleReceiptSharedSecret: undefined,
  };
}

async function buildTestServer(overrides?: {
  config?: Partial<RelayConfig>;
  receiptVerifier?: {
    verifyReceipt: (params: { receiptBase64: string; bundleId: string }) => Promise<{
      environment: string;
      bundleId: string;
      validatedAtMs: number;
    }>;
  };
}) {
  const stateDir = await makeTempDir();
  const config = {
    ...makeConfig(stateDir),
    ...(overrides?.config ?? {}),
  };
  const stateStore = new RelayStateStore(stateDir, parseEncryptionKey(config.encryptionKey));
  await stateStore.ensureReady();
  const app = Fastify();
  const challengeStore = new ChallengeStore(config.challengeTtlMs, () => 1_000_000);
  const rateLimiter = new SlidingWindowRateLimiter(config.rateLimitWindowMs, () => 1_000_000);

  await app.register(
    registerRelayRoutes({
      config,
      stateStore,
      challengeStore,
      rateLimiter,
      appAttestVerifier: {
        verifyRegistration: async ({
          request,
        }: {
          request: RegisterRequestBody;
        }) => ({
          keyId: request.appAttest.keyId,
          publicKey: "public-key",
          signCount: 1,
          attestedAtMs: 1_000_000,
        }),
      } as never,
      receiptVerifier:
        (overrides?.receiptVerifier as never) ??
        ({
          verifyReceipt: async () => ({
            environment: "Production",
            bundleId: "ai.openclaw.client",
            validatedAtMs: 1_000_000,
          }),
        } as never),
      apnsSender: {
        send: async () => ({
          ok: true,
          status: 200,
          apnsId: "apns-id-1",
          environment: "production",
          tokenSuffix: "90abcdef",
        }),
      } as never,
    }),
  );

  return { app, stateStore };
}

describe("relay register and send routes", () => {
  it("issues a challenge, registers a handle, and sends an alert push", async () => {
    const { app, stateStore } = await buildTestServer();

    const challengeResponse = await app.inject({
      method: "POST",
      url: "/v1/push/challenge",
    });
    expect(challengeResponse.statusCode).toBe(200);
    const challenge = challengeResponse.json() as { challengeId: string };

    const registerResponse = await app.inject({
      method: "POST",
      url: "/v1/push/register",
      payload: {
        challengeId: challenge.challengeId,
        installationId: "install-1",
        bundleId: "ai.openclaw.client",
        environment: "production",
        distribution: "official",
        appVersion: "2026.3.11",
        apnsToken: "1234567890abcdef1234567890abcdef",
        appAttest: {
          keyId: "key-1",
          assertion: "assertion",
          clientDataHash: "ignored-by-stub",
          signedPayloadBase64: "e30=",
          attestationObject: "attestation",
        },
        receipt: {
          base64: "receipt",
        },
      },
    });
    expect(registerResponse.statusCode).toBe(200);
    const registered = registerResponse.json() as {
      relayHandle: string;
      expiresAtMs: number;
      tokenSuffix: string;
      status: string;
    };
    expect(registered.relayHandle).toBeTruthy();
    expect(registered.status).toBe("active");

    const sendResponse = await app.inject({
      method: "POST",
      url: "/v1/push/send",
      headers: {
        authorization: "Bearer relay-token",
      },
      payload: {
        relayHandle: registered.relayHandle,
        pushType: "alert",
        priority: 10,
        payload: {
          aps: {
            alert: {
              title: "Wake",
              body: "Ping",
            },
            sound: "default",
          },
          openclaw: {
            kind: "push.test",
          },
        },
      },
    });
    expect(sendResponse.statusCode).toBe(200);
    expect(sendResponse.json()).toMatchObject({
      ok: true,
      status: 200,
    });

    const stored = await stateStore.findRegistrationByHandle(registered.relayHandle);
    expect(stored?.status).toBe("active");
    expect(stored?.lastApnsStatus).toBe(200);
  });

  it("marks a registration stale when APNs reports BadDeviceToken", async () => {
    const stateDir = await makeTempDir();
    const config = makeConfig(stateDir);
    const stateStore = new RelayStateStore(stateDir, parseEncryptionKey(config.encryptionKey));
    await stateStore.ensureReady();
    const app = Fastify();
    const challengeStore = new ChallengeStore(config.challengeTtlMs, () => 2_000_000);
    const rateLimiter = new SlidingWindowRateLimiter(config.rateLimitWindowMs, () => 2_000_000);

    await app.register(
      registerRelayRoutes({
        config,
        stateStore,
        challengeStore,
        rateLimiter,
        appAttestVerifier: {
          verifyRegistration: async ({
            request,
          }: {
            request: RegisterRequestBody;
          }) => ({
            keyId: request.appAttest.keyId,
            publicKey: "public-key",
            signCount: 1,
            attestedAtMs: 2_000_000,
          }),
        } as never,
        receiptVerifier: {
          verifyReceipt: async () => ({
            environment: "Production",
            bundleId: "ai.openclaw.client",
            validatedAtMs: 2_000_000,
          }),
        } as never,
        apnsSender: {
          send: async () => ({
            ok: false,
            status: 400,
            reason: "BadDeviceToken",
            environment: "production",
            tokenSuffix: "90abcdef",
          }),
        } as never,
      }),
    );

    const challengeResponse = await app.inject({
      method: "POST",
      url: "/v1/push/challenge",
    });
    const challenge = challengeResponse.json() as { challengeId: string };
    const registerResponse = await app.inject({
      method: "POST",
      url: "/v1/push/register",
      payload: {
        challengeId: challenge.challengeId,
        installationId: "install-2",
        bundleId: "ai.openclaw.client",
        environment: "production",
        distribution: "official",
        appVersion: "2026.3.11",
        apnsToken: "abcdefabcdefabcdefabcdefabcdefab",
        appAttest: {
          keyId: "key-2",
          assertion: "assertion",
          clientDataHash: "ignored-by-stub",
          signedPayloadBase64: "e30=",
          attestationObject: "attestation",
        },
        receipt: {
          base64: "receipt",
        },
      },
    });
    const registered = registerResponse.json() as { relayHandle: string };

    const sendResponse = await app.inject({
      method: "POST",
      url: "/v1/push/send",
      headers: {
        authorization: "Bearer relay-token",
      },
      payload: {
        relayHandle: registered.relayHandle,
        pushType: "background",
        priority: 5,
        payload: {
          aps: {
            "content-available": 1,
          },
          openclaw: {
            kind: "node.wake",
          },
        },
      },
    });
    expect(sendResponse.statusCode).toBe(400);

    const stored = await stateStore.findRegistrationByHandle(registered.relayHandle);
    expect(stored?.status).toBe("stale");
    expect(stored?.lastApnsReason).toBe("BadDeviceToken");
  });

  it("rejects missing or expired challenges", async () => {
    const { app } = await buildTestServer();

    const response = await app.inject({
      method: "POST",
      url: "/v1/push/register",
      payload: {
        challengeId: "missing",
        installationId: "install-1",
        bundleId: "ai.openclaw.client",
        environment: "production",
        distribution: "official",
        appVersion: "2026.3.11",
        apnsToken: "1234567890abcdef1234567890abcdef",
        appAttest: {
          keyId: "key-1",
          assertion: "assertion",
          clientDataHash: "ignored-by-stub",
          signedPayloadBase64: "e30=",
          attestationObject: "attestation",
        },
        receipt: {
          base64: "receipt",
        },
      },
    });

    expect(response.statusCode).toBe(401);
    expect(response.json()).toMatchObject({
      error: "invalid_challenge",
    });
  });

  it("rejects bundle IDs outside the allowlist", async () => {
    const { app } = await buildTestServer();
    const challenge = (await app.inject({ method: "POST", url: "/v1/push/challenge" })).json() as {
      challengeId: string;
    };

    const response = await app.inject({
      method: "POST",
      url: "/v1/push/register",
      payload: {
        challengeId: challenge.challengeId,
        installationId: "install-1",
        bundleId: "ai.openclaw.other",
        environment: "production",
        distribution: "official",
        appVersion: "2026.3.11",
        apnsToken: "1234567890abcdef1234567890abcdef",
        appAttest: {
          keyId: "key-1",
          assertion: "assertion",
          clientDataHash: "ignored-by-stub",
          signedPayloadBase64: "e30=",
          attestationObject: "attestation",
        },
        receipt: {
          base64: "receipt",
        },
      },
    });

    expect(response.statusCode).toBe(403);
    expect(response.json()).toMatchObject({
      error: "bundle_not_allowed",
    });
  });

  it("returns unauthorized for invalid receipts", async () => {
    const { app } = await buildTestServer({
      receiptVerifier: {
        verifyReceipt: async () => {
          throw new ReceiptVerificationError("receipt bundle id mismatch");
        },
      },
    });
    const challenge = (await app.inject({ method: "POST", url: "/v1/push/challenge" })).json() as {
      challengeId: string;
    };

    const response = await app.inject({
      method: "POST",
      url: "/v1/push/register",
      payload: {
        challengeId: challenge.challengeId,
        installationId: "install-1",
        bundleId: "ai.openclaw.client",
        environment: "production",
        distribution: "official",
        appVersion: "2026.3.11",
        apnsToken: "1234567890abcdef1234567890abcdef",
        appAttest: {
          keyId: "key-1",
          assertion: "assertion",
          clientDataHash: "ignored-by-stub",
          signedPayloadBase64: "e30=",
          attestationObject: "attestation",
        },
        receipt: {
          base64: "receipt",
        },
      },
    });

    expect(response.statusCode).toBe(401);
    expect(response.json()).toMatchObject({
      error: "unauthorized",
      message: "receipt bundle id mismatch",
    });
  });

  it("returns service unavailable when Apple receipt verification is unavailable", async () => {
    const { app } = await buildTestServer({
      receiptVerifier: {
        verifyReceipt: async () => {
          throw new ReceiptVerificationServiceError("Apple receipt validation unavailable");
        },
      },
    });
    const challenge = (await app.inject({ method: "POST", url: "/v1/push/challenge" })).json() as {
      challengeId: string;
    };

    const response = await app.inject({
      method: "POST",
      url: "/v1/push/register",
      payload: {
        challengeId: challenge.challengeId,
        installationId: "install-1",
        bundleId: "ai.openclaw.client",
        environment: "production",
        distribution: "official",
        appVersion: "2026.3.11",
        apnsToken: "1234567890abcdef1234567890abcdef",
        appAttest: {
          keyId: "key-1",
          assertion: "assertion",
          clientDataHash: "ignored-by-stub",
          signedPayloadBase64: "e30=",
          attestationObject: "attestation",
        },
        receipt: {
          base64: "receipt",
        },
      },
    });

    expect(response.statusCode).toBe(503);
    expect(response.json()).toMatchObject({
      error: "service_unavailable",
      message: "receipt verification unavailable",
    });
  });

  it("rejects send requests without the gateway bearer token", async () => {
    const { app } = await buildTestServer();

    const response = await app.inject({
      method: "POST",
      url: "/v1/push/send",
      payload: {
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
      },
    });

    expect(response.statusCode).toBe(401);
    expect(response.json()).toMatchObject({
      error: "unauthorized",
    });
  });
});
