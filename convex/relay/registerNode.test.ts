import { getFunctionName } from "convex/server";
import { afterEach, describe, expect, it, vi } from "vitest";

const verifyAssertionMock = vi.fn();
const verifyAttestationMock = vi.fn();

vi.mock("node-app-attest", () => ({
  verifyAssertion: verifyAssertionMock,
  verifyAttestation: verifyAttestationMock,
}));

import { encodeSha256Base64Url, normalizeApnsToken } from "./hashes.js";
import { deriveGatewayDeviceId, publicKeyRawBase64UrlFromPem } from "./gatewayAuth.js";
import { decryptString, hashSha256Sync, parseEncryptionKey } from "./nodeCrypto.js";
import { verifyAndPersistRegistrationInternal } from "./registerNode.js";
import type { RegisterRequestBody } from "./types.js";
import { generateKeyPairSync } from "node:crypto";

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
const ORIGINAL_FETCH = globalThis.fetch;

type TestableInternalAction = {
  _handler: (
    ctx: {
      runQuery: ReturnType<typeof vi.fn>;
      runMutation: ReturnType<typeof vi.fn>;
    },
    args: {
      challenge: string;
      request: RegisterRequestBody;
    },
  ) => Promise<unknown>;
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

async function makeRegisterRequest(): Promise<RegisterRequestBody> {
  const { publicKey } = generateKeyPairSync("ed25519");
  const publicKeyPem = publicKey.export({ format: "pem", type: "spki" }).toString();
  const gatewayPublicKey = publicKeyRawBase64UrlFromPem(publicKeyPem);
  const gatewayDeviceId = deriveGatewayDeviceId(gatewayPublicKey);
  if (!gatewayDeviceId) {
    throw new Error("failed to derive test gateway device id");
  }
  const request: RegisterRequestBody = {
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
    apnsToken: "1234567890ABCDEF1234567890ABCDEF",
    appAttest: {
      keyId: "key-1",
      assertion: Buffer.from("assertion").toString("base64"),
      clientDataHash: "",
      signedPayloadBase64: "",
      attestationObject: Buffer.from("attestation").toString("base64"),
    },
    receipt: {
      base64: "receipt",
    },
  };

  const signedPayload = JSON.stringify({
    challengeId: request.challengeId,
    installationId: request.installationId,
    bundleId: request.bundleId,
    environment: request.environment,
    distribution: request.distribution,
    gateway: request.gateway,
    appVersion: request.appVersion,
    apnsToken: request.apnsToken,
  });
  request.appAttest.signedPayloadBase64 = Buffer.from(signedPayload, "utf8").toString("base64");
  request.appAttest.clientDataHash = await encodeSha256Base64Url(signedPayload);
  return request;
}

describe("verifyAndPersistRegistrationInternal", () => {
  afterEach(() => {
    restoreEnv();
    vi.restoreAllMocks();
    verifyAssertionMock.mockReset();
    verifyAttestationMock.mockReset();
    globalThis.fetch = ORIGINAL_FETCH;
  });

  it("verifies and persists a registration", async () => {
    setRequiredEnv({
      APPLE_RECEIPT_SECRET: "shared-secret",
    });
    vi.spyOn(Date, "now").mockReturnValue(1_700_000_000_000);

    const request = await makeRegisterRequest();
    const runQuery = vi.fn().mockResolvedValue(null);
    const runMutation = vi.fn().mockResolvedValue(undefined);
    verifyAttestationMock.mockReturnValue({
      publicKey: "public-key",
    });
    verifyAssertionMock.mockReturnValue({
      signCount: 7,
    });

    const fetchMock = vi.fn().mockResolvedValue(
      new Response(
        JSON.stringify({
          status: 0,
          environment: "Production",
          receipt: {
            bundle_id: request.bundleId,
          },
        }),
        {
          status: 200,
          headers: {
            "content-type": "application/json",
          },
        },
      ),
    );
    globalThis.fetch = fetchMock as typeof fetch;

    const result = await (verifyAndPersistRegistrationInternal as unknown as TestableInternalAction)
      ._handler(
        {
          runQuery,
          runMutation,
        },
        {
          challenge: "opaque-challenge",
          request,
        },
      );

    expect(runQuery).toHaveBeenCalledTimes(1);
    expect(getFunctionName(runQuery.mock.calls[0]![0])).toBe(
      "relay/internal:getAppAttestKeyByKeyIdInternal",
    );
    expect(runQuery.mock.calls[0]![1]).toEqual({
      keyId: "key-1",
    });

    expect(fetchMock).toHaveBeenCalledTimes(1);
    expect(runMutation).toHaveBeenCalledTimes(1);
    expect(getFunctionName(runMutation.mock.calls[0]![0])).toBe(
      "relay/internal:applyVerifiedRegistrationInternal",
    );

    expect(result).toMatchObject({
      ok: true,
      response: {
        status: "active",
      },
    });

    const mutationArgs = runMutation.mock.calls[0]![1] as {
      appAttestRecord: Record<string, unknown>;
      registrationRecord: {
        apnsTokenCiphertext: string;
        relayHandleHash: string;
        sendGrantHash: string;
        relayHandleExpiresAtMs: number;
        tokenSuffix: string;
      };
    };
    expect(mutationArgs.appAttestRecord).toMatchObject({
      keyId: "key-1",
      installationId: "install-1",
      bundleId: "ai.openclaw.client",
      publicKey: "public-key",
      signCount: 7,
      attestedAtMs: 1_700_000_000_000,
      lastAssertedAtMs: 1_700_000_000_000,
    });

    const normalizedToken = normalizeApnsToken(request.apnsToken);
    expect(
      decryptString(
        mutationArgs.registrationRecord.apnsTokenCiphertext,
        parseEncryptionKey(process.env.RELAY_ENC_KEY!),
      ),
    ).toBe(normalizedToken);

    if (typeof result === "object" && result !== null && "ok" in result && result.ok) {
      const successResult = result as {
        ok: true;
        response: {
          relayHandle: string;
          sendGrant: string;
          expiresAtMs: number;
          tokenSuffix: string;
        };
      };
      expect(mutationArgs.registrationRecord.relayHandleHash).toBe(
        hashSha256Sync(successResult.response.relayHandle),
      );
      expect(mutationArgs.registrationRecord.sendGrantHash).toBe(
        hashSha256Sync(successResult.response.sendGrant),
      );
      expect(mutationArgs.registrationRecord.relayHandleExpiresAtMs).toBe(
        successResult.response.expiresAtMs,
      );
      expect(mutationArgs.registrationRecord.tokenSuffix).toBe(successResult.response.tokenSuffix);
    }
  });

  it("returns unauthorized when App Attest verification fails", async () => {
    setRequiredEnv();

    const request = await makeRegisterRequest();
    request.appAttest.clientDataHash = "wrong-hash";

    const runQuery = vi.fn().mockResolvedValue(null);
    const runMutation = vi.fn();
    const fetchMock = vi.fn();
    globalThis.fetch = fetchMock as typeof fetch;

    const result = await (verifyAndPersistRegistrationInternal as unknown as TestableInternalAction)
      ._handler(
        {
          runQuery,
          runMutation,
        },
        {
          challenge: "opaque-challenge",
          request,
        },
      );

    expect(result).toEqual({
      ok: false,
      error: "unauthorized",
      message: "clientDataHash does not match request payload",
    });
    expect(fetchMock).not.toHaveBeenCalled();
    expect(runMutation).not.toHaveBeenCalled();
  });

  it("returns unauthorized when receipt verification fails", async () => {
    setRequiredEnv();

    const request = await makeRegisterRequest();
    const runQuery = vi.fn().mockResolvedValue(null);
    const runMutation = vi.fn();
    verifyAttestationMock.mockReturnValue({
      publicKey: "public-key",
    });
    verifyAssertionMock.mockReturnValue({
      signCount: 7,
    });

    const fetchMock = vi.fn().mockResolvedValue(
      new Response(
        JSON.stringify({
          status: 0,
          environment: "Production",
          receipt: {
            bundle_id: "ai.openclaw.other",
          },
        }),
        {
          status: 200,
          headers: {
            "content-type": "application/json",
          },
        },
      ),
    );
    globalThis.fetch = fetchMock as typeof fetch;

    const result = await (verifyAndPersistRegistrationInternal as unknown as TestableInternalAction)
      ._handler(
        {
          runQuery,
          runMutation,
        },
        {
          challenge: "opaque-challenge",
          request,
        },
      );

    expect(result).toEqual({
      ok: false,
      error: "unauthorized",
      message: "receipt bundle id mismatch",
    });
    expect(runMutation).not.toHaveBeenCalled();
  });

  it("returns service_unavailable when receipt verification is unavailable", async () => {
    setRequiredEnv();

    const request = await makeRegisterRequest();
    const runQuery = vi.fn().mockResolvedValue(null);
    const runMutation = vi.fn();
    verifyAttestationMock.mockReturnValue({
      publicKey: "public-key",
    });
    verifyAssertionMock.mockReturnValue({
      signCount: 7,
    });
    globalThis.fetch = vi.fn(async () => {
      throw new Error("network down");
    }) as typeof fetch;

    const result = await (verifyAndPersistRegistrationInternal as unknown as TestableInternalAction)
      ._handler(
        {
          runQuery,
          runMutation,
        },
        {
          challenge: "opaque-challenge",
          request,
        },
      );

    expect(result).toEqual({
      ok: false,
      error: "service_unavailable",
      message: "receipt verification unavailable",
    });
    expect(runMutation).not.toHaveBeenCalled();
  });
});
