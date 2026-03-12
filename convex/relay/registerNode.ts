"use node";

import { randomUUID } from "node:crypto";
import { anyApi, internalActionGeneric } from "convex/server";
import { v } from "convex/values";
import { verifyAssertion, verifyAttestation } from "node-app-attest";
import { loadRelayConfig } from "./config.js";
import { deriveGatewayDeviceId, normalizeGatewayPublicKey } from "./gatewayAuth.js";
import { apnsTokenSuffix, encodeSha256Base64Url, normalizeApnsToken } from "./hashes.js";
import { encryptString, hashSha256Sync, parseEncryptionKey, randomOpaqueToken } from "./nodeCrypto.js";
import type {
  AppAttestRecord,
  RegisterActionResult,
  RegisterRequestBody,
  RelayRegistrationRecord,
} from "./types.js";

const APPLE_PRODUCTION_RECEIPT_URL = "https://buy.itunes.apple.com/verifyReceipt";
const APPLE_SANDBOX_RECEIPT_URL = "https://sandbox.itunes.apple.com/verifyReceipt";

const internalAction = internalActionGeneric;

const registerRequestValidator = v.object({
  challengeId: v.string(),
  installationId: v.string(),
  bundleId: v.string(),
  environment: v.literal("production"),
  distribution: v.literal("official"),
  gateway: v.object({
    deviceId: v.string(),
    publicKey: v.string(),
  }),
  appVersion: v.string(),
  apnsToken: v.string(),
  appAttest: v.object({
    keyId: v.string(),
    attestationObject: v.optional(v.string()),
    assertion: v.string(),
    clientDataHash: v.string(),
    signedPayloadBase64: v.string(),
  }),
  receipt: v.object({
    base64: v.string(),
  }),
});

type ReceiptVerificationResult = {
  environment: string;
  bundleId: string;
};

type AppleVerifyReceiptResponse = {
  status: number;
  environment?: string;
  receipt?: {
    bundle_id?: string;
  };
};

class AppAttestVerificationError extends Error {}

class ReceiptVerificationError extends Error {}

class ReceiptVerificationServiceError extends Error {}

function unexpectedMessage(error: unknown, fallback: string): string {
  return error instanceof Error && error.message ? error.message : fallback;
}

async function verifyReceipt(params: {
  receiptBase64: string;
  bundleId: string;
  sharedSecret?: string;
}): Promise<ReceiptVerificationResult> {
  const production = await callApple({
    url: APPLE_PRODUCTION_RECEIPT_URL,
    receiptBase64: params.receiptBase64,
    sharedSecret: params.sharedSecret,
  });
  const result =
    production.status === 21007
      ? await callApple({
          url: APPLE_SANDBOX_RECEIPT_URL,
          receiptBase64: params.receiptBase64,
          sharedSecret: params.sharedSecret,
        })
      : production;

  if (result.status !== 0) {
    throw new ReceiptVerificationError(`Apple receipt validation failed with status ${result.status}`);
  }

  const receiptBundleId = result.receipt?.bundle_id?.trim();
  if (!receiptBundleId || receiptBundleId !== params.bundleId) {
    throw new ReceiptVerificationError("receipt bundle id mismatch");
  }
  const receiptEnvironment = result.environment?.trim();
  if (receiptEnvironment !== "Production" && receiptEnvironment !== "Sandbox") {
    throw new ReceiptVerificationError("receipt environment invalid");
  }

  return {
    environment: receiptEnvironment,
    bundleId: receiptBundleId,
  };
}

async function callApple(params: {
  url: string;
  receiptBase64: string;
  sharedSecret?: string;
}): Promise<AppleVerifyReceiptResponse> {
  let response: Response;
  try {
    response = await fetch(params.url, {
      method: "POST",
      headers: {
        "content-type": "application/json",
      },
      body: JSON.stringify({
        "receipt-data": params.receiptBase64,
        ...(params.sharedSecret ? { password: params.sharedSecret } : {}),
        "exclude-old-transactions": true,
      }),
    });
  } catch (error) {
    throw new ReceiptVerificationServiceError(
      `Apple receipt validation unavailable: ${unexpectedMessage(error, "unknown error")}`,
    );
  }

  if (!response.ok) {
    throw new ReceiptVerificationServiceError(
      `Apple receipt validation unavailable (HTTP ${response.status})`,
    );
  }

  return (await response.json()) as AppleVerifyReceiptResponse;
}

async function verifyAppAttest(params: {
  challenge: string;
  request: RegisterRequestBody;
  existingKey: AppAttestRecord | null;
  teamId: string;
  allowDevelopmentEnvironment: boolean;
  nowMs: number;
}): Promise<AppAttestRecord> {
  const payloadBuffer = Buffer.from(params.request.appAttest.signedPayloadBase64, "base64");
  const payload = payloadBuffer.toString("utf8");
  const expectedClientDataHash = await encodeSha256Base64Url(payload);

  if (expectedClientDataHash !== params.request.appAttest.clientDataHash) {
    throw new AppAttestVerificationError("clientDataHash does not match request payload");
  }

  let parsedPayload: Partial<{
    challengeId: string;
    installationId: string;
    bundleId: string;
    environment: string;
    distribution: string;
    gateway: {
      deviceId: string;
      publicKey: string;
    };
    appVersion: string;
    apnsToken: string;
  }>;

  try {
    parsedPayload = JSON.parse(payload) as typeof parsedPayload;
  } catch {
    throw new AppAttestVerificationError("signed payload is not valid JSON");
  }

  if (
    parsedPayload.challengeId !== params.request.challengeId ||
    parsedPayload.installationId !== params.request.installationId ||
    parsedPayload.bundleId !== params.request.bundleId ||
    parsedPayload.environment !== params.request.environment ||
    parsedPayload.distribution !== params.request.distribution ||
    parsedPayload.gateway?.deviceId !== params.request.gateway.deviceId ||
    parsedPayload.gateway?.publicKey !== params.request.gateway.publicKey ||
    parsedPayload.appVersion !== params.request.appVersion ||
    normalizeApnsToken(parsedPayload.apnsToken ?? "") !== normalizeApnsToken(params.request.apnsToken)
  ) {
    throw new AppAttestVerificationError("signed payload does not match registration request");
  }

  let publicKey: string;
  let signCount: number;

  if (!params.existingKey) {
    const attestationObject = params.request.appAttest.attestationObject;
    if (!attestationObject) {
      throw new AppAttestVerificationError("attestationObject is required for new App Attest keys");
    }

    try {
      const verified = verifyAttestation({
        attestation: Buffer.from(attestationObject, "base64"),
        challenge: params.challenge,
        keyId: params.request.appAttest.keyId,
        bundleIdentifier: params.request.bundleId,
        teamIdentifier: params.teamId,
        allowDevelopmentEnvironment: params.allowDevelopmentEnvironment,
      });
      publicKey = verified.publicKey;
      signCount = 0;
    } catch (error) {
      throw new AppAttestVerificationError(unexpectedMessage(error, "App Attest attestation failed"));
    }
  } else {
    if (
      params.existingKey.installationId !== params.request.installationId ||
      params.existingKey.bundleId !== params.request.bundleId ||
      params.existingKey.environment !== params.request.environment ||
      params.existingKey.revokedAtMs
    ) {
      throw new AppAttestVerificationError("App Attest key binding mismatch");
    }
    publicKey = params.existingKey.publicKey;
    signCount = params.existingKey.signCount;
  }

  let assertionSignCount: number;
  try {
    const assertion = verifyAssertion({
      assertion: Buffer.from(params.request.appAttest.assertion, "base64"),
      payload,
      publicKey,
      bundleIdentifier: params.request.bundleId,
      teamIdentifier: params.teamId,
      signCount,
    });
    assertionSignCount = assertion.signCount;
  } catch (error) {
    throw new AppAttestVerificationError(unexpectedMessage(error, "App Attest assertion failed"));
  }

  return {
    keyId: params.request.appAttest.keyId,
    installationId: params.request.installationId,
    bundleId: params.request.bundleId,
    environment: params.request.environment,
    publicKey,
    signCount: assertionSignCount,
    attestedAtMs: params.existingKey?.attestedAtMs ?? params.nowMs,
    lastAssertedAtMs: params.nowMs,
    revokedAtMs: params.existingKey?.revokedAtMs,
  };
}

function buildRegistrationRecord(params: {
  request: RegisterRequestBody;
  receiptEnvironment: string;
  relayHandle: string;
  sendGrant: string;
  nowMs: number;
  handleTtlMs: number;
  encryptionKey: Buffer;
}): RelayRegistrationRecord {
  const normalizedToken = normalizeApnsToken(params.request.apnsToken);

  return {
    registrationId: randomUUID(),
    installationId: params.request.installationId,
    bundleId: params.request.bundleId,
    environment: params.request.environment,
    distribution: params.request.distribution,
    gatewayDeviceId: params.request.gateway.deviceId,
    gatewayPublicKey: params.request.gateway.publicKey,
    apnsTopic: params.request.bundleId,
    apnsTokenCiphertext: encryptString(normalizedToken, params.encryptionKey),
    apnsTokenHash: hashSha256Sync(normalizedToken),
    tokenSuffix: apnsTokenSuffix(normalizedToken),
    relayHandleHash: hashSha256Sync(params.relayHandle),
    sendGrantHash: hashSha256Sync(params.sendGrant),
    relayHandleExpiresAtMs: params.nowMs + params.handleTtlMs,
    appAttestKeyId: params.request.appAttest.keyId,
    proofType: "receipt",
    receiptEnvironment: params.receiptEnvironment,
    appVersion: params.request.appVersion,
    status: "active",
    createdAtMs: params.nowMs,
    updatedAtMs: params.nowMs,
    lastRegisteredAtMs: params.nowMs,
  };
}

export const verifyAndPersistRegistrationInternal = internalAction({
  args: {
    challenge: v.string(),
    request: registerRequestValidator,
  },
  handler: async (ctx, args): Promise<RegisterActionResult> => {
    const config = loadRelayConfig();
    const nowMs = Date.now();

    try {
      const existingKey = await ctx.runQuery(anyApi.relay.internal.getAppAttestKeyByKeyIdInternal, {
        keyId: args.request.appAttest.keyId,
      });

      const appAttestRecord = await verifyAppAttest({
        challenge: args.challenge,
        request: args.request,
        existingKey,
        teamId: config.appleTeamId,
        allowDevelopmentEnvironment: config.appAttestAllowDevelopment,
        nowMs,
      });

      const receipt = await verifyReceipt({
        receiptBase64: args.request.receipt.base64,
        bundleId: args.request.bundleId,
        sharedSecret: config.appleReceiptSharedSecret,
      });
      const normalizedGatewayPublicKey = normalizeGatewayPublicKey(args.request.gateway.publicKey);
      if (!normalizedGatewayPublicKey) {
        return {
          ok: false,
          error: "unauthorized",
          message: "gateway public key invalid",
        };
      }
      const derivedGatewayDeviceId = deriveGatewayDeviceId(normalizedGatewayPublicKey);
      if (!derivedGatewayDeviceId || derivedGatewayDeviceId !== args.request.gateway.deviceId.trim()) {
        return {
          ok: false,
          error: "unauthorized",
          message: "gateway device identity mismatch",
        };
      }
      args.request.gateway.publicKey = normalizedGatewayPublicKey;
      args.request.gateway.deviceId = derivedGatewayDeviceId;

      const relayHandle = randomOpaqueToken(32);
      const sendGrant = randomOpaqueToken(32);
      const registrationRecord = buildRegistrationRecord({
        request: args.request,
        receiptEnvironment: receipt.environment,
        relayHandle,
        sendGrant,
        nowMs,
        handleTtlMs: config.handleTtlMs,
        encryptionKey: parseEncryptionKey(config.encryptionKey),
      });

      await ctx.runMutation(anyApi.relay.internal.applyVerifiedRegistrationInternal, {
        appAttestRecord,
        registrationRecord,
      });

      return {
        ok: true,
        response: {
          relayHandle,
          sendGrant,
          expiresAtMs: registrationRecord.relayHandleExpiresAtMs,
          tokenSuffix: registrationRecord.tokenSuffix,
          status: "active",
        },
      };
    } catch (error) {
      if (error instanceof AppAttestVerificationError || error instanceof ReceiptVerificationError) {
        return {
          ok: false,
          error: "unauthorized",
          message: error.message,
        };
      }

      if (error instanceof ReceiptVerificationServiceError) {
        return {
          ok: false,
          error: "service_unavailable",
          message: "receipt verification unavailable",
        };
      }

      throw error;
    }
  },
});
