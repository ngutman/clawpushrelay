import type { FastifyReply, FastifyRequest } from "fastify";
import { z } from "zod";
import { AppAttestVerificationError, AppAttestVerifier } from "./app-attest.js";
import { ApnsSender } from "./apns.js";
import { ChallengeStore } from "./challenges.js";
import { randomOpaqueToken } from "./crypto.js";
import { SlidingWindowRateLimiter } from "./rate-limit.js";
import {
  ReceiptVerificationError,
  ReceiptVerificationServiceError,
  ReceiptVerifier,
} from "./receipt.js";
import { RelayStateStore } from "./state-store.js";
import type { RelayConfig } from "./config.js";
import type { RegisterRequestBody, SendRequestBody } from "./types.js";

const registerSchema = z.object({
  challengeId: z.string().min(1),
  installationId: z.string().min(1),
  bundleId: z.string().min(1),
  environment: z.literal("production"),
  distribution: z.literal("official"),
  appVersion: z.string().min(1),
  apnsToken: z.string().regex(/^[0-9a-fA-F]{32,}$/),
  appAttest: z.object({
    keyId: z.string().min(1),
    attestationObject: z.string().min(1).optional(),
    assertion: z.string().min(1),
    clientDataHash: z.string().min(1),
    signedPayloadBase64: z.string().min(1),
  }),
  receipt: z.object({
    base64: z.string().min(1),
  }),
});

const sendSchema = z.object({
  relayHandle: z.string().min(1),
  pushType: z.enum(["alert", "background"]),
  priority: z.union([z.literal(5), z.literal(10)]),
  payload: z.record(z.string(), z.unknown()),
});

function clientIp(request: FastifyRequest): string {
  return request.ip || "unknown";
}

function unauthorized(reply: FastifyReply, message: string): FastifyReply {
  return reply.code(401).send({
    error: "unauthorized",
    message,
  });
}

function rateLimited(reply: FastifyReply): FastifyReply {
  return reply.code(429).send({
    error: "rate_limited",
    message: "rate limit exceeded",
  });
}

function serviceUnavailable(reply: FastifyReply, message: string): FastifyReply {
  return reply.code(503).send({
    error: "service_unavailable",
    message,
  });
}

function summarizeIdentifier(value: string): string {
  const trimmed = value.trim();
  if (trimmed.length <= 12) {
    return trimmed;
  }
  return `${trimmed.slice(0, 6)}...${trimmed.slice(-6)}`;
}

function validatePushPayload(body: SendRequestBody): string | null {
  const aps = body.payload.aps;
  if (typeof aps !== "object" || aps === null || Array.isArray(aps)) {
    return "payload.aps is required";
  }
  if (body.pushType === "background") {
    const contentAvailable = (aps as Record<string, unknown>)["content-available"];
    if (contentAvailable !== 1) {
      return "background push payload must set aps.content-available to 1";
    }
    if (body.priority !== 5) {
      return "background pushes must use priority 5";
    }
    return null;
  }
  if (body.priority !== 10) {
    return "alert pushes must use priority 10";
  }
  const alert = (aps as Record<string, unknown>).alert;
  if (typeof alert !== "object" || alert === null || Array.isArray(alert)) {
    return "alert push payload must include aps.alert";
  }
  return null;
}

export function registerRelayRoutes(params: {
  config: RelayConfig;
  stateStore: RelayStateStore;
  challengeStore: ChallengeStore;
  rateLimiter: SlidingWindowRateLimiter;
  appAttestVerifier: AppAttestVerifier;
  receiptVerifier: ReceiptVerifier;
  apnsSender: ApnsSender;
}) {
  return async function routes(fastify: {
    post: (
      path: string,
      handler: (request: FastifyRequest, reply: FastifyReply) => Promise<unknown>,
    ) => void;
  }) {
    fastify.post("/v1/push/challenge", async (request, reply) => {
      if (
        !params.rateLimiter.consume(
          `challenge:${clientIp(request)}`,
          params.config.challengeRateLimitMax,
        )
      ) {
        return rateLimited(reply);
      }
      const challenge = params.challengeStore.issue();
      reply.header("cache-control", "no-store");
      return reply.code(200).send(challenge);
    });

    fastify.post("/v1/push/register", async (request, reply) => {
      if (
        !params.rateLimiter.consume(
          `register:${clientIp(request)}`,
          params.config.registerRateLimitMax,
        )
      ) {
        return rateLimited(reply);
      }

      const parsed = registerSchema.safeParse(request.body);
      if (!parsed.success) {
        return await reply.code(400).send({
          error: "invalid_request",
          message: parsed.error.issues[0]?.message ?? "invalid request",
        });
      }
      const body = parsed.data;
      if (!params.config.allowedBundleIds.includes(body.bundleId)) {
        return reply.code(403).send({
          error: "bundle_not_allowed",
          message: "bundle id is not allowed",
        });
      }

      const challenge = params.challengeStore.consume(body.challengeId);
      if (!challenge) {
        request.log.warn(
          {
            event: "push_register_rejected",
            reason: "invalid_challenge",
            installationId: summarizeIdentifier(body.installationId),
            bundleId: body.bundleId,
          },
          "push register rejected",
        );
        reply.header("cache-control", "no-store");
        return reply.code(401).send({
          error: "invalid_challenge",
          message: "challenge missing or expired",
        });
      }

      try {
        await params.appAttestVerifier.verifyRegistration({
          challenge: challenge.challenge,
          request: body,
        });
        const receipt = await params.receiptVerifier.verifyReceipt({
          receiptBase64: body.receipt.base64,
          bundleId: body.bundleId,
        });

        const relayHandle = randomOpaqueToken(32);
        const nowMs = Date.now();
        const registration = await params.stateStore.replaceRegistration({
          installationId: body.installationId,
          bundleId: body.bundleId,
          environment: body.environment,
          distribution: body.distribution,
          relayHandle,
          relayHandleExpiresAtMs: nowMs + params.config.handleTtlMs,
          apnsTopic: body.bundleId,
          apnsToken: body.apnsToken,
          appAttestKeyId: body.appAttest.keyId,
          receiptEnvironment: receipt.environment,
          appVersion: body.appVersion,
          nowMs,
        });

        reply.header("cache-control", "no-store");
        return reply.code(200).send({
          relayHandle,
          expiresAtMs: registration.relayHandleExpiresAtMs,
          tokenSuffix: registration.tokenSuffix,
          status: "active",
        });
      } catch (error) {
        if (
          error instanceof AppAttestVerificationError ||
          error instanceof ReceiptVerificationError
        ) {
          request.log.warn(
            {
              event: "push_register_rejected",
              reason: error.message,
              errorName: error.name,
              installationId: summarizeIdentifier(body.installationId),
              bundleId: body.bundleId,
              appAttestKeyId: summarizeIdentifier(body.appAttest.keyId),
            },
            "push register rejected",
          );
          reply.header("cache-control", "no-store");
          return unauthorized(reply, error.message);
        }
        if (error instanceof ReceiptVerificationServiceError) {
          request.log.error(
            {
              event: "push_register_service_unavailable",
              reason: error.message,
              installationId: summarizeIdentifier(body.installationId),
              bundleId: body.bundleId,
            },
            "push register unavailable",
          );
          reply.header("cache-control", "no-store");
          return serviceUnavailable(reply, "receipt verification unavailable");
        }
        throw error;
      }
    });

    fastify.post("/v1/push/send", async (request, reply) => {
      if (
        !params.rateLimiter.consume(`send:${clientIp(request)}`, params.config.sendRateLimitMax)
      ) {
        return rateLimited(reply);
      }
      const authorization = request.headers.authorization?.trim() ?? "";
      if (authorization !== `Bearer ${params.config.gatewayBearerToken}`) {
        return unauthorized(reply, "missing or invalid gateway bearer token");
      }

      const parsed = sendSchema.safeParse(request.body);
      if (!parsed.success) {
        return await reply.code(400).send({
          error: "invalid_request",
          message: parsed.error.issues[0]?.message ?? "invalid request",
        });
      }

      const body = parsed.data;
      const payloadError = validatePushPayload(body);
      if (payloadError) {
        return reply.code(400).send({
          error: "invalid_request",
          message: payloadError,
        });
      }

      const registration = await params.stateStore.findRegistrationByHandle(body.relayHandle);
      if (!registration) {
        return reply.code(410).send({
          ok: false,
          status: 410,
          reason: "Unregistered",
          environment: "production",
          tokenSuffix: "unknown",
        });
      }
      const nowMs = Date.now();
      if (registration.status !== "active" || registration.relayHandleExpiresAtMs <= nowMs) {
        await params.stateStore.markRegistrationStatus(body.relayHandle, "stale", nowMs, "expired");
        return reply.code(410).send({
          ok: false,
          status: 410,
          reason: "Unregistered",
          environment: registration.environment,
          tokenSuffix: registration.tokenSuffix,
        });
      }

      try {
        const apnsToken = await params.stateStore.decryptApnsToken(registration);
        const result = await params.apnsSender.send({
          token: apnsToken,
          topic: registration.apnsTopic,
          payload: body.payload,
          pushType: body.pushType,
          priority: body.priority,
        });
        await params.stateStore.updateSendResult({
          relayHandle: body.relayHandle,
          status: result.status,
          reason: result.reason,
          nowMs,
        });
        return reply.code(result.status).send(result);
      } catch (error) {
        return reply.code(503).send({
          ok: false,
          status: 503,
          reason: error instanceof Error ? error.message : String(error),
          environment: registration.environment,
          tokenSuffix: registration.tokenSuffix,
        });
      }
    });
  };
}
