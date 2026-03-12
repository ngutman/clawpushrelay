import { z } from "zod";
import type { RegisterRequestBody, SendRequestBody } from "./types.js";

export const registerRequestSchema = z.object({
  challengeId: z.string().min(1),
  installationId: z.string().min(1),
  bundleId: z.string().min(1),
  environment: z.literal("production"),
  distribution: z.literal("official"),
  gateway: z.object({
    deviceId: z.string().min(1),
    publicKey: z.string().min(1),
  }),
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

export const sendRequestSchema = z.object({
  relayHandle: z.string().min(1),
  pushType: z.enum(["alert", "background"]),
  priority: z.union([z.literal(5), z.literal(10)]),
  payload: z.record(z.string(), z.unknown()),
});

export function validatePushPayload(body: SendRequestBody): string | null {
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

export function parseRegisterRequest(body: unknown): RegisterRequestBody {
  return registerRequestSchema.parse(body);
}

export function parseSendRequest(body: unknown): SendRequestBody {
  return sendRequestSchema.parse(body);
}
