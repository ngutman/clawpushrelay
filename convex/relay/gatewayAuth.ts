"use node";

import { createHash, createPublicKey, verify as verifySignature } from "node:crypto";

const ED25519_SPKI_PREFIX = Buffer.from("302a300506032b6570032100", "hex");

function base64UrlEncode(buf: Buffer): string {
  return buf.toString("base64").replaceAll("+", "-").replaceAll("/", "_").replace(/=+$/g, "");
}

function base64UrlDecode(input: string): Buffer {
  const normalized = input.replaceAll("-", "+").replaceAll("_", "/");
  const padded = normalized + "=".repeat((4 - (normalized.length % 4)) % 4);
  return Buffer.from(padded, "base64");
}

export function normalizeGatewayPublicKey(value: string): string | null {
  try {
    return base64UrlEncode(base64UrlDecode(value.trim()));
  } catch {
    return null;
  }
}

export function publicKeyRawBase64UrlFromPem(publicKeyPem: string): string {
  const key = createPublicKey(publicKeyPem);
  const spki = key.export({ type: "spki", format: "der" }) as Buffer;
  if (
    spki.length === ED25519_SPKI_PREFIX.length + 32 &&
    spki.subarray(0, ED25519_SPKI_PREFIX.length).equals(ED25519_SPKI_PREFIX)
  ) {
    return base64UrlEncode(spki.subarray(ED25519_SPKI_PREFIX.length));
  }
  return base64UrlEncode(spki);
}

export function deriveGatewayDeviceId(publicKey: string): string | null {
  const normalized = normalizeGatewayPublicKey(publicKey);
  if (!normalized) {
    return null;
  }
  return createHash("sha256").update(base64UrlDecode(normalized)).digest("hex");
}

export function buildGatewaySignaturePayload(params: {
  gatewayDeviceId: string;
  signedAtMs: number;
  bodyText: string;
}): string {
  return [
    "openclaw-relay-send-v1",
    params.gatewayDeviceId.trim(),
    String(Math.trunc(params.signedAtMs)),
    params.bodyText,
  ].join("\n");
}

export function verifyGatewaySignature(params: {
  publicKey: string;
  payload: string;
  signature: string;
}): boolean {
  try {
    const rawPublicKey = base64UrlDecode(params.publicKey);
    const key = createPublicKey({
      key: Buffer.concat([ED25519_SPKI_PREFIX, rawPublicKey]),
      type: "spki",
      format: "der",
    });
    const signature = base64UrlDecode(params.signature);
    return verifySignature(null, Buffer.from(params.payload, "utf8"), key, signature);
  } catch {
    return false;
  }
}
