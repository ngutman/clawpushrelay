import { createCipheriv, createDecipheriv, createHash, randomBytes } from "node:crypto";

function toBase64Url(value: Uint8Array): string {
  return Buffer.from(value)
    .toString("base64")
    .replace(/\+/g, "-")
    .replace(/\//g, "_")
    .replace(/=+$/g, "");
}

function fromBase64Url(value: string): Buffer {
  const normalized = value.replace(/-/g, "+").replace(/_/g, "/");
  const padding = normalized.length % 4 === 0 ? "" : "=".repeat(4 - (normalized.length % 4));
  return Buffer.from(`${normalized}${padding}`, "base64");
}

export function parseEncryptionKey(raw: string): Buffer {
  const trimmed = raw.trim();
  if (/^[0-9a-f]{64}$/i.test(trimmed)) {
    return Buffer.from(trimmed, "hex");
  }
  const buffer = Buffer.from(trimmed.replace(/-/g, "+").replace(/_/g, "/"), "base64");
  if (buffer.length !== 32) {
    throw new Error("CLAWPUSHRELAY_ENCRYPTION_KEY must decode to 32 bytes");
  }
  return buffer;
}

export function hashSha256(value: string): string {
  return createHash("sha256").update(value, "utf8").digest("hex");
}

export function encodeSha256Base64Url(value: string): string {
  return toBase64Url(createHash("sha256").update(value, "utf8").digest());
}

export function encryptString(plaintext: string, key: Buffer): string {
  const iv = randomBytes(12);
  const cipher = createCipheriv("aes-256-gcm", key, iv);
  const encrypted = Buffer.concat([cipher.update(plaintext, "utf8"), cipher.final()]);
  const tag = cipher.getAuthTag();
  return `${toBase64Url(iv)}.${toBase64Url(encrypted)}.${toBase64Url(tag)}`;
}

export function decryptString(ciphertext: string, key: Buffer): string {
  const [ivPart, encryptedPart, tagPart] = ciphertext.split(".");
  if (!ivPart || !encryptedPart || !tagPart) {
    throw new Error("invalid ciphertext payload");
  }
  const decipher = createDecipheriv("aes-256-gcm", key, fromBase64Url(ivPart));
  decipher.setAuthTag(fromBase64Url(tagPart));
  const plaintext = Buffer.concat([
    decipher.update(fromBase64Url(encryptedPart)),
    decipher.final(),
  ]);
  return plaintext.toString("utf8");
}

export function randomOpaqueToken(bytes: number): string {
  return toBase64Url(randomBytes(bytes));
}

export function apnsTokenSuffix(token: string): string {
  const normalized = token.trim().replace(/[<>\s]/g, "").toLowerCase();
  return normalized.slice(-8);
}
