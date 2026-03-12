import { describe, expect, it } from "vitest";
import {
  decryptString,
  encryptString,
  hashSha256Sync,
  parseEncryptionKey,
  randomOpaqueToken,
} from "./nodeCrypto.js";

describe("node crypto helpers", () => {
  it("parses hex and base64 encryption keys", () => {
    const hex = "11".repeat(32);
    const base64 = Buffer.alloc(32, 7).toString("base64");

    expect(parseEncryptionKey(hex)).toEqual(Buffer.from(hex, "hex"));
    expect(parseEncryptionKey(base64)).toEqual(Buffer.alloc(32, 7));
  });

  it("rejects invalid encryption keys", () => {
    expect(() => parseEncryptionKey("short")).toThrow("RELAY_ENC_KEY must decode to 32 bytes");
  });

  it("round-trips encrypted values", () => {
    const key = parseEncryptionKey(Buffer.alloc(32, 9).toString("base64"));
    const ciphertext = encryptString("secret payload", key);

    expect(decryptString(ciphertext, key)).toBe("secret payload");
  });

  it("emits opaque random tokens and stable sync hashes", () => {
    const token = randomOpaqueToken(32);

    expect(token).toMatch(/^[A-Za-z0-9_-]+$/);
    expect(hashSha256Sync("hello")).toBe(
      "2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824",
    );
  });
});
