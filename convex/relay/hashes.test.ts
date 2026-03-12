import { describe, expect, it } from "vitest";
import {
  apnsTokenSuffix,
  encodeSha256Base64Url,
  hashSha256,
  normalizeApnsToken,
} from "./hashes.js";

describe("hash helpers", () => {
  it("normalizes APNs tokens and extracts their suffix", () => {
    expect(normalizeApnsToken(" <ABCDef12 34> ")).toBe("abcdef1234");
    expect(apnsTokenSuffix(" 1234567890ABCDEF ")).toBe("90abcdef");
  });

  it("hashes to stable SHA-256 encodings", async () => {
    expect(await hashSha256("hello")).toBe(
      "2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824",
    );
    expect(await encodeSha256Base64Url("hello")).toBe("LPJNul-wow4m6DsqxbninhsWHlwfp0JecwQzYpOLmCQ");
  });
});
