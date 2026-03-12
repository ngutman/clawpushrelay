import { describe, expect, it } from "vitest";
import { loadRelayConfig } from "./config.js";

function makeEnv(overrides: NodeJS.ProcessEnv = {}): NodeJS.ProcessEnv {
  return {
    RELAY_ENC_KEY: Buffer.alloc(32, 7).toString("base64"),
    RELAY_ALLOWED_BUNDLE_IDS: "ai.openclaw.client,ai.openclaw.beta",
    APPLE_TEAM_ID: "TEAM123",
    APP_ATTEST_ALLOW_DEV: "true",
    HANDLE_TTL_MS: "60000",
    CHALLENGE_TTL_MS: "300000",
    RATE_LIMIT_WINDOW_MS: "60000",
    CHALLENGE_RATE_LIMIT_MAX: "30",
    REGISTER_RATE_LIMIT_MAX: "10",
    SEND_RATE_LIMIT_MAX: "120",
    APNS_TEAM_ID: "TEAM123",
    APNS_KEY_ID: "KEY123",
    APNS_P8: "-----BEGIN PRIVATE KEY-----\\nsecret\\n-----END PRIVATE KEY-----",
    APPLE_RECEIPT_SECRET: "receipt-secret",
    ...overrides,
  };
}

describe("loadRelayConfig", () => {
  it("loads required config and applies conversions", () => {
    const config = loadRelayConfig(makeEnv());

    expect(config.allowedBundleIds).toEqual(["ai.openclaw.client", "ai.openclaw.beta"]);
    expect(config.appAttestAllowDevelopment).toBe(true);
    expect(config.apnsPrivateKey).toContain("\nsecret\n");
    expect(config.appleReceiptSharedSecret).toBe("receipt-secret");
  });

  it("applies defaults for optional values", () => {
    const config = loadRelayConfig(
      makeEnv({
        RELAY_ALLOWED_BUNDLE_IDS: "",
        APP_ATTEST_ALLOW_DEV: "",
        HANDLE_TTL_MS: "",
        CHALLENGE_TTL_MS: "",
        RATE_LIMIT_WINDOW_MS: "",
        CHALLENGE_RATE_LIMIT_MAX: "",
        REGISTER_RATE_LIMIT_MAX: "",
        SEND_RATE_LIMIT_MAX: "",
        APPLE_RECEIPT_SECRET: "",
      }),
    );

    expect(config.allowedBundleIds).toEqual(["ai.openclaw.client"]);
    expect(config.appAttestAllowDevelopment).toBe(false);
    expect(config.handleTtlMs).toBe(30 * 24 * 60 * 60 * 1000);
    expect(config.challengeTtlMs).toBe(5 * 60 * 1000);
    expect(config.rateLimitWindowMs).toBe(60 * 1000);
    expect(config.challengeRateLimitMax).toBe(30);
    expect(config.registerRateLimitMax).toBe(10);
    expect(config.sendRateLimitMax).toBe(120);
    expect(config.appleReceiptSharedSecret).toBeUndefined();
  });

  it("normalizes quoted APNS_P8 values", () => {
    const config = loadRelayConfig(
      makeEnv({
        APNS_P8: "\"-----BEGIN PRIVATE KEY-----\\nsecret\\n-----END PRIVATE KEY-----\"",
      }),
    );

    expect(config.apnsPrivateKey).toBe("-----BEGIN PRIVATE KEY-----\nsecret\n-----END PRIVATE KEY-----");
  });

  it("throws when a required environment variable is missing", () => {
    expect(() => loadRelayConfig(makeEnv({ RELAY_ENC_KEY: "" }))).toThrow(
      "missing required environment variable RELAY_ENC_KEY",
    );
  });

  it("throws when numeric values are invalid", () => {
    expect(() => loadRelayConfig(makeEnv({ SEND_RATE_LIMIT_MAX: "0" }))).toThrow(
      "invalid numeric environment variable SEND_RATE_LIMIT_MAX",
    );
  });
});
