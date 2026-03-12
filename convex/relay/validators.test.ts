import { describe, expect, it } from "vitest";
import {
  parseRegisterRequest,
  parseSendRequest,
  validatePushPayload,
} from "./validators.js";
import type { SendRequestBody } from "./types.js";

function makeSendBody(overrides: Partial<SendRequestBody> = {}): SendRequestBody {
  return {
    relayHandle: "relay-handle",
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
    ...overrides,
  };
}

describe("request validators", () => {
  it("accepts a valid register payload", () => {
    const body = parseRegisterRequest({
      challengeId: "challenge-1",
      installationId: "install-1",
      bundleId: "ai.openclaw.client",
      environment: "production",
      distribution: "official",
      appVersion: "1.0.0",
      apnsToken: "1234567890abcdef1234567890abcdef",
      appAttest: {
        keyId: "key-1",
        assertion: "assertion",
        clientDataHash: "client-hash",
        signedPayloadBase64: "payload",
        attestationObject: "attestation",
      },
      receipt: {
        base64: "receipt",
      },
    });

    expect(body.bundleId).toBe("ai.openclaw.client");
  });

  it("rejects invalid register payloads", () => {
    expect(() =>
      parseRegisterRequest({
        challengeId: "challenge-1",
        installationId: "install-1",
        bundleId: "ai.openclaw.client",
        environment: "sandbox",
        distribution: "official",
        appVersion: "1.0.0",
        apnsToken: "not-a-token",
        appAttest: {
          keyId: "key-1",
          assertion: "assertion",
          clientDataHash: "client-hash",
          signedPayloadBase64: "payload",
        },
        receipt: {
          base64: "receipt",
        },
      }),
    ).toThrow();
  });

  it("accepts a valid send payload", () => {
    const body = parseSendRequest(makeSendBody());
    expect(validatePushPayload(body)).toBeNull();
  });

  it("rejects invalid push payload shapes", () => {
    expect(
      validatePushPayload(
        makeSendBody({
          payload: {},
        }),
      ),
    ).toBe("payload.aps is required");

    expect(
      validatePushPayload(
        makeSendBody({
          pushType: "background",
          priority: 10,
          payload: {
            aps: {
              "content-available": 1,
            },
          },
        }),
      ),
    ).toBe("background pushes must use priority 5");

    expect(
      validatePushPayload(
        makeSendBody({
          payload: {
            aps: {},
          },
        }),
      ),
    ).toBe("alert push payload must include aps.alert");
  });
});
