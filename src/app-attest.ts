import { verifyAssertion, verifyAttestation } from "node-app-attest";
import { encodeSha256Base64Url } from "./crypto.js";
import { RelayStateStore } from "./state-store.js";
import type { AppAttestVerificationResult, RegisterRequestBody } from "./types.js";

export class AppAttestVerificationError extends Error {}

export class AppAttestVerifier {
  constructor(
    private readonly store: RelayStateStore,
    private readonly options: {
      teamId: string;
      allowDevelopmentEnvironment: boolean;
    },
    private readonly now: () => number = () => Date.now(),
  ) {}

  async verifyRegistration(params: {
    challenge: string;
    request: RegisterRequestBody;
  }): Promise<AppAttestVerificationResult> {
    const payloadBuffer = Buffer.from(params.request.appAttest.signedPayloadBase64, "base64");
    const payload = payloadBuffer.toString("utf8");
    const expectedClientDataHash = encodeSha256Base64Url(payload);
    if (expectedClientDataHash !== params.request.appAttest.clientDataHash) {
      throw new AppAttestVerificationError("clientDataHash does not match request payload");
    }
    let parsedPayload: Partial<{
      challengeId: string;
      installationId: string;
      bundleId: string;
      environment: string;
      distribution: string;
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
      parsedPayload.appVersion !== params.request.appVersion ||
      parsedPayload.apnsToken?.trim().toLowerCase() !== params.request.apnsToken.trim().toLowerCase()
    ) {
      throw new AppAttestVerificationError("signed payload does not match registration request");
    }

    const existing = await this.store.getAppAttestRecord(params.request.appAttest.keyId);
    let publicKey: string;
    let signCount: number;

    if (!existing) {
      const attestationObject = params.request.appAttest.attestationObject;
      if (!attestationObject) {
        throw new AppAttestVerificationError("attestationObject is required for new App Attest keys");
      }
      const verified = verifyAttestation({
        attestation: Buffer.from(attestationObject, "base64"),
        challenge: params.challenge,
        keyId: params.request.appAttest.keyId,
        bundleIdentifier: params.request.bundleId,
        teamIdentifier: this.options.teamId,
        allowDevelopmentEnvironment: this.options.allowDevelopmentEnvironment,
      });
      publicKey = verified.publicKey;
      signCount = 0;
    } else {
      if (
        existing.installationId !== params.request.installationId ||
        existing.bundleId !== params.request.bundleId ||
        existing.environment !== params.request.environment ||
        existing.revokedAtMs
      ) {
        throw new AppAttestVerificationError("App Attest key binding mismatch");
      }
      publicKey = existing.publicKey;
      signCount = existing.signCount;
    }

    const assertion = verifyAssertion({
      assertion: Buffer.from(params.request.appAttest.assertion, "base64"),
      payload,
      publicKey,
      bundleIdentifier: params.request.bundleId,
      teamIdentifier: this.options.teamId,
      signCount,
    });

    const nowMs = this.now();
    await this.store.upsertAppAttestRecord({
      keyId: params.request.appAttest.keyId,
      installationId: params.request.installationId,
      bundleId: params.request.bundleId,
      environment: params.request.environment,
      publicKey,
      signCount: assertion.signCount,
      attestedAtMs: existing?.attestedAtMs ?? nowMs,
      lastAssertedAtMs: nowMs,
      revokedAtMs: existing?.revokedAtMs,
    });

    return {
      keyId: params.request.appAttest.keyId,
      publicKey,
      signCount: assertion.signCount,
      attestedAtMs: existing ? existing.attestedAtMs : nowMs,
    };
  }
}
