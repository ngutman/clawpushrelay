export type Distribution = "official";

export type PushEnvironment = "production";

export type PushType = "alert" | "background";

export type RegistrationStatus = "active" | "stale" | "revoked";

export type ChallengeRecord = {
  challengeId: string;
  challenge: string;
  createdAtMs: number;
  expiresAtMs: number;
};

export type AppAttestRecord = {
  keyId: string;
  installationId: string;
  bundleId: string;
  environment: PushEnvironment;
  publicKey: string;
  signCount: number;
  attestedAtMs: number;
  lastAssertedAtMs: number;
  revokedAtMs?: number;
};

export type RelayRegistrationRecord = {
  registrationId: string;
  installationId: string;
  bundleId: string;
  environment: PushEnvironment;
  distribution: Distribution;
  apnsTopic: string;
  apnsTokenCiphertext: string;
  apnsTokenHash: string;
  tokenSuffix: string;
  relayHandleHash: string;
  relayHandleExpiresAtMs: number;
  appAttestKeyId: string;
  proofType: "receipt";
  receiptEnvironment: string;
  appVersion: string;
  status: RegistrationStatus;
  createdAtMs: number;
  updatedAtMs: number;
  lastRegisteredAtMs: number;
  lastSentAtMs?: number;
  lastApnsStatus?: number;
  lastApnsReason?: string;
};

export type RelayState = {
  version: 1;
  appAttestKeysById: Record<string, AppAttestRecord>;
  registrationsByHandleHash: Record<string, RelayRegistrationRecord>;
};

export type RegisterRequestBody = {
  challengeId: string;
  installationId: string;
  bundleId: string;
  environment: PushEnvironment;
  distribution: Distribution;
  appVersion: string;
  apnsToken: string;
  appAttest: {
    keyId: string;
    attestationObject?: string;
    assertion: string;
    clientDataHash: string;
    signedPayloadBase64: string;
  };
  receipt: {
    base64: string;
  };
};

export type RegisterResponseBody = {
  relayHandle: string;
  expiresAtMs: number;
  tokenSuffix: string;
  status: "active";
};

export type SendRequestBody = {
  relayHandle: string;
  pushType: PushType;
  priority: 5 | 10;
  payload: Record<string, unknown>;
};

export type RelaySendResult = {
  ok: boolean;
  status: number;
  apnsId?: string;
  reason?: string;
  environment: PushEnvironment;
  tokenSuffix: string;
};

export type AppAttestVerificationResult = {
  keyId: string;
  publicKey: string;
  signCount: number;
  attestedAtMs?: number;
};

export type ReceiptVerificationResult = {
  environment: string;
  bundleId: string;
  validatedAtMs: number;
};
