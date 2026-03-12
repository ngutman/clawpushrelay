export type RelayConfig = {
  encryptionKey: string;
  gatewayBearerToken: string;
  allowedBundleIds: string[];
  appleTeamId: string;
  appAttestAllowDevelopment: boolean;
  handleTtlMs: number;
  challengeTtlMs: number;
  rateLimitWindowMs: number;
  challengeRateLimitMax: number;
  registerRateLimitMax: number;
  sendRateLimitMax: number;
  apnsTeamId: string;
  apnsKeyId: string;
  apnsPrivateKey: string;
  appleReceiptSharedSecret?: string;
};

function readString(name: string, env: NodeJS.ProcessEnv): string {
  const value = env[name]?.trim();
  if (!value) {
    throw new Error(`missing required environment variable ${name}`);
  }
  return value;
}

function readOptionalString(name: string, env: NodeJS.ProcessEnv): string | undefined {
  const value = env[name]?.trim();
  return value ? value : undefined;
}

function readNumber(name: string, env: NodeJS.ProcessEnv, fallback: number): number {
  const raw = env[name]?.trim();
  if (!raw) {
    return fallback;
  }
  const parsed = Number(raw);
  if (!Number.isFinite(parsed) || parsed <= 0) {
    throw new Error(`invalid numeric environment variable ${name}`);
  }
  return Math.trunc(parsed);
}

function readBoolean(name: string, env: NodeJS.ProcessEnv, fallback: boolean): boolean {
  const raw = env[name]?.trim().toLowerCase();
  if (!raw) {
    return fallback;
  }
  return raw === "1" || raw === "true" || raw === "yes";
}

function readStringList(name: string, env: NodeJS.ProcessEnv, fallback: string[]): string[] {
  const raw = env[name]?.trim();
  if (!raw) {
    return fallback;
  }
  const values = raw
    .split(",")
    .map((value) => value.trim())
    .filter(Boolean);
  if (values.length === 0) {
    throw new Error(`invalid list environment variable ${name}`);
  }
  return values;
}

function normalizePrivateKey(raw: string): string {
  return raw.replace(/\\n/g, "\n");
}

export function loadRelayConfig(env: NodeJS.ProcessEnv = process.env): RelayConfig {
  return {
    encryptionKey: readString("RELAY_ENC_KEY", env),
    gatewayBearerToken: readString("RELAY_GATEWAY_TOKEN", env),
    allowedBundleIds: readStringList("RELAY_ALLOWED_BUNDLE_IDS", env, ["ai.openclaw.client"]),
    appleTeamId: readString("APPLE_TEAM_ID", env),
    appAttestAllowDevelopment: readBoolean("APP_ATTEST_ALLOW_DEV", env, false),
    handleTtlMs: readNumber("HANDLE_TTL_MS", env, 30 * 24 * 60 * 60 * 1000),
    challengeTtlMs: readNumber("CHALLENGE_TTL_MS", env, 5 * 60 * 1000),
    rateLimitWindowMs: readNumber("RATE_LIMIT_WINDOW_MS", env, 60 * 1000),
    challengeRateLimitMax: readNumber("CHALLENGE_RATE_LIMIT_MAX", env, 30),
    registerRateLimitMax: readNumber("REGISTER_RATE_LIMIT_MAX", env, 10),
    sendRateLimitMax: readNumber("SEND_RATE_LIMIT_MAX", env, 120),
    apnsTeamId: readString("APNS_TEAM_ID", env),
    apnsKeyId: readString("APNS_KEY_ID", env),
    apnsPrivateKey: normalizePrivateKey(readString("APNS_P8", env)),
    appleReceiptSharedSecret: readOptionalString("APPLE_RECEIPT_SECRET", env),
  };
}
