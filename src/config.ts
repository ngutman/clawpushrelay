import fs from "node:fs/promises";
import path from "node:path";

export type RelayConfig = {
  host: string;
  port: number;
  trustProxy: boolean | string[];
  stateDir: string;
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

function readTrustProxy(env: NodeJS.ProcessEnv): boolean | string[] {
  const raw = env.CLAWPUSHRELAY_TRUST_PROXY?.trim();
  if (!raw) {
    return false;
  }
  const normalized = raw.toLowerCase();
  if (normalized === "1" || normalized === "true" || normalized === "yes") {
    return true;
  }
  if (normalized === "0" || normalized === "false" || normalized === "no") {
    return false;
  }
  return raw
    .split(",")
    .map((value) => value.trim())
    .filter(Boolean);
}

async function resolvePrivateKey(env: NodeJS.ProcessEnv): Promise<string> {
  const inline = readOptionalString("CLAWPUSHRELAY_APNS_PRIVATE_KEY_P8", env);
  if (inline) {
    return inline.replace(/\\n/g, "\n");
  }
  const keyPath = readOptionalString("CLAWPUSHRELAY_APNS_PRIVATE_KEY_PATH", env);
  if (!keyPath) {
    throw new Error(
      "missing APNs private key: set CLAWPUSHRELAY_APNS_PRIVATE_KEY_P8 or CLAWPUSHRELAY_APNS_PRIVATE_KEY_PATH",
    );
  }
  const file = await fs.readFile(path.resolve(keyPath), "utf8");
  return file.trim();
}

export async function loadRelayConfig(
  env: NodeJS.ProcessEnv = process.env,
): Promise<RelayConfig> {
  return {
    host: env.CLAWPUSHRELAY_HOST?.trim() || "127.0.0.1",
    port: readNumber("CLAWPUSHRELAY_PORT", env, 8787),
    trustProxy: readTrustProxy(env),
    stateDir: path.resolve(env.CLAWPUSHRELAY_STATE_DIR?.trim() || "./data"),
    encryptionKey: readString("CLAWPUSHRELAY_ENCRYPTION_KEY", env),
    gatewayBearerToken: readString("CLAWPUSHRELAY_GATEWAY_BEARER_TOKEN", env),
    allowedBundleIds: (env.CLAWPUSHRELAY_ALLOWED_BUNDLE_IDS?.trim() || "ai.openclaw.client")
      .split(",")
      .map((value) => value.trim())
      .filter(Boolean),
    appleTeamId: readString("CLAWPUSHRELAY_APPLE_TEAM_ID", env),
    appAttestAllowDevelopment: readBoolean(
      "CLAWPUSHRELAY_APP_ATTEST_ALLOW_DEVELOPMENT",
      env,
      false,
    ),
    handleTtlMs: readNumber("CLAWPUSHRELAY_HANDLE_TTL_MS", env, 30 * 24 * 60 * 60 * 1000),
    challengeTtlMs: readNumber("CLAWPUSHRELAY_CHALLENGE_TTL_MS", env, 5 * 60 * 1000),
    rateLimitWindowMs: readNumber("CLAWPUSHRELAY_RATE_LIMIT_WINDOW_MS", env, 60 * 1000),
    challengeRateLimitMax: readNumber("CLAWPUSHRELAY_CHALLENGE_RATE_LIMIT_MAX", env, 30),
    registerRateLimitMax: readNumber("CLAWPUSHRELAY_REGISTER_RATE_LIMIT_MAX", env, 10),
    sendRateLimitMax: readNumber("CLAWPUSHRELAY_SEND_RATE_LIMIT_MAX", env, 120),
    apnsTeamId: readString("CLAWPUSHRELAY_APNS_TEAM_ID", env),
    apnsKeyId: readString("CLAWPUSHRELAY_APNS_KEY_ID", env),
    apnsPrivateKey: await resolvePrivateKey(env),
    appleReceiptSharedSecret: readOptionalString(
      "CLAWPUSHRELAY_APPLE_RECEIPT_SHARED_SECRET",
      env,
    ),
  };
}
