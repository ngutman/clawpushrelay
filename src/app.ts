import Fastify from "fastify";
import { AppAttestVerifier } from "./app-attest.js";
import { ApnsSender } from "./apns.js";
import { ChallengeStore } from "./challenges.js";
import type { RelayConfig } from "./config.js";
import { parseEncryptionKey } from "./crypto.js";
import { SlidingWindowRateLimiter } from "./rate-limit.js";
import { ReceiptVerifier } from "./receipt.js";
import { registerRelayRoutes } from "./routes.js";
import { RelayStateStore } from "./state-store.js";

export async function createRelayApp(config: RelayConfig) {
  const stateStore = new RelayStateStore(config.stateDir, parseEncryptionKey(config.encryptionKey));
  await stateStore.ensureReady();

  const fastify = Fastify({
    logger: true,
    trustProxy: config.trustProxy,
  });

  const challengeStore = new ChallengeStore(config.challengeTtlMs);
  const rateLimiter = new SlidingWindowRateLimiter(config.rateLimitWindowMs);
  const appAttestVerifier = new AppAttestVerifier(stateStore, {
    teamId: config.appleTeamId,
    allowDevelopmentEnvironment: config.appAttestAllowDevelopment,
  });
  const receiptVerifier = new ReceiptVerifier({
    sharedSecret: config.appleReceiptSharedSecret,
  });
  const apnsSender = new ApnsSender({
    teamId: config.apnsTeamId,
    keyId: config.apnsKeyId,
    privateKey: config.apnsPrivateKey,
  });

  await fastify.register(
    registerRelayRoutes({
      config,
      stateStore,
      challengeStore,
      rateLimiter,
      appAttestVerifier,
      receiptVerifier,
      apnsSender,
    }),
  );

  fastify.get("/healthz", async () => ({ ok: true }));
  return fastify;
}
