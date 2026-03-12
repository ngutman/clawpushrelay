import { defineSchema, defineTable } from "convex/server";
import { v } from "convex/values";

const challenges = defineTable({
  challengeId: v.string(),
  challenge: v.string(),
  createdAtMs: v.number(),
  expiresAtMs: v.number(),
  consumedAtMs: v.optional(v.number()),
})
  .index("by_challenge_id", ["challengeId"])
  .index("by_expires_at", ["expiresAtMs"]);

const appAttestKeys = defineTable({
  keyId: v.string(),
  installationId: v.string(),
  bundleId: v.string(),
  environment: v.literal("production"),
  publicKey: v.string(),
  signCount: v.number(),
  attestedAtMs: v.number(),
  lastAssertedAtMs: v.number(),
  revokedAtMs: v.optional(v.number()),
})
  .index("by_key_id", ["keyId"])
  .index("by_installation_bundle_environment", ["installationId", "bundleId", "environment"]);

const registrations = defineTable({
  registrationId: v.string(),
  installationId: v.string(),
  bundleId: v.string(),
  environment: v.literal("production"),
  distribution: v.literal("official"),
  apnsTopic: v.string(),
  apnsTokenCiphertext: v.string(),
  apnsTokenHash: v.string(),
  tokenSuffix: v.string(),
  relayHandleHash: v.string(),
  relayHandleExpiresAtMs: v.number(),
  appAttestKeyId: v.string(),
  proofType: v.literal("receipt"),
  receiptEnvironment: v.string(),
  appVersion: v.string(),
  status: v.union(v.literal("active"), v.literal("stale"), v.literal("revoked")),
  createdAtMs: v.number(),
  updatedAtMs: v.number(),
  lastRegisteredAtMs: v.number(),
  lastSentAtMs: v.optional(v.number()),
  lastApnsStatus: v.optional(v.number()),
  lastApnsReason: v.optional(v.string()),
})
  .index("by_relay_handle_hash", ["relayHandleHash"])
  .index("by_installation_bundle_environment_status", [
    "installationId",
    "bundleId",
    "environment",
    "status",
  ])
  .index("by_app_attest_key_id", ["appAttestKeyId"])
  .index("by_handle_expiry", ["relayHandleExpiresAtMs"]);

const rateLimitEvents = defineTable({
  scope: v.union(v.literal("challenge"), v.literal("register"), v.literal("send")),
  subjectHash: v.string(),
  createdAtMs: v.number(),
  expiresAtMs: v.number(),
})
  .index("by_scope_subject_created_at", ["scope", "subjectHash", "createdAtMs"])
  .index("by_expires_at", ["expiresAtMs"]);

export default defineSchema({
  challenges,
  app_attest_keys: appAttestKeys,
  registrations,
  rate_limit_events: rateLimitEvents,
});
