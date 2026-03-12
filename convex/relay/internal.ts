import { internalMutationGeneric, internalQueryGeneric } from "convex/server";
import { v } from "convex/values";
import type {
  AppAttestRecord,
  ChallengeRecord,
  RateLimitScope,
  RegistrationStatus,
  RelayRegistrationRecord,
} from "./types.js";

const internalMutation = internalMutationGeneric;
const internalQuery = internalQueryGeneric;

const rateLimitScopeValidator = v.union(
  v.literal("challenge"),
  v.literal("register"),
  v.literal("send"),
);

const registrationStatusValidator = v.union(
  v.literal("active"),
  v.literal("stale"),
  v.literal("revoked"),
);

const challengeRecordValidator = v.object({
  challengeId: v.string(),
  challenge: v.string(),
  createdAtMs: v.number(),
  expiresAtMs: v.number(),
  consumedAtMs: v.optional(v.number()),
});

const appAttestRecordValidator = v.object({
  keyId: v.string(),
  installationId: v.string(),
  bundleId: v.string(),
  environment: v.literal("production"),
  publicKey: v.string(),
  signCount: v.number(),
  attestedAtMs: v.number(),
  lastAssertedAtMs: v.number(),
  revokedAtMs: v.optional(v.number()),
});

const registrationRecordValidator = v.object({
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
  status: registrationStatusValidator,
  createdAtMs: v.number(),
  updatedAtMs: v.number(),
  lastRegisteredAtMs: v.number(),
  lastSentAtMs: v.optional(v.number()),
  lastApnsStatus: v.optional(v.number()),
  lastApnsReason: v.optional(v.string()),
});

type RegistrationPatch = Partial<RelayRegistrationRecord>;

type MutableChallengeRecord = ChallengeRecord;
type MutableRegistrationRecord = RelayRegistrationRecord;
type StoredDoc<T> = T & { _id: any };
type RateLimitEvent = {
  scope: RateLimitScope;
  subjectHash: string;
  createdAtMs: number;
  expiresAtMs: number;
};

export function buildChallengeRecord(params: {
  challengeId: string;
  challenge: string;
  nowMs: number;
  ttlMs: number;
}): ChallengeRecord {
  return {
    challengeId: params.challengeId,
    challenge: params.challenge,
    createdAtMs: params.nowMs,
    expiresAtMs: params.nowMs + params.ttlMs,
  };
}

export function consumeChallengeRecord(
  record: ChallengeRecord | null,
  nowMs: number,
): {
  consumed: boolean;
  record: MutableChallengeRecord | null;
} {
  if (!record) {
    return { consumed: false, record: null };
  }
  if (record.consumedAtMs !== undefined || record.expiresAtMs <= nowMs) {
    return { consumed: false, record };
  }
  return {
    consumed: true,
    record: {
      ...record,
      consumedAtMs: nowMs,
    },
  };
}

export function consumeRateLimit(
  events: RateLimitEvent[],
  params: {
    scope: RateLimitScope;
    subjectHash: string;
    nowMs: number;
    windowMs: number;
    limit: number;
  },
): {
  allowed: boolean;
  remaining: number;
  nextEvent?: RateLimitEvent;
} {
  const cutoff = params.nowMs - params.windowMs;
  const activeEvents = events.filter(
    (event) =>
      event.scope === params.scope &&
      event.subjectHash === params.subjectHash &&
      event.createdAtMs > cutoff,
  );
  if (activeEvents.length >= params.limit) {
    return {
      allowed: false,
      remaining: 0,
    };
  }
  return {
    allowed: true,
    remaining: Math.max(0, params.limit - activeEvents.length - 1),
    nextEvent: {
      scope: params.scope,
      subjectHash: params.subjectHash,
      createdAtMs: params.nowMs,
      expiresAtMs: params.nowMs + params.windowMs,
    },
  };
}

export function buildRegistrationPatchesForInsert(
  existing: RelayRegistrationRecord[],
  next: RelayRegistrationRecord,
): {
  stalePatches: Array<{
    relayHandleHash: string;
    patch: RegistrationPatch;
  }>;
  nextRecord: RelayRegistrationRecord;
} {
  const stalePatches = existing
    .filter(
      (record) =>
        record.installationId === next.installationId &&
        record.bundleId === next.bundleId &&
        record.environment === next.environment &&
        record.status === "active",
    )
    .map((record) => ({
      relayHandleHash: record.relayHandleHash,
      patch: {
        status: "stale" as RegistrationStatus,
        updatedAtMs: next.updatedAtMs,
      },
    }));

  return {
    stalePatches,
    nextRecord: next,
  };
}

export function expireRegistrationIfNeeded(
  record: RelayRegistrationRecord | null,
  nowMs: number,
): {
  expired: boolean;
  record: MutableRegistrationRecord | null;
} {
  if (!record) {
    return { expired: false, record: null };
  }
  if (record.status !== "active" || record.relayHandleExpiresAtMs > nowMs) {
    return { expired: false, record };
  }
  return {
    expired: true,
    record: {
      ...record,
      status: "stale",
      updatedAtMs: nowMs,
      lastApnsReason: "expired",
    },
  };
}

export function applySendResultToRegistration(
  record: RelayRegistrationRecord | null,
  params: {
    status: number;
    reason?: string;
    nowMs: number;
  },
): MutableRegistrationRecord | null {
  if (!record) {
    return null;
  }
  const next: MutableRegistrationRecord = {
    ...record,
    lastSentAtMs: params.nowMs,
    lastApnsStatus: params.status,
    lastApnsReason: params.reason,
    updatedAtMs: params.nowMs,
  };
  if (params.status === 410 || (params.status === 400 && params.reason === "BadDeviceToken")) {
    next.status = "stale";
  }
  return next;
}

export const issueChallengeInternal = internalMutation({
  args: {
    challengeId: v.string(),
    challenge: v.string(),
    nowMs: v.number(),
    ttlMs: v.number(),
  },
  handler: async (ctx, args) => {
    const record = buildChallengeRecord(args);
    await ctx.db.insert("challenges", record);
    return record;
  },
});

export const consumeChallengeInternal = internalMutation({
  args: {
    challengeId: v.string(),
    nowMs: v.number(),
  },
  handler: async (ctx, args) => {
    const current = (await ctx.db
      .query("challenges")
      .withIndex("by_challenge_id", (q) => q.eq("challengeId", args.challengeId))
      .unique()) as StoredDoc<ChallengeRecord> | null;

    const result = consumeChallengeRecord(current, args.nowMs);
    if (!result.consumed || !current || !result.record) {
      return null;
    }
    await ctx.db.patch(current._id, {
      consumedAtMs: result.record.consumedAtMs,
    });
    return result.record;
  },
});

export const consumeRateLimitInternal = internalMutation({
  args: {
    scope: rateLimitScopeValidator,
    subjectHash: v.string(),
    nowMs: v.number(),
    windowMs: v.number(),
    limit: v.number(),
  },
  handler: async (ctx, args) => {
    const cutoff = args.nowMs - args.windowMs;
    const activeEvents = ((await ctx.db
      .query("rate_limit_events")
      .withIndex("by_scope_subject_created_at", (q) => q.eq("scope", args.scope))
      .collect()) as RateLimitEvent[]).filter(
      (event) => event.subjectHash === args.subjectHash && event.createdAtMs > cutoff,
    );

    const result = consumeRateLimit(activeEvents, args);
    if (!result.allowed || !result.nextEvent) {
      return result;
    }
    await ctx.db.insert("rate_limit_events", result.nextEvent);
    return result;
  },
});

export const issueChallengeAndConsumeRateLimitInternal = internalMutation({
  args: {
    challengeId: v.string(),
    challenge: v.string(),
    subjectHash: v.string(),
    nowMs: v.number(),
    ttlMs: v.number(),
    windowMs: v.number(),
    limit: v.number(),
  },
  handler: async (ctx, args) => {
    const cutoff = args.nowMs - args.windowMs;
    const activeEvents = ((await ctx.db
      .query("rate_limit_events")
      .withIndex("by_scope_subject_created_at", (q) => q.eq("scope", "challenge"))
      .collect()) as RateLimitEvent[]).filter(
      (event) => event.subjectHash === args.subjectHash && event.createdAtMs > cutoff,
    );
    const rateLimit = consumeRateLimit(activeEvents, {
      scope: "challenge",
      subjectHash: args.subjectHash,
      nowMs: args.nowMs,
      windowMs: args.windowMs,
      limit: args.limit,
    });
    if (!rateLimit.allowed || !rateLimit.nextEvent) {
      return {
        allowed: false,
        remaining: rateLimit.remaining,
        challenge: null,
      };
    }

    await ctx.db.insert("rate_limit_events", rateLimit.nextEvent);
    const challengeRecord = buildChallengeRecord({
      challengeId: args.challengeId,
      challenge: args.challenge,
      nowMs: args.nowMs,
      ttlMs: args.ttlMs,
    });
    await ctx.db.insert("challenges", challengeRecord);

    return {
      allowed: true,
      remaining: rateLimit.remaining,
      challenge: challengeRecord,
    };
  },
});

export const consumeChallengeAndRegisterRateLimitInternal = internalMutation({
  args: {
    challengeId: v.string(),
    subjectHash: v.string(),
    nowMs: v.number(),
    windowMs: v.number(),
    limit: v.number(),
  },
  handler: async (ctx, args) => {
    const cutoff = args.nowMs - args.windowMs;
    const activeEvents = ((await ctx.db
      .query("rate_limit_events")
      .withIndex("by_scope_subject_created_at", (q) => q.eq("scope", "register"))
      .collect()) as RateLimitEvent[]).filter(
      (event) => event.subjectHash === args.subjectHash && event.createdAtMs > cutoff,
    );
    const rateLimit = consumeRateLimit(activeEvents, {
      scope: "register",
      subjectHash: args.subjectHash,
      nowMs: args.nowMs,
      windowMs: args.windowMs,
      limit: args.limit,
    });
    if (!rateLimit.allowed || !rateLimit.nextEvent) {
      return {
        allowed: false,
        remaining: rateLimit.remaining,
        challenge: null,
      };
    }

    await ctx.db.insert("rate_limit_events", rateLimit.nextEvent);

    const current = (await ctx.db
      .query("challenges")
      .withIndex("by_challenge_id", (q) => q.eq("challengeId", args.challengeId))
      .unique()) as StoredDoc<ChallengeRecord> | null;
    const consumed = consumeChallengeRecord(current, args.nowMs);
    if (!consumed.consumed || !current || !consumed.record) {
      return {
        allowed: true,
        remaining: rateLimit.remaining,
        challenge: null,
      };
    }

    await ctx.db.patch(current._id, {
      consumedAtMs: consumed.record.consumedAtMs,
    });
    return {
      allowed: true,
      remaining: rateLimit.remaining,
      challenge: consumed.record,
    };
  },
});

export const consumeSendRateLimitInternal = internalMutation({
  args: {
    subjectHash: v.string(),
    nowMs: v.number(),
    windowMs: v.number(),
    limit: v.number(),
  },
  handler: async (ctx, args) => {
    const cutoff = args.nowMs - args.windowMs;
    const activeEvents = ((await ctx.db
      .query("rate_limit_events")
      .withIndex("by_scope_subject_created_at", (q) => q.eq("scope", "send"))
      .collect()) as RateLimitEvent[]).filter(
      (event) => event.subjectHash === args.subjectHash && event.createdAtMs > cutoff,
    );
    const result = consumeRateLimit(activeEvents, {
      scope: "send",
      subjectHash: args.subjectHash,
      nowMs: args.nowMs,
      windowMs: args.windowMs,
      limit: args.limit,
    });
    if (!result.allowed || !result.nextEvent) {
      return result;
    }
    await ctx.db.insert("rate_limit_events", result.nextEvent);
    return result;
  },
});

export const getAppAttestKeyByKeyIdInternal = internalQuery({
  args: {
    keyId: v.string(),
  },
  handler: async (ctx, args) => {
    return (await ctx.db
      .query("app_attest_keys")
      .withIndex("by_key_id", (q) => q.eq("keyId", args.keyId))
      .unique()) as AppAttestRecord | null;
  },
});

export const upsertAppAttestKeyInternal = internalMutation({
  args: {
    record: appAttestRecordValidator,
  },
  handler: async (ctx, args) => {
    const existing = (await ctx.db
      .query("app_attest_keys")
      .withIndex("by_key_id", (q) => q.eq("keyId", args.record.keyId))
      .unique()) as StoredDoc<AppAttestRecord> | null;
    if (!existing) {
      await ctx.db.insert("app_attest_keys", args.record);
      return args.record;
    }
    await ctx.db.patch(existing._id, args.record);
    return args.record;
  },
});

export const upsertRegistrationInternal = internalMutation({
  args: {
    record: registrationRecordValidator,
  },
  handler: async (ctx, args) => {
    const active = ((await ctx.db
      .query("registrations")
      .withIndex("by_installation_bundle_environment_status", (q) =>
        q.eq("installationId", args.record.installationId),
      )
      .collect()) as Array<StoredDoc<RelayRegistrationRecord>>).filter(
      (record) =>
        record.bundleId === args.record.bundleId &&
        record.environment === args.record.environment &&
        record.status === "active",
    );

    const patches = buildRegistrationPatchesForInsert(active, args.record);
    for (const item of patches.stalePatches) {
      const existing = active.find((record) => record.relayHandleHash === item.relayHandleHash);
      if (!existing) {
        continue;
      }
      await ctx.db.patch(existing._id, item.patch);
    }

    await ctx.db.insert("registrations", patches.nextRecord);
    return {
      staleCount: patches.stalePatches.length,
      record: patches.nextRecord,
    };
  },
});

export const applyVerifiedRegistrationInternal = internalMutation({
  args: {
    appAttestRecord: appAttestRecordValidator,
    registrationRecord: registrationRecordValidator,
  },
  handler: async (ctx, args) => {
    const existingKey = (await ctx.db
      .query("app_attest_keys")
      .withIndex("by_key_id", (q) => q.eq("keyId", args.appAttestRecord.keyId))
      .unique()) as StoredDoc<AppAttestRecord> | null;
    if (!existingKey) {
      await ctx.db.insert("app_attest_keys", args.appAttestRecord);
    } else {
      await ctx.db.patch(existingKey._id, args.appAttestRecord);
    }

    const active = ((await ctx.db
      .query("registrations")
      .withIndex("by_installation_bundle_environment_status", (q) =>
        q.eq("installationId", args.registrationRecord.installationId),
      )
      .collect()) as Array<StoredDoc<RelayRegistrationRecord>>).filter(
      (record) =>
        record.bundleId === args.registrationRecord.bundleId &&
        record.environment === args.registrationRecord.environment &&
        record.status === "active",
    );
    const patches = buildRegistrationPatchesForInsert(active, args.registrationRecord);
    for (const item of patches.stalePatches) {
      const existing = active.find((record) => record.relayHandleHash === item.relayHandleHash);
      if (!existing) {
        continue;
      }
      await ctx.db.patch(existing._id, item.patch);
    }

    await ctx.db.insert("registrations", patches.nextRecord);
    return {
      staleCount: patches.stalePatches.length,
      appAttestRecord: args.appAttestRecord,
      registrationRecord: patches.nextRecord,
    };
  },
});

export const getRegistrationByRelayHandleHashInternal = internalQuery({
  args: {
    relayHandleHash: v.string(),
  },
  handler: async (ctx, args) => {
    return (await ctx.db
      .query("registrations")
      .withIndex("by_relay_handle_hash", (q) => q.eq("relayHandleHash", args.relayHandleHash))
      .unique()) as RelayRegistrationRecord | null;
  },
});

export const expireRegistrationIfNeededInternal = internalMutation({
  args: {
    relayHandleHash: v.string(),
    nowMs: v.number(),
  },
  handler: async (ctx, args) => {
    const current = (await ctx.db
      .query("registrations")
      .withIndex("by_relay_handle_hash", (q) => q.eq("relayHandleHash", args.relayHandleHash))
      .unique()) as StoredDoc<RelayRegistrationRecord> | null;

    const result = expireRegistrationIfNeeded(current, args.nowMs);
    if (!result.expired || !current || !result.record) {
      return result.record;
    }
    await ctx.db.patch(current._id, {
      status: result.record.status,
      updatedAtMs: result.record.updatedAtMs,
      lastApnsReason: result.record.lastApnsReason,
    });
    return result.record;
  },
});

export const markRegistrationStatusInternal = internalMutation({
  args: {
    relayHandleHash: v.string(),
    status: registrationStatusValidator,
    nowMs: v.number(),
    reason: v.optional(v.string()),
  },
  handler: async (ctx, args) => {
    const current = (await ctx.db
      .query("registrations")
      .withIndex("by_relay_handle_hash", (q) => q.eq("relayHandleHash", args.relayHandleHash))
      .unique()) as StoredDoc<RelayRegistrationRecord> | null;
    if (!current) {
      return null;
    }
    await ctx.db.patch(current._id, {
      status: args.status,
      updatedAtMs: args.nowMs,
      lastApnsReason: args.reason ?? current.lastApnsReason,
    });
    return {
      ...current,
      status: args.status,
      updatedAtMs: args.nowMs,
      lastApnsReason: args.reason ?? current.lastApnsReason,
    };
  },
});

export const recordSendResultInternal = internalMutation({
  args: {
    relayHandleHash: v.string(),
    result: v.object({
      ok: v.boolean(),
      status: v.number(),
      apnsId: v.optional(v.string()),
      reason: v.optional(v.string()),
      environment: v.literal("production"),
      tokenSuffix: v.string(),
    }),
    nowMs: v.number(),
  },
  handler: async (ctx, args) => {
    const current = (await ctx.db
      .query("registrations")
      .withIndex("by_relay_handle_hash", (q) => q.eq("relayHandleHash", args.relayHandleHash))
      .unique()) as StoredDoc<RelayRegistrationRecord> | null;

    const next = applySendResultToRegistration(current, {
      status: args.result.status,
      reason: args.result.reason,
      nowMs: args.nowMs,
    });
    if (!current || !next) {
      return null;
    }
    await ctx.db.patch(current._id, {
      status: next.status,
      updatedAtMs: next.updatedAtMs,
      lastSentAtMs: next.lastSentAtMs,
      lastApnsStatus: next.lastApnsStatus,
      lastApnsReason: next.lastApnsReason,
    });
    return next;
  },
});
