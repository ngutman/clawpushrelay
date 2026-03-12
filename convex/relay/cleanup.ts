import { internalMutationGeneric } from "convex/server";
import { v } from "convex/values";

const internalMutation = internalMutationGeneric;

type ExpiringDoc = {
  _id: unknown;
  expiresAtMs: number;
};

const DEFAULT_CHALLENGE_DELETE_LIMIT = 128;
const DEFAULT_RATE_LIMIT_DELETE_LIMIT = 256;

export function selectExpiredDocIds<T extends ExpiringDoc>(
  docs: T[],
  nowMs: number,
  limit: number,
): Array<T["_id"]> {
  return docs
    .filter((doc) => doc.expiresAtMs <= nowMs)
    .sort((left, right) => left.expiresAtMs - right.expiresAtMs)
    .slice(0, limit)
    .map((doc) => doc._id);
}

export const pruneExpiredStateInternal = internalMutation({
  args: {
    nowMs: v.optional(v.number()),
    challengesLimit: v.optional(v.number()),
    rateLimitEventsLimit: v.optional(v.number()),
  },
  handler: async (ctx, args) => {
    const nowMs = args.nowMs ?? Date.now();
    const challengesLimit = args.challengesLimit ?? DEFAULT_CHALLENGE_DELETE_LIMIT;
    const rateLimitEventsLimit = args.rateLimitEventsLimit ?? DEFAULT_RATE_LIMIT_DELETE_LIMIT;

    const challengeIds = selectExpiredDocIds(
      (await ctx.db.query("challenges").collect()) as Array<ExpiringDoc>,
      nowMs,
      challengesLimit,
    );
    for (const challengeId of challengeIds) {
      await ctx.db.delete(challengeId as never);
    }

    const rateLimitEventIds = selectExpiredDocIds(
      (await ctx.db.query("rate_limit_events").collect()) as Array<ExpiringDoc>,
      nowMs,
      rateLimitEventsLimit,
    );
    for (const rateLimitEventId of rateLimitEventIds) {
      await ctx.db.delete(rateLimitEventId as never);
    }

    return {
      challengesDeleted: challengeIds.length,
      rateLimitEventsDeleted: rateLimitEventIds.length,
    };
  },
});
