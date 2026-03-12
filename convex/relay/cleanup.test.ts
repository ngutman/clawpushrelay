import { describe, expect, it, vi } from "vitest";
import { pruneExpiredStateInternal, selectExpiredDocIds } from "./cleanup.js";

describe("selectExpiredDocIds", () => {
  it("returns expired ids ordered by expiry and capped by the limit", () => {
    const ids = selectExpiredDocIds(
      [
        { _id: "late", expiresAtMs: 9_000 },
        { _id: "fresh", expiresAtMs: 11_000 },
        { _id: "first", expiresAtMs: 5_000 },
        { _id: "second", expiresAtMs: 7_000 },
      ],
      10_000,
      2,
    );

    expect(ids).toEqual(["first", "second"]);
  });
});

describe("pruneExpiredStateInternal", () => {
  it("deletes expired challenges and rate-limit events", async () => {
    const deleteSpy = vi.fn().mockResolvedValue(undefined);
    const ctx: {
      db: {
        query: (table: "challenges" | "rate_limit_events") => {
          collect: () => Promise<Array<{ _id: string; expiresAtMs: number }>>;
        };
        delete: typeof deleteSpy;
      };
    } = {
      db: {
        query: (table: "challenges" | "rate_limit_events") => ({
          collect: async () =>
            table === "challenges"
              ? [
                  { _id: "challenge-1", expiresAtMs: 1_000 },
                  { _id: "challenge-2", expiresAtMs: 5_000 },
                  { _id: "challenge-3", expiresAtMs: 9_000 },
                ]
              : [
                  { _id: "rate-1", expiresAtMs: 2_000 },
                  { _id: "rate-2", expiresAtMs: 7_000 },
                  { _id: "rate-3", expiresAtMs: 12_000 },
                ],
        }),
        delete: deleteSpy,
      },
    };

    const result = await (pruneExpiredStateInternal as unknown as {
      _handler: (
        ctx: {
          db: {
            query: (table: "challenges" | "rate_limit_events") => {
              collect: () => Promise<Array<{ _id: string; expiresAtMs: number }>>;
            };
            delete: typeof deleteSpy;
          };
        },
        args: { nowMs: number; challengesLimit: number; rateLimitEventsLimit: number },
      ) => Promise<{ challengesDeleted: number; rateLimitEventsDeleted: number }>;
    })._handler(ctx, {
      nowMs: 8_000,
      challengesLimit: 10,
      rateLimitEventsLimit: 10,
    });

    expect(result).toEqual({
      challengesDeleted: 2,
      rateLimitEventsDeleted: 2,
    });
    expect(deleteSpy.mock.calls.map(([id]) => id)).toEqual([
      "challenge-1",
      "challenge-2",
      "rate-1",
      "rate-2",
    ]);
  });
});
