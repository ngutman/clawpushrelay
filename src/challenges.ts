import { randomUUID } from "node:crypto";
import { randomOpaqueToken } from "./crypto.js";
import type { ChallengeRecord } from "./types.js";

export class ChallengeStore {
  private readonly records = new Map<string, ChallengeRecord>();

  constructor(
    private readonly ttlMs: number,
    private readonly now: () => number = () => Date.now(),
  ) {}

  issue(): ChallengeRecord {
    this.prune();
    const createdAtMs = this.now();
    const record: ChallengeRecord = {
      challengeId: randomUUID(),
      challenge: randomOpaqueToken(32),
      createdAtMs,
      expiresAtMs: createdAtMs + this.ttlMs,
    };
    this.records.set(record.challengeId, record);
    return record;
  }

  consume(challengeId: string): ChallengeRecord | null {
    this.prune();
    const record = this.records.get(challengeId) ?? null;
    if (!record) {
      return null;
    }
    this.records.delete(challengeId);
    if (record.expiresAtMs <= this.now()) {
      return null;
    }
    return record;
  }

  private prune(): void {
    const now = this.now();
    for (const [challengeId, record] of this.records) {
      if (record.expiresAtMs <= now) {
        this.records.delete(challengeId);
      }
    }
  }
}
