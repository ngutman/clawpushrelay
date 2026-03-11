type Bucket = {
  timestamps: number[];
};

export class SlidingWindowRateLimiter {
  private readonly buckets = new Map<string, Bucket>();

  constructor(
    private readonly windowMs: number,
    private readonly now: () => number = () => Date.now(),
  ) {}

  consume(key: string, limit: number): boolean {
    const now = this.now();
    const cutoff = now - this.windowMs;
    const bucket = this.buckets.get(key) ?? { timestamps: [] };
    bucket.timestamps = bucket.timestamps.filter((value) => value > cutoff);
    if (bucket.timestamps.length >= limit) {
      this.buckets.set(key, bucket);
      return false;
    }
    bucket.timestamps.push(now);
    this.buckets.set(key, bucket);
    return true;
  }
}
