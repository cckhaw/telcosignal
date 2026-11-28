import { randomBytes } from "node:crypto";
import { Redis } from "ioredis";
/** Short-lived data only (nonces, rate-limit counters). Redis is never a system of record. */
export interface EphemeralStore {
  /** Atomically set key if absent with TTL. true = first use. Throws if the store is unavailable (callers fail closed). */
  setNx(key: string, ttlSeconds: number): Promise<boolean>;
  incr(key: string, ttlSeconds: number): Promise<number>;
  /** Sliding-window log (R-009): record one event at `nowMs` and return how many events fall in the last `windowMs`, this one included. Exact (no window-edge burst). Throws if the store is unavailable. */
  slide(key: string, windowMs: number, nowMs: number): Promise<number>;
  /** Add a member to a TTL-bound set; returns the set size. Used for distinct-count heuristics; members are keyed hashes, never numbers. */
  addToSet(key: string, member: string, ttlSeconds: number): Promise<number>;
  close(): Promise<void>;
}
export class RedisStore implements EphemeralStore {
  readonly redis: Redis;
  private r: Redis;
  constructor(url: string) {
    this.r = new Redis(url, { maxRetriesPerRequest: 1, enableOfflineQueue: false, connectTimeout: 1000, lazyConnect: false });
    this.r.on("error", () => undefined);
    this.redis = this.r;
  }
  async setNx(key: string, ttl: number): Promise<boolean> {
    return (await this.r.set(key, "1", "EX", ttl, "NX")) === "OK";
  }
  async incr(key: string, ttl: number): Promise<number> {
    const n = await this.r.incr(key);
    if (n === 1) await this.r.expire(key, ttl);
    return n;
  }
  async slide(key: string, windowMs: number, nowMs: number): Promise<number> {
    const member = `${nowMs}:${randomBytes(6).toString("hex")}`;
    const res = (await this.r.multi().zremrangebyscore(key, 0, nowMs - windowMs).zadd(key, nowMs, member).zcard(key).pexpire(key, windowMs * 2).exec()) as Array<[Error | null, unknown]>;
    const err = res.find((x) => x[0]);
    if (err) throw err[0];
    return Number(res[2]?.[1] ?? 0);
  }
  async addToSet(key: string, member: string, ttl: number): Promise<number> {
    const [, , card] = (await this.r.multi().sadd(key, member).expire(key, ttl, "NX").scard(key).exec()) as Array<[Error | null, unknown]>;
    return Number(card?.[1] ?? 0);
  }
  async close(): Promise<void> { this.r.disconnect(); }
}
