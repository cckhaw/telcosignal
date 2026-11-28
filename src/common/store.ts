import { Redis } from "ioredis";
/** Short-lived data only (nonces, rate-limit counters). Redis is never a system of record. */
export interface EphemeralStore {
  /** Atomically set key if absent with TTL. true = first use. Throws if the store is unavailable (callers fail closed). */
  setNx(key: string, ttlSeconds: number): Promise<boolean>;
  incr(key: string, ttlSeconds: number): Promise<number>;
  /** Current value of a counter written with incr (0 if absent). Throws if the store is unavailable. */
  get(key: string): Promise<number>;
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
  async get(key: string): Promise<number> {
    return Number((await this.r.get(key)) ?? 0);
  }
  async addToSet(key: string, member: string, ttl: number): Promise<number> {
    const [, , card] = (await this.r.multi().sadd(key, member).expire(key, ttl, "NX").scard(key).exec()) as Array<[Error | null, unknown]>;
    return Number(card?.[1] ?? 0);
  }
  async close(): Promise<void> { this.r.disconnect(); }
}
