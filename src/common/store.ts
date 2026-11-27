import { Redis } from "ioredis";
/** Short-lived data only (nonces, rate-limit counters). Redis is never a system of record. */
export interface EphemeralStore {
  /** Atomically set key if absent with TTL. true = first use. Throws if the store is unavailable (callers fail closed). */
  setNx(key: string, ttlSeconds: number): Promise<boolean>;
  incr(key: string, ttlSeconds: number): Promise<number>;
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
  async close(): Promise<void> { this.r.disconnect(); }
}
