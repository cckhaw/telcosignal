import type { EphemeralStore } from "../common/store.js";
import type { Pool } from "../db/pool.js";
import { ApiError } from "../common/errors.js";

export interface LimitConfig {
  perParticipantSignalPerMinute: number;   // default per organisation and signal (override table can change it)
  perTelcoPerSecond: number;               // platform-wide protection of each telco connection
  perSubjectPerHour: number;               // same participant asking about the same number (keyed hash) repeatedly
}
export const DEFAULT_LIMITS: LimitConfig = { perParticipantSignalPerMinute: 600, perTelcoPerSecond: 200, perSubjectPerHour: 20 };

async function hit(store: EphemeralStore, key: string, ttl: number, max: number): Promise<boolean> {
  try { return (await store.incr(key, ttl)) <= max; }
  catch { throw new ApiError("SERVICE_UNAVAILABLE", "limiter store unavailable (failing closed)"); }   // never silently unlimited
}
const bucket = (s: number) => Math.floor(Date.now() / (s * 1000));

/** Fixed-window counters in the ephemeral store. Throws ApiError(RATE_LIMITED) when exceeded; fails closed if the store is down. */
export class Limiter {
  constructor(private store: EphemeralStore, private pool: Pool, private cfg: LimitConfig) {}
  async participantSignal(orgId: string, signal: string): Promise<void> {
    const o = await this.pool.query("SELECT max_per_minute FROM rate_limit_override WHERE org_id=$1 AND signal=$2", [orgId, signal]);
    const max = (o.rows[0]?.max_per_minute as number | undefined) ?? this.cfg.perParticipantSignalPerMinute;
    if (!(await hit(this.store, `rl:ps:${orgId}:${signal}:${bucket(60)}`, 120, max))) throw new ApiError("RATE_LIMITED", "participant/signal quota exceeded");
  }
  async telco(telcoId: string): Promise<boolean> {          // returns false (not throw): caller answers UNAVAILABLE for this request only
    return hit(this.store, `rl:t:${telcoId}:${bucket(1)}`, 5, this.cfg.perTelcoPerSecond);
  }
  async subject(orgId: string, subjectHashHex: string): Promise<void> {
    if (!(await hit(this.store, `rl:s:${orgId}:${subjectHashHex}:${bucket(3600)}`, 7200, this.cfg.perSubjectPerHour))) throw new ApiError("RATE_LIMITED", "repeat lookups of one subject exceeded");
  }
}
