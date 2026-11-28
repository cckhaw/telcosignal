import type { EphemeralStore } from "../common/store.js";
import type { Pool } from "../db/pool.js";
import { ApiError } from "../common/errors.js";

export interface LimitConfig {
  perParticipantSignalPerMinute: number;   // default per organisation and signal (override table can change it)
  perTelcoPerSecond: number;               // platform-wide protection of each telco connection
  perSubjectPerHour: number;               // same participant asking about the same number (keyed hash) repeatedly
  perParticipantConsentPerMinute: number;  // consent registrations per organisation (stops consent farming and storage exhaustion)
  perSubjectLocationGlobalPerHour: number; // location checks for one subject by ALL participants together (R-029): a second organisation cannot restart the count
  perSubjectLocationPerHour: number;       // location checks for one subject by one participant: low on purpose, repeated probes with moving circles would triangulate the person
}
export const DEFAULT_LIMITS: LimitConfig = { perParticipantSignalPerMinute: 600, perTelcoPerSecond: 200, perSubjectPerHour: 20, perParticipantConsentPerMinute: 120, perSubjectLocationPerHour: 4, perSubjectLocationGlobalPerHour: 8 };

/** Sliding-window limit (R-009): the number of attempts in the last `windowSec` seconds, counted exactly from a per-key log, must stay within `max`.
 *  No window-edge burst (a fixed window allows up to 2x around its boundary; a weighted two-bucket approximation still allows it for bunched traffic).
 *  Rejected attempts are recorded too, as before. Fails closed if the store is down. */
async function hit(store: EphemeralStore, base: string, windowSec: number, max: number, now = Date.now()): Promise<boolean> {
  try { return (await store.slide(base, windowSec * 1000, now)) <= max; }
  catch { throw new ApiError("SERVICE_UNAVAILABLE", "limiter store unavailable (failing closed)"); }   // never silently unlimited
}
export const __hitForTest = hit;

/** Fixed-window counters in the ephemeral store. Throws ApiError(RATE_LIMITED) when exceeded; fails closed if the store is down. */
export class Limiter {
  constructor(private store: EphemeralStore, private pool: Pool, private cfg: LimitConfig) {}
  async participantSignal(orgId: string, signal: string): Promise<void> {
    const o = await this.pool.query("SELECT max_per_minute FROM rate_limit_override WHERE org_id=$1 AND signal=$2", [orgId, signal]);
    const max = (o.rows[0]?.max_per_minute as number | undefined) ?? this.cfg.perParticipantSignalPerMinute;
    if (!(await hit(this.store, `rl:ps:${orgId}:${signal}`, 60, max))) throw new ApiError("RATE_LIMITED", "participant/signal quota exceeded");
  }
  async telco(telcoId: string): Promise<boolean> {          // returns false (not throw): caller answers UNAVAILABLE for this request only
    return hit(this.store, `rl:t:${telcoId}`, 1, this.cfg.perTelcoPerSecond);
  }
  async consentCreate(orgId: string): Promise<void> {
    if (!(await hit(this.store, `rl:cc:${orgId}`, 60, this.cfg.perParticipantConsentPerMinute))) throw new ApiError("RATE_LIMITED", "consent registration quota exceeded");
  }
  async subject(orgId: string, subjectHashHex: string): Promise<void> {
    if (!(await hit(this.store, `rl:s:${orgId}:${subjectHashHex}`, 3600, this.cfg.perSubjectPerHour))) throw new ApiError("RATE_LIMITED", "repeat lookups of one subject exceeded");
  }
  async locationSubject(orgId: string, subjectHashHex: string): Promise<void> {
    if (!(await hit(this.store, `rl:sl:${orgId}:${subjectHashHex}`, 3600, this.cfg.perSubjectLocationPerHour))) throw new ApiError("RATE_LIMITED", "repeat location checks of one subject exceeded");
  }
  async locationSubjectGlobal(subjectHashHex: string): Promise<void> {
    if (!(await hit(this.store, `rl:slg:${subjectHashHex}`, 3600, this.cfg.perSubjectLocationGlobalPerHour))) throw new ApiError("RATE_LIMITED", "location checks of one subject across all participants exceeded");
  }
}
