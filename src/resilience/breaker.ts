// Circuit breaker + bulkhead decorator for any TelcoAdapter.
import type { AdapterRequest, AdapterResult, TelcoAdapter } from "../adapters/types.js";
import type { Signal } from "../consent/consent.js";

export interface ResilienceConfig { windowMs: number; minRequests: number; failureRate: number; openMs: number; maxConcurrent: number }
export const DEFAULT_RESILIENCE: ResilienceConfig = { windowMs: 10_000, minRequests: 8, failureRate: 0.5, openMs: 15_000, maxConcurrent: 50 };
export type BreakerState = "closed" | "open" | "half_open";

/** Only genuine telco/transport faults count towards opening the breaker. A flood of numbers the telco does not know
 *  (404/422/rc=14) is a legitimate answer, so it must NOT be usable to trip the breaker and deny service to everyone. */
export function isTelcoFault(r: AdapterResult): boolean {
  if (r.status !== "UNAVAILABLE") return false;
  return !/^telco status 4\d\d$|^telco rc 14$|^some fields not available$|^no match fields$/.test(r.reason);
}

export class ResilientAdapter implements TelcoAdapter {
  private events: Array<{ at: number; fault: boolean }> = [];
  private state: BreakerState = "closed";
  private openedAt = 0;
  private probing = false;
  private inFlight = 0;
  readonly supports: ReadonlySet<Signal>;
  constructor(private inner: TelcoAdapter, private cfg: ResilienceConfig = DEFAULT_RESILIENCE, private now: () => number = Date.now) {
    this.supports = inner.supports;
  }
  get telcoId() { return this.inner.telcoId; }
  getState(): { state: BreakerState; inFlight: number; recentFaults: number; recentTotal: number } {
    this.trim();
    return { state: this.currentState(), inFlight: this.inFlight, recentFaults: this.events.filter((e) => e.fault).length, recentTotal: this.events.length };
  }
  private trim() { const cut = this.now() - this.cfg.windowMs; this.events = this.events.filter((e) => e.at >= cut); }
  private currentState(): BreakerState {
    if (this.state === "open" && this.now() - this.openedAt >= this.cfg.openMs) this.state = "half_open";
    return this.state;
  }
  private unavailable(reason: string): AdapterResult { return { status: "UNAVAILABLE", reason, telcoMs: 0 }; }

  async call(r: AdapterRequest): Promise<AdapterResult> {
    if (!this.inner.supports.has(r.signal)) return this.inner.call(r);          // NOT_SUPPORTED needs no connection and must not affect the breaker
    const st = this.currentState();
    if (st === "open") return this.unavailable("circuit open");
    if (st === "half_open") { if (this.probing) return this.unavailable("circuit half-open: probe in progress"); this.probing = true; }
    if (this.inFlight >= this.cfg.maxConcurrent) { if (st === "half_open") this.probing = false; return this.unavailable("bulkhead full"); }
    this.inFlight++;
    let res: AdapterResult;
    try { res = await this.inner.call(r); }
    catch { res = this.unavailable("adapter exception"); }                        // adapters should not throw; if one does, fail safe
    finally { this.inFlight--; }
    const fault = isTelcoFault(res);
    if (st === "half_open") {
      this.probing = false;
      if (fault) { this.state = "open"; this.openedAt = this.now(); }
      else { this.state = "closed"; this.events = []; }
      return res;
    }
    this.events.push({ at: this.now(), fault }); this.trim();
    const total = this.events.length, faults = this.events.filter((e) => e.fault).length;
    if (total >= this.cfg.minRequests && faults / total >= this.cfg.failureRate) { this.state = "open"; this.openedAt = this.now(); }
    return res;
  }
  async close() { await this.inner.close(); }
}
