// Enumeration / bulk-lookup detection. Works on KEYED HASHES and counters only: no number ever reaches Redis, logs or the DB.
import type { EphemeralStore } from "../common/store.js";
import type { Pool } from "../db/pool.js";
import type { Kms } from "../kms/types.js";
import type { Audit } from "../audit/audit.js";
import type { Logger } from "pino";

export interface AbuseConfig { windowSeconds: number; distinctSubjects: number; sameRangeSubjects: number; consentFailures: number; autoSuspend: boolean }
export const DEFAULT_ABUSE: AbuseConfig = { windowSeconds: 600, distinctSubjects: 60, sameRangeSubjects: 20, consentFailures: 15, autoSuspend: false };
export type AbuseKind = "HIGH_DISTINCT_SUBJECTS" | "SEQUENTIAL_RANGE" | "CONSENT_PROBING";

export class AbuseDetector {
  constructor(private store: EphemeralStore, private pool: Pool, private kms: Kms, private audit: Audit, private log: Logger, private cfg: AbuseConfig) {}

  /** Record one lookup attempt (whether or not consent was valid) and raise flags when heuristics trip. Never throws to the caller: detection must not break serving. */
  async observe(o: { orgId: string; clientId: string; msisdn: string; correlationId: string; consentOk: boolean }): Promise<AbuseKind[]> {
    const raised: AbuseKind[] = [];
    try {
      const w = this.cfg.windowSeconds, win = Math.floor(Date.now() / (w * 1000));
      const subj = (await this.kms.hmac("msisdn-hmac", o.msisdn)).toString("hex").slice(0, 32);
      // Range bucket = the number without its last 3 digits, hashed under a separate keyed context: sequential scans fall into one bucket.
      const range = (await this.kms.hmac("abuse-range-hmac", o.msisdn.slice(0, -3))).toString("hex").slice(0, 32);
      const distinct = await this.store.addToSet(`ab:d:${o.orgId}:${win}`, subj, w * 2);
      const sameRange = await this.store.addToSet(`ab:r:${o.orgId}:${range}:${win}`, subj, w * 2);
      let fails = 0;
      if (!o.consentOk) fails = await this.store.incr(`ab:c:${o.orgId}:${win}`, w * 2);
      const checks: Array<[AbuseKind, number, number]> = [["HIGH_DISTINCT_SUBJECTS", distinct, this.cfg.distinctSubjects], ["SEQUENTIAL_RANGE", sameRange, this.cfg.sameRangeSubjects], ["CONSENT_PROBING", fails, this.cfg.consentFailures]];
      for (const [kind, observed, threshold] of checks) {
        if (observed < threshold) continue;
        if (!(await this.store.setNx(`ab:f:${o.orgId}:${kind}:${win}`, w * 2))) continue;       // one flag per kind per window
        raised.push(kind);
        await this.pool.query("INSERT INTO abuse_flag(org_id, client_id, kind, observed, threshold, window_s, correlation_id) VALUES ($1,$2,$3,$4,$5,$6,$7)", [o.orgId, o.clientId, kind, observed, threshold, w, o.correlationId]);
        this.log.warn({ "event.category": "security", "event.action": "abuse.enumeration_suspected", "event.outcome": "alert", correlation_id: o.correlationId, actor: o.clientId, kind, observed, threshold, window_s: w }, "security_event");
        await this.audit.record({ correlationId: o.correlationId, actor: o.clientId, action: "abuse.flagged", orgId: o.orgId, outcome: kind, detail: { observed, threshold, window_s: w } });
        if (this.cfg.autoSuspend) await this.suspend(o.clientId, o.correlationId, o.orgId, kind);
      }
    } catch { /* detection is best-effort; the request path has already been protected by hard limits */ }
    return raised;
  }

  /** Suspension = participant kill switch (also the manual admin action in M4a). Idempotent and audited. */
  async suspend(clientId: string, correlationId: string, orgId: string, reason: string): Promise<void> {
    const r = await this.pool.query("SELECT abuse_suspend($1) AS ok", [clientId]);     // narrow SECURITY DEFINER path; app role cannot write kill_switch directly
    this.log.warn({ "event.category": "security", "event.action": "participant.suspended", "event.outcome": r.rows[0]?.ok ? "success" : "failure", correlation_id: correlationId, actor: clientId, reason }, "security_event");
    await this.audit.record({ correlationId, actor: "system", action: "participant.suspended", orgId, outcome: r.rows[0]?.ok ? "OK" : "NOT_FOUND", detail: { client: clientId, reason } });
  }
}
