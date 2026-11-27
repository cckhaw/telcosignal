// Alert evaluation: configurable rules over rollups, with acknowledgement and escalation. Emits SIEM-ready security events.
import type { Pool } from "../db/pool.js";
import { percentile } from "./rollups.js";

export interface AlertEvent { action: "alert.opened" | "alert.escalated" | "alert.resolved"; ruleId: string; severity: string; observed: number | null; threshold: number; alertId: number }
const SEC_CODES: Record<string, string> = { auth_failures: "AUTHENTICATION_FAILED", rate_limit_hits: "RATE_LIMITED", replay_rejections: "REPLAY_REJECTED", consent_denials: "CONSENT_REQUIRED" };
const MIN_VOLUME = 5;      // below this many eligible requests in the window, rate-based rules are not evaluated (avoids noise at low volume)

export async function metricValue(w: Pool, metric: string, windowMinutes: number, now: Date): Promise<number | null> {
  const from = new Date(now.getTime() - windowMinutes * 60_000);
  if (SEC_CODES[metric]) return Number((await w.query("SELECT coalesce(sum(events),0) n FROM rollup_security_minute WHERE bucket >= $1 AND bucket <= $2 AND error_code = $3", [from, now, SEC_CODES[metric]])).rows[0].n);
  if (metric === "abuse_flags") return Number((await w.query("SELECT count(*) n FROM abuse_flag WHERE ts >= $1", [from])).rows[0].n)      // no upper bound: Postgres timestamps have microseconds, JS only milliseconds, so "<= now" could miss a flag written in the same millisecond;
  if (metric === "creds_expiring") return Number((await w.query("SELECT count(*) n FROM client_keys WHERE revoked_at IS NULL AND expires_at < $1::timestamptz + interval '30 days'", [now])).rows[0].n);
  const r = (await w.query(
    `SELECT coalesce(sum(requests) FILTER (WHERE outcome <> 'REJECTED' AND outcome <> 'NOT_SUPPORTED'),0) AS eligible,
            coalesce(sum(requests) FILTER (WHERE outcome IN ('TRUE','FALSE')),0) AS ok,
            coalesce(sum(requests) FILTER (WHERE outcome = 'UNAVAILABLE'),0) AS unavailable,
            coalesce(sum(requests) FILTER (WHERE reason_class = 'timeout'),0) AS timeouts,
            coalesce(sum(requests) FILTER (WHERE reason_class = 'circuit_open'),0) AS circuit_open
     FROM rollup_minute WHERE bucket >= $1 AND bucket <= $2`, [from, now])).rows[0];
  const eligible = Number(r.eligible);
  if (metric === "circuit_open") return Number(r.circuit_open);
  if (metric === "overhead_p95_ms") {
    const h = (await w.query("SELECT array_agg(s ORDER BY i) h FROM (SELECT i, sum(v)::int s FROM rollup_minute, unnest(h_over) WITH ORDINALITY AS t(v, i) WHERE bucket >= $1 AND bucket <= $2 GROUP BY i) x", [from, now])).rows[0].h as number[] | null;
    return h ? percentile(h, 0.95) : null;
  }
  if (eligible < MIN_VOLUME) return null;
  if (metric === "success_rate_min") return Number(r.ok) / eligible;
  if (metric === "unavailable_rate") return Number(r.unavailable) / eligible;
  if (metric === "timeout_rate") return Number(r.timeouts) / eligible;
  return null;
}

export async function evaluateAlerts(w: Pool, now = new Date()): Promise<AlertEvent[]> {
  const events: AlertEvent[] = [];
  const rules = (await w.query("SELECT * FROM alert_rule WHERE enabled")).rows as Array<{ id: string; metric: string; comparator: string; threshold: string; window_minutes: number; severity: string; escalate_after_minutes: number }>;
  for (const r of rules) {
    const observed = await metricValue(w, r.metric, r.window_minutes, now);
    const thr = Number(r.threshold);
    const breached = observed !== null && (r.comparator === "gt" ? observed > thr : observed < thr);
    const active = (await w.query("SELECT id, status, opened_at FROM alert WHERE rule_id=$1 AND status IN ('open','acknowledged','escalated')", [r.id])).rows[0] as { id: string; status: string; opened_at: Date } | undefined;
    if (breached && !active) {
      const ins = await w.query("INSERT INTO alert(rule_id, opened_at, severity, observed, threshold) VALUES ($1,$2,$3,$4,$5) ON CONFLICT DO NOTHING RETURNING id", [r.id, now, r.severity, observed === Infinity ? 1e9 : observed, thr]);
      if (ins.rowCount) events.push({ action: "alert.opened", ruleId: r.id, severity: r.severity, observed, threshold: thr, alertId: Number(ins.rows[0].id) });
    } else if (breached && active && active.status === "open" && now.getTime() - new Date(active.opened_at).getTime() >= r.escalate_after_minutes * 60_000) {
      await w.query("UPDATE alert SET status='escalated', escalated_at=$2 WHERE id=$1 AND status='open'", [active.id, now]);      // acknowledgement stops escalation
      events.push({ action: "alert.escalated", ruleId: r.id, severity: r.severity, observed, threshold: thr, alertId: Number(active.id) });
    } else if (!breached && active && observed !== null) {
      await w.query("UPDATE alert SET status='resolved', resolved_at=$2 WHERE id=$1", [active.id, now]);
      events.push({ action: "alert.resolved", ruleId: r.id, severity: r.severity, observed, threshold: thr, alertId: Number(active.id) });
    }
  }
  return events;
}
