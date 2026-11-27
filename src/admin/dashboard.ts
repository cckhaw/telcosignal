// KPI engine: every number comes from the time-bucketed rollups (and a few small registries), never from the request path.
// Definitions: docs/kpi-definitions.md. Percentiles are the upper bound of the histogram bucket (conservative).
import type { Tx } from "../db/pool.js";
import { percentile } from "../ops/rollups.js";

export interface Filters { from: Date; to: Date; orgId?: string | undefined; telcoId?: string | undefined; signal?: string | undefined; version?: string | undefined }
export interface Pct { p50: number | null; p95: number | null; p99: number | null }
export interface Dashboard {
  filters: Filters; freshness: { watermark: Date | null; ageSeconds: number | null; stale: boolean };
  traffic: { requests: number; billable: number; avgRps: number; peakRps: number; trend: Array<{ hour: Date; requests: number }>; byOrg: Array<{ org: string; requests: number; share: number }>; byTelco: Array<{ telco: string; requests: number; share: number }> };
  latency: { total: Pct; overhead: Pct; telco: Pct };
  reliability: { outcomes: Record<string, number>; successRate: number | null; availability: number | null; unavailableRate: number | null; notSupportedRate: number | null; timeoutRate: number | null; byReason: Record<string, number>; sla: { target: number; attainment: number | null; breaches: number; buckets: number } };
  security: { byCode: Record<string, number>; abuseFlags: number | null; credsNearExpiry: number };
  business: { activeParticipants: number; onboarding: Record<string, number> | null; coverage: { covered: number; possible: number } | null; billableVolume: number; charges: number | null; telcoCost: number | null };
}
const STALE_SECONDS = 180;
function where(f: Filters): { sql: string; params: unknown[] } {
  return { sql: "bucket >= $1 AND bucket < $2 AND ($3::uuid IS NULL OR org_id = $3) AND ($4::text IS NULL OR telco_id = $4) AND ($5::text IS NULL OR signal = $5) AND ($6::text IS NULL OR api_version = $6)", params: [f.from, f.to, f.orgId ?? null, f.telcoId ?? null, f.signal ?? null, f.version ?? null] };
}
async function merged(tx: Tx, col: "h_total" | "h_over" | "h_telco", f: Filters): Promise<Pct> {
  const w = where(f);
  const r = await tx.query(`SELECT array_agg(s ORDER BY i) h FROM (SELECT i, sum(v)::int s FROM rollup_minute, unnest(${col}) WITH ORDINALITY AS t(v, i) WHERE ${w.sql} GROUP BY i) x`, w.params);
  const h = r.rows[0]?.h as number[] | null;
  return h ? { p50: percentile(h, 0.5), p95: percentile(h, 0.95), p99: percentile(h, 0.99) } : { p50: null, p95: null, p99: null };
}
export async function loadDashboard(tx: Tx, f: Filters, o: { staff: boolean; now?: Date }): Promise<Dashboard> {
  const now = o.now ?? new Date(); const w = where(f);
  const outc = (await tx.query(`SELECT outcome, reason_class, sum(requests)::int n, sum(billable)::int b FROM rollup_minute WHERE ${w.sql} GROUP BY 1,2`, w.params)).rows as Array<{ outcome: string; reason_class: string; n: number; b: number }>;
  const outcomes: Record<string, number> = {}, byReason: Record<string, number> = {}; let requests = 0, billable = 0;
  for (const r of outc) { outcomes[r.outcome] = (outcomes[r.outcome] ?? 0) + r.n; byReason[r.reason_class] = (byReason[r.reason_class] ?? 0) + r.n; requests += r.n; billable += r.b; }
  const minutes = (await tx.query(`SELECT bucket, sum(requests)::int n, (sum(requests) FILTER (WHERE outcome IN ('TRUE','FALSE')))::int ok, (sum(requests) FILTER (WHERE outcome NOT IN ('REJECTED','NOT_SUPPORTED')))::int elig FROM rollup_minute WHERE ${w.sql} GROUP BY 1 ORDER BY 1`, w.params)).rows as Array<{ n: number; ok: number | null; elig: number | null }>;
  const peak = minutes.reduce((m, r) => Math.max(m, r.n), 0) / 60;
  const spanS = Math.max(1, (Math.min(f.to.getTime(), now.getTime()) - f.from.getTime()) / 1000);
  const trend = (await tx.query(`SELECT date_trunc('hour', bucket) AS hr, sum(requests)::int AS n FROM rollup_minute WHERE ${w.sql} GROUP BY 1 ORDER BY 1`, w.params)).rows.map((r) => ({ hour: r.hr as Date, requests: r.n as number }));
  const share = (rows: Array<{ k: string; n: number }>) => rows.map((r) => ({ requests: r.n, share: requests ? r.n / requests : 0, k: r.k }));
  const byOrgRows = o.staff ? (await tx.query(`SELECT coalesce(o.name, m.org_id::text) AS k, sum(m.requests)::int AS n FROM rollup_minute m LEFT JOIN organisations o ON o.id = m.org_id WHERE ${w.sql.replace(/\b(bucket|org_id|telco_id|signal|api_version)\b/g, "m.$1")} GROUP BY 1 ORDER BY 2 DESC`, w.params)).rows as Array<{ k: string; n: number }> : [];
  const byTelcoRows = (await tx.query(`SELECT telco_id AS k, sum(requests)::int AS n FROM rollup_minute WHERE ${w.sql} GROUP BY 1 ORDER BY 2 DESC`, w.params)).rows as Array<{ k: string; n: number }>;
  const eligible = (outcomes["TRUE"] ?? 0) + (outcomes["FALSE"] ?? 0) + (outcomes["UNAVAILABLE"] ?? 0), ok = (outcomes["TRUE"] ?? 0) + (outcomes["FALSE"] ?? 0);
  const targets = Object.fromEntries((await tx.query("SELECT kpi, target::float t FROM kpi_target")).rows.map((r) => [r.kpi as string, r.t as number]));
  const slaBuckets = minutes.filter((m) => (m.elig ?? 0) >= 5);
  const good = slaBuckets.filter((m) => (m.ok ?? 0) / (m.elig ?? 1) >= (targets["success_rate"] ?? 0.995)).length;
  const sec = (await tx.query("SELECT error_code, sum(events)::int n FROM rollup_security_minute WHERE bucket >= $1 AND bucket < $2 AND ($3::uuid IS NULL OR org_id = $3) GROUP BY 1", [f.from, f.to, f.orgId ?? null])).rows as Array<{ error_code: string; n: number }>;
  const abuse = o.staff ? Number((await tx.query("SELECT count(*) n FROM abuse_flag WHERE ts >= $1 AND ts < $2", [f.from, f.to])).rows[0].n) : null;
  const creds = Number((await tx.query("SELECT count(*) n FROM client_keys WHERE revoked_at IS NULL AND expires_at < now() + interval '30 days'")).rows[0].n);
  const active = Number((await tx.query(`SELECT count(DISTINCT org_id) n FROM rollup_minute WHERE ${w.sql}`, w.params)).rows[0].n);
  const onb = o.staff ? Object.fromEntries((await tx.query("SELECT state, count(*)::int n FROM organisations GROUP BY 1")).rows.map((r) => [r.state as string, r.n as number])) : null;
  const cov = o.staff ? (await tx.query("SELECT (SELECT count(*)::int FROM telco_signal_coverage c JOIN telcos t ON t.id=c.telco_id WHERE t.state='active') AS covered, (SELECT count(*)::int FROM telcos WHERE state='active') * (SELECT count(*)::int FROM signals) AS possible")).rows[0] as { covered: number; possible: number } : null;
  const ch = (await tx.query("SELECT sum(total_minor)::bigint s, count(*)::int n FROM statement WHERE kind='participant' AND period_start >= $1 AND period_end <= $2 AND ($3::uuid IS NULL OR org_id = $3)", [f.from, f.to, f.orgId ?? null])).rows[0];
  const tc = o.staff ? (await tx.query("SELECT sum(total_minor)::bigint s, count(*)::int n FROM statement WHERE kind='telco' AND period_start >= $1 AND period_end <= $2", [f.from, f.to])).rows[0] : null;
  const st = (await tx.query("SELECT watermark FROM rollup_state WHERE name='main'")).rows[0]?.watermark as Date | undefined;
  const age = st ? Math.round((now.getTime() - st.getTime()) / 1000) : null;
  return {
    filters: f, freshness: { watermark: st ?? null, ageSeconds: age, stale: age === null || age > STALE_SECONDS },
    traffic: { requests, billable, avgRps: requests / spanS, peakRps: peak, trend, byOrg: share(byOrgRows).map((x) => ({ org: x.k, requests: x.requests, share: x.share })), byTelco: share(byTelcoRows).map((x) => ({ telco: x.k || "(none)", requests: x.requests, share: x.share })) },
    latency: { total: await merged(tx, "h_total", f), overhead: await merged(tx, "h_over", f), telco: await merged(tx, "h_telco", f) },
    reliability: {
      outcomes, successRate: eligible ? ok / eligible : null, availability: eligible ? 1 - (byReason["no_route"] ?? 0) / Math.max(eligible, 1) - (byReason["circuit_open"] ?? 0) / Math.max(eligible, 1) : null,
      unavailableRate: eligible ? (outcomes["UNAVAILABLE"] ?? 0) / eligible : null, notSupportedRate: requests ? (outcomes["NOT_SUPPORTED"] ?? 0) / requests : null, timeoutRate: eligible ? (byReason["timeout"] ?? 0) / eligible : null, byReason,
      sla: { target: targets["success_rate"] ?? 0.995, attainment: slaBuckets.length ? good / slaBuckets.length : null, breaches: slaBuckets.length - good, buckets: slaBuckets.length },
    },
    security: { byCode: Object.fromEntries(sec.map((r) => [r.error_code, r.n])), abuseFlags: abuse, credsNearExpiry: creds },
    business: { activeParticipants: active, onboarding: onb, coverage: cov, billableVolume: billable, charges: ch?.n ? Number(ch.s) : null, telcoCost: tc && tc.n ? Number(tc.s) : null },
  };
}
const q = (v: unknown) => { let s = String(v ?? ""); if (/^[=+\-@\t\r]/.test(s)) s = "'" + s; return /[",\n]/.test(s) ? `"${s.replace(/"/g, '""')}"` : s; };     // CSV-injection safe
export const csvLine = (cells: unknown[]) => cells.map(q).join(",") + "\n";
export function dashboardCsv(d: Dashboard): string {
  let o = csvLine(["section", "metric", "value"]);
  const add = (s: string, m: string, v: unknown) => { o += csvLine([s, m, v]); };
  add("meta", "from", d.filters.from.toISOString()); add("meta", "to", d.filters.to.toISOString()); add("meta", "data_as_of", d.freshness.watermark?.toISOString() ?? "never");
  add("traffic", "requests", d.traffic.requests); add("traffic", "billable", d.traffic.billable); add("traffic", "avg_rps", d.traffic.avgRps.toFixed(4)); add("traffic", "peak_rps", d.traffic.peakRps.toFixed(4));
  for (const t of d.traffic.byTelco) add("traffic_by_telco", t.telco, t.requests);
  for (const [k, v] of Object.entries(d.latency)) for (const [p, x] of Object.entries(v)) add("latency_ms", `${k}_${p}`, x === Infinity ? ">=2000" : x ?? "");
  for (const [k, v] of Object.entries(d.reliability.outcomes)) add("outcome", k, v);
  for (const [k, v] of Object.entries(d.reliability.byReason)) add("reason_class", k, v);
  add("reliability", "success_rate", d.reliability.successRate ?? ""); add("reliability", "sla_attainment", d.reliability.sla.attainment ?? ""); add("reliability", "sla_breaches", d.reliability.sla.breaches);
  for (const [k, v] of Object.entries(d.security.byCode)) add("security", k, v);
  add("business", "active_participants", d.business.activeParticipants); add("business", "billable_volume", d.business.billableVolume); add("business", "charges_minor", d.business.charges ?? ""); add("business", "telco_cost_minor", d.business.telcoCost ?? "");
  return o;
}
