import { describe, it, expect, beforeAll, afterAll } from "vitest";
import pg from "pg";
import { startHarness, num, numB, numC, type Harness } from "../helpers/harness.js";
import { startAdmin, type Admin, type Session } from "../helpers/admin-harness.js";
import { loadDashboard, type Dashboard, type Filters } from "../../src/admin/dashboard.js";
import { percentile, refreshRollups, BOUNDS } from "../../src/ops/rollups.js";
import { evaluateAlerts } from "../../src/ops/alerts.js";
import { runRetention } from "../../src/ops/retention.js";

let h: Harness, a: Admin; const S: Record<string, Session> = {};
const body = (n: string, ref: string, extra: Record<string, unknown> = {}) => ({ phoneNumber: n, consentRef: ref, purposeCode: "FRAUD_PREVENTION", ...extra });
const su = async <T>(fn: (c: pg.Client) => Promise<T>) => { const c = new pg.Client({ connectionString: h.adminUrl.replace(/\/[^/]*$/, `/${h.dbName}`) }); await c.connect(); try { return await fn(c); } finally { await c.end(); } };
const dash = async (f: Filters, staff = true, org: string | null = null): Promise<Dashboard> => {
  const c = await a.pool.connect();
  try { await c.query("BEGIN"); await c.query("SELECT set_config('app.admin_scope',$1,true), set_config('app.org_id',$2,true)", [staff ? "all" : "org", org ?? ""]); const r = await loadDashboard(c, f, { staff }); await c.query("ROLLBACK"); return r; } finally { c.release(); }
};
const WIDE = (): Filters => ({ from: new Date(Date.now() - 3 * 3600e3), to: new Date(Date.now() + 3600e3) });
let latOrg = "";
let seq = 0; const mid = () => String(7000 + seq++);
async function call(c: typeof h.bankA, signal: string, n: string, extra: Record<string, unknown> = {}) {
  const k = await h.consent(c, n); return h.call(c, "POST", `/v1/signals/${signal}/check`, { body: body(n, k.ref, extra) });
}

beforeAll(async () => {
  h = await startHarness({ telcoTimeoutMs: 400 }); a = await startAdmin(h);
  for (const u of ["alice", "bob", "olivia", "sam", "fiona", "ian", "banker-a", "banker-b"]) S[u] = await a.login(u);
});
afterAll(async () => { await a.stop(); await h.stop(); });

describe("percentiles and histograms", () => {
  it("percentile() returns the conservative bucket upper bound", () => {
    expect(percentile([0, 0, 0, 0, 0, 0, 0, 0, 0, 0], 0.5)).toBeNull();
    expect(percentile([100, 0, 0, 0, 0, 0, 0, 0, 0, 0], 0.99)).toBe(5);
    expect(percentile([50, 50, 0, 0, 0, 0, 0, 0, 0, 0], 0.5)).toBe(5); expect(percentile([50, 50, 0, 0, 0, 0, 0, 0, 0, 0], 0.51)).toBe(10);
    expect(percentile([0, 0, 0, 0, 0, 0, 0, 0, 0, 1], 0.5)).toBe(Infinity);
    expect(BOUNDS).toEqual([5, 10, 25, 50, 100, 250, 500, 1000, 2000]);
  });
  it("known latencies in usage records come out as the right p50/p95/p99, with platform overhead separate from telco time", async () => {
    const org = (await h.migrator.query("INSERT INTO organisations(name, kind, state) VALUES ('Latency Org','bank','active') RETURNING id")).rows[0].id as string; latOrg = org;
    await h.migrator.query("INSERT INTO usage_record(org_id, signal, telco_id, outcome, billable, total_ms, telco_ms, correlation_id) SELECT $1,'SIM_SWAP','telco-a','FALSE',true,30,20,'lat-'||g FROM generate_series(1,100) g", [org]);
    await h.migrator.query("INSERT INTO usage_record(org_id, signal, telco_id, outcome, billable, total_ms, telco_ms, correlation_id) SELECT $1,'SIM_SWAP','telco-a','FALSE',true,800,790,'slow-'||g FROM generate_series(1,5) g", [org]);
    await refreshRollups(h.worker);
    const d = await dash({ ...WIDE(), orgId: org });
    expect(d.traffic.requests).toBe(105);
    expect([d.latency.total.p50, d.latency.total.p95, d.latency.total.p99]).toEqual([50, 50, 1000]);         // 30 ms -> (25,50]; 800 ms -> (500,1000]
    expect([d.latency.telco.p50, d.latency.telco.p95, d.latency.telco.p99]).toEqual([25, 25, 1000]);          // 20 ms -> (10,25]
    expect([d.latency.overhead.p50, d.latency.overhead.p95, d.latency.overhead.p99]).toEqual([25, 25, 25]);   // overhead 10 ms (and 10 ms for the slow ones) -> (5,10]/(10,25]
  });
});

describe("ACCEPTANCE: dashboard totals reconcile with usage records", () => {
  beforeAll(async () => {
    for (let i = 0; i < 6; i++) await call(h.bankA, "sim-swap", num(i % 2 ? "1" : "0", mid()));
    for (let i = 0; i < 3; i++) await call(h.bankA, "sim-swap", numC("0", mid()));
    for (let i = 0; i < 2; i++) await call(h.bankA, "kyc-match", num("0", mid()), { name: "Synthetic Person" });
    for (const dgt of ["3", "4", "2"]) await call(h.bankA, "sim-swap", num(dgt, mid()));                    // telco faults: not billable
    await call(h.bankA, "device-swap", numB("0", mid()));                                                    // NOT_SUPPORTED
    await h.call(h.bankA, "POST", "/v1/signals/sim-swap/check", { body: body(num("0", mid()), "CONSENT-NOPE-0009") });   // REJECTED
    for (let i = 0; i < 4; i++) await call(h.bankB, "sim-swap", numB(i % 2 ? "1" : "0", mid()));
    for (let i = 0; i < 2; i++) await call(h.bankB, "call-forwarding", numB("0", mid()));
    await call(h.bankB, "sim-swap", numB("3", mid()));
    await h.app.drainLogs(); await refreshRollups(h.worker);
  });
  const sql = async (where = "TRUE", params: unknown[] = []) => (await h.migrator.query(`SELECT count(*)::int n, count(*) FILTER (WHERE billable)::int b FROM usage_record WHERE ${where}`, params)).rows[0] as { n: number; b: number };

  it("total requests and billable volume equal the usage records exactly", async () => {
    const d = await dash(WIDE()); const u = await sql();
    expect(d.traffic.requests).toBe(u.n); expect(d.traffic.billable).toBe(u.b); expect(d.business.billableVolume).toBe(u.b);
    expect(u.n).toBeGreaterThan(20);
  });
  it("every outcome count and every error type equals the usage records", async () => {
    const d = await dash(WIDE());
    const by = async (col: string) => Object.fromEntries((await h.migrator.query(`SELECT ${col} k, count(*)::int n FROM usage_record WHERE org_id IN (SELECT id FROM organisations) GROUP BY 1`)).rows.map((r) => [r.k as string, r.n as number]));
    const outcomes = await by("outcome"), reasons = await by("reason_class");
    for (const [k, n] of Object.entries(outcomes)) expect(d.reliability.outcomes[k], k).toBe(n);
    expect(Object.keys(d.reliability.outcomes).sort()).toEqual(Object.keys(outcomes).sort());
    for (const [k, n] of Object.entries(reasons)) expect(d.reliability.byReason[k], k).toBe(n);
    expect(d.reliability.outcomes["REJECTED"]).toBeGreaterThanOrEqual(1); expect(d.reliability.byReason["telco_fault"]).toBeGreaterThanOrEqual(2); expect(d.reliability.byReason["timeout"]).toBeGreaterThanOrEqual(1);
  });
  it("breakdowns by telco, signal and participant add up to the same totals and match the records", async () => {
    const d = await dash(WIDE()); const u = await sql();
    expect(d.traffic.byTelco.reduce((s, x) => s + x.requests, 0)).toBe(u.n); expect(d.traffic.byOrg.reduce((s, x) => s + x.requests, 0)).toBe(u.n);
    for (const t of ["telco-a", "telco-b", "telco-c"]) expect((await dash({ ...WIDE(), telcoId: t })).traffic.requests, t).toBe((await sql("telco_id = $1", [t])).n);
    for (const sg of ["SIM_SWAP", "KYC_MATCH", "DEVICE_SWAP", "CALL_FORWARDING"]) expect((await dash({ ...WIDE(), signal: sg })).traffic.requests, sg).toBe((await sql("signal = $1", [sg])).n);
    expect((await dash({ ...WIDE(), version: "v1" })).traffic.requests).toBe(u.n); expect((await dash({ ...WIDE(), version: "v9" })).traffic.requests).toBe(0);
    const orgs = [h.orgA, h.orgB, latOrg]; let sum = 0;
    for (const o of orgs) { const dd = await dash({ ...WIDE(), orgId: o }); expect(dd.traffic.requests).toBe((await sql("org_id = $1", [o])).n); expect(dd.traffic.billable).toBe((await sql("org_id = $1", [o])).b); sum += dd.traffic.requests; }
    expect(sum).toBe(u.n);
    const combo = await dash({ ...WIDE(), orgId: h.orgA, telcoId: "telco-a", signal: "SIM_SWAP" }); expect(combo.traffic.requests).toBe((await sql("org_id=$1 AND telco_id='telco-a' AND signal='SIM_SWAP'", [h.orgA])).n);
  });
  it("the portal's screen and CSV export show the same numbers as the records", async () => {
    const u = await sql(); const page = await S["alice"]!.get("/dashboard?period=24h");
    expect(page.status).toBe(200); expect(page.text).toContain(`<td>${u.n}</td><td>${u.b}</td>`); expect(page.text).toContain("Data as of");
    const csv = (await S["sam"]!.get("/dashboard.csv?period=24h")).text;
    const val = (sec: string, m: string) => csv.split("\n").map((l) => l.split(",")).find((p) => p[0] === sec && p[1] === m)?.[2];
    expect(Number(val("traffic", "requests"))).toBe(u.n); expect(Number(val("traffic", "billable"))).toBe(u.b); expect(Number(val("business", "billable_volume"))).toBe(u.b);
    const month = new Date().toISOString().slice(0, 7); const rep = (await S["fiona"]!.get(`/reports/monthly.csv?month=${month}`)).text;
    expect(rep.split("\n").find((l) => l.startsWith("traffic,requests,"))).toBe(`traffic,requests,${u.n}`);
  });
  it("rebuilding rollups is idempotent: nothing is double-counted, and late data is picked up", async () => {
    const before = (await dash(WIDE())).traffic.requests;
    await refreshRollups(h.worker); await refreshRollups(h.worker, { from: new Date(Date.now() - 3 * 3600e3) });
    expect((await dash(WIDE())).traffic.requests).toBe(before);
    await call(h.bankA, "sim-swap", num("0", mid())); await refreshRollups(h.worker);
    const after = await dash(WIDE()); expect(after.traffic.requests).toBe(before + 1); expect(after.traffic.requests).toBe((await sql()).n);
  });
  it("freshness is stated and staleness is flagged", async () => {
    let d = await dash(WIDE()); expect(d.freshness.stale).toBe(false); expect(d.freshness.watermark).not.toBeNull();
    await h.migrator.query("UPDATE rollup_state SET watermark = now() - interval '1 hour'");
    d = await dash(WIDE()); expect(d.freshness.stale).toBe(true);
    expect((await S["alice"]!.get("/dashboard")).text).toContain("Rollups are stale");
    await refreshRollups(h.worker); expect((await dash(WIDE())).freshness.stale).toBe(false);
  });
  it("SLA attainment is computed per minute against the configurable target", async () => {
    const d = await dash(WIDE()); expect(d.reliability.sla.target).toBe(0.995);
    expect(d.reliability.successRate).toBeGreaterThan(0); expect(d.reliability.successRate).toBeLessThan(1);
    expect(d.reliability.sla.buckets).toBeGreaterThanOrEqual(1); expect(d.reliability.sla.breaches + 0).toBeGreaterThanOrEqual(0);
  });
  it("each organisation sees only its own figures; staff-only sections are hidden from restricted users", async () => {
    const own = await dash({ ...WIDE(), orgId: h.orgA }, false, h.orgA);
    expect(own.traffic.requests).toBe((await sql("org_id=$1", [h.orgA])).n);
    expect(own.traffic.byOrg).toEqual([]); expect(own.business.onboarding).toBeNull(); expect(own.business.coverage).toBeNull(); expect(own.business.telcoCost).toBeNull(); expect(own.security.abuseFlags).toBeNull();
    const widened = await dash({ ...WIDE(), orgId: h.orgB }, false, h.orgA);                     // asking for another organisation's figures from an org-scoped session
    expect(widened.traffic.requests).toBe(0);
    const pa = await S["banker-a"]!.get("/dashboard?period=24h"), pb = await S["banker-b"]!.get("/dashboard?period=24h");
    expect(pa.text).toContain(`<td>${(await sql("org_id=$1", [h.orgA])).n}</td>`); expect(pb.text).toContain(`<td>${(await sql("org_id=$1", [h.orgB])).n}</td>`);
    expect(pa.text).not.toContain("Share by participant"); expect((await S["banker-a"]!.get(`/dashboard?org=${h.orgB}`)).text).toContain(`<td>${(await sql("org_id=$1", [h.orgA])).n}</td>`);   // the org parameter is ignored
    expect((await S["banker-a"]!.get("/dashboard.csv")).status).toBe(200);
  });
  it("hostile or invalid filters are refused", async () => {
    for (const bad of ["period=1y", "org=abc", "telco=x;y", "signal=NOPE", "version=1.0", "from=a&to=b", `from=${new Date().toISOString()}&to=2000-01-01T00:00:00Z`]) expect((await S["alice"]!.get(`/dashboard?${bad}`)).status, bad).toBe(400);
    expect((await S["alice"]!.get("/reports/monthly?month=2026-13")).status).toBe(400);
  });
  it("the dashboard never touches the request path: rollups are the only source and are rebuilt by a role that cannot write anything else", async () => {
    await expect(h.worker.query("UPDATE usage_record SET billable=true")).rejects.toThrow(/permission denied|append-only/i);
    await expect(h.worker.query("INSERT INTO usage_record(org_id,signal,outcome,billable,total_ms,correlation_id) VALUES (gen_random_uuid(),'SIM_SWAP','TRUE',true,1,'x')")).rejects.toThrow(/permission denied/i);
    await expect(h.worker.query("SELECT * FROM audit_log")).rejects.toThrow(/permission denied/i);
    await expect(a.pool.query("DELETE FROM rollup_minute")).rejects.toThrow(/permission denied/i);
  });
});

describe("alerts: configurable thresholds, acknowledgement and escalation", () => {
  const T = () => new Date();
  it("a seeded burst of authentication failures opens an alert with a SIEM-ready event; it is not duplicated", async () => {
    for (let i = 0; i < 25; i++) await h.call(h.bankA, "POST", "/v1/signals/sim-swap/check", { body: body(num("0", mid()), "CONSENT-X-0001"), token: "garbage" });
    await h.app.drainLogs(); await refreshRollups(h.worker);
    const ev = await evaluateAlerts(h.worker, T());
    const opened = ev.find((e) => e.ruleId === "auth-failures-high")!;
    expect(opened).toMatchObject({ action: "alert.opened", severity: "warning", threshold: 20 }); expect(opened.observed).toBeGreaterThanOrEqual(25);
    expect((await evaluateAlerts(h.worker, T())).filter((e) => e.ruleId === "auth-failures-high")).toEqual([]);
    expect((await h.migrator.query("SELECT count(*)::int n FROM alert WHERE rule_id='auth-failures-high'")).rows[0].n).toBe(1);
    expect((await S["sam"]!.get("/alerts")).text).toContain("auth-failures-high");
  });
  it("acknowledgement stops escalation; an unacknowledged alert escalates after its window", async () => {
    // a second alert: replay rejections
    for (let i = 0; i < 7; i++) { const n = num("0", mid()); const k = await h.consent(h.bankA, n); const jti = "replay-" + Math.random().toString(36).slice(2, 12) + "abcdefgh"; const t = await h.token(h.bankA);
      await h.call(h.bankA, "POST", "/v1/signals/sim-swap/check", { body: body(n, k.ref), token: t, jti }); await h.call(h.bankA, "POST", "/v1/signals/sim-swap/check", { body: body(n, k.ref), token: t, jti }); }
    await h.app.drainLogs(); await refreshRollups(h.worker);
    expect((await evaluateAlerts(h.worker, T())).find((e) => e.ruleId === "replay-rejections")?.action).toBe("alert.opened");
    const ids = (await h.migrator.query("SELECT id, rule_id FROM alert WHERE status='open'")).rows as Array<{ id: string; rule_id: string }>;
    const authId = ids.find((r) => r.rule_id === "auth-failures-high")!.id, replayId = ids.find((r) => r.rule_id === "replay-rejections")!.id;
    expect((await S["sam"]!.post(`/alerts/${authId}/ack`, {})).status).toBe(302);                           // acknowledged by the security auditor
    expect((await S["fiona"]!.post(`/alerts/${replayId}/ack`, {})).status).toBe(403); expect((await S["banker-a"]!.post(`/alerts/${replayId}/ack`, {})).status).toBe(403);
    await h.migrator.query("UPDATE alert_rule SET window_minutes = 240 WHERE id IN ('auth-failures-high','replay-rejections')");     // a persistent condition: the burst is still inside the window an hour later
    const later = new Date(Date.now() + 60 * 60_000);                                                      // an hour later: both past their escalation time (30 and 15 minutes)
    await refreshRollups(h.worker, { now: later });
    const ev = await evaluateAlerts(h.worker, later);
    expect(ev.find((e) => e.ruleId === "replay-rejections")).toMatchObject({ action: "alert.escalated" });
    expect(ev.find((e) => e.ruleId === "auth-failures-high")).toBeUndefined();                             // acknowledged: no escalation
    const st = Object.fromEntries((await h.migrator.query("SELECT rule_id, status, acknowledged_by FROM alert WHERE rule_id IN ('auth-failures-high','replay-rejections')")).rows.map((r) => [r.rule_id as string, r]));
    expect(st["auth-failures-high"]).toMatchObject({ status: "acknowledged", acknowledged_by: "sam" }); expect(st["replay-rejections"]).toMatchObject({ status: "escalated" });
  });
  it("alerts resolve themselves when the condition clears", async () => {
    const far = new Date(Date.now() + 6 * 3600e3);
    await refreshRollups(h.worker, { now: far, from: new Date(Date.now() - 3 * 3600e3), to: new Date(far.getTime() + 60_000) });
    const ev = await evaluateAlerts(h.worker, far);
    expect(ev.filter((e) => e.action === "alert.resolved").map((e) => e.ruleId).sort()).toEqual(expect.arrayContaining(["auth-failures-high", "replay-rejections"]));
    expect((await h.migrator.query("SELECT count(*)::int n FROM alert WHERE status IN ('open','acknowledged','escalated') AND rule_id IN ('auth-failures-high','replay-rejections')")).rows[0].n).toBe(0);
  });
  it("thresholds are configurable by operations/admins only; every change is versioned and audited; a disabled rule does not fire", async () => {
    expect((await S["fiona"]!.post("/alerts/rules", { id: "auth-failures-high", metric: "auth_failures", comparator: "gt", threshold: "1000", windowMinutes: "10", severity: "warning", escalateAfter: "30", enabled: "on" })).status).toBe(403);
    expect((await S["sam"]!.post("/alerts/rules", { id: "auth-failures-high", metric: "auth_failures", comparator: "gt", threshold: "1000", windowMinutes: "10", severity: "warning", escalateAfter: "30", enabled: "on" })).status).toBe(403);
    expect((await S["olivia"]!.post("/alerts/rules", { id: "auth-failures-high", metric: "auth_failures", comparator: "gt", threshold: "1000", windowMinutes: "10", severity: "warning", escalateAfter: "30", enabled: "on" })).status).toBe(302);
    const hist = (await h.migrator.query("SELECT before_state, after_state, changed_by FROM alert_rule_history WHERE rule_id='auth-failures-high' ORDER BY version DESC LIMIT 1")).rows[0];
    expect(hist.changed_by).toBe("olivia"); expect(Number(hist.before_state.threshold)).toBe(20); expect(Number(hist.after_state.threshold)).toBe(1000);
    for (let i = 0; i < 25; i++) await h.call(h.bankA, "POST", "/v1/signals/sim-swap/check", { body: body(num("0", mid()), "CONSENT-X-0002"), token: "garbage" });
    await h.app.drainLogs(); await refreshRollups(h.worker);
    expect((await evaluateAlerts(h.worker, T())).find((e) => e.ruleId === "auth-failures-high")).toBeUndefined();     // 25 < 1000 now
    await S["olivia"]!.post("/alerts/rules", { id: "replay-rejections", metric: "replay_rejections", comparator: "gt", threshold: "0", windowMinutes: "10", severity: "critical", escalateAfter: "15" });   // disabled (checkbox absent)
    expect((await h.migrator.query("SELECT enabled FROM alert_rule WHERE id='replay-rejections'")).rows[0].enabled).toBe(false);
    expect((await h.migrator.query("SELECT outcome, detail_text FROM audit_log WHERE action='admin.alert.rule' AND actor='olivia' ORDER BY seq DESC LIMIT 1")).rows[0].detail_text).toContain('"enabled":false');
    await expect(h.migrator.query("UPDATE alert_rule_history SET changed_by='x'")).rejects.toThrow(/append-only|permission denied/i);
    await expect(a.pool.query("UPDATE alert_rule SET threshold=999999")).rejects.toThrow(/permission denied/i);
    for (const u of ["banker-a", "fiona", "ian"]) expect((await S[u]!.get("/alerts")).status, u).toBe(403);
  });
  it("service-level alerts: a collapse in success rate raises a critical alert, low volume does not", async () => {
    const quiet = await startHarness({ telcoTimeoutMs: 300 });
    try {
      const q = (n: string, ref: string) => quiet.call(quiet.bankA, "POST", "/v1/signals/sim-swap/check", { body: body(n, ref) });
      for (let i = 0; i < 3; i++) { const n = num("3", mid()); const k = await quiet.consent(quiet.bankA, n); await q(n, k.ref); }
      await quiet.app.drainLogs(); await refreshRollups(quiet.worker);
      expect((await evaluateAlerts(quiet.worker, T())).find((e) => e.ruleId === "success-rate-low")).toBeUndefined();      // 3 requests: below the evaluation floor
      for (let i = 0; i < 12; i++) { const n = num("3", mid()); const k = await quiet.consent(quiet.bankA, n); await q(n, k.ref); }
      await quiet.app.drainLogs(); await refreshRollups(quiet.worker);
      const ev = await evaluateAlerts(quiet.worker, T());
      expect(ev.find((e) => e.ruleId === "success-rate-low")).toMatchObject({ action: "alert.opened", severity: "critical" });
    } finally { await quiet.stop(); }
  });
  it("credential expiry and enumeration flags raise alerts", async () => {
    await h.migrator.query("UPDATE client_keys SET expires_at = now() + interval '10 days' WHERE client_id='bank-b'");
    await h.migrator.query("INSERT INTO abuse_flag(org_id, client_id, kind, observed, threshold, window_s, correlation_id) VALUES ($1,'bank-a','SEQUENTIAL_RANGE',30,20,600,'seed-corr-0001')", [h.orgA]);
    const ev = await evaluateAlerts(h.worker, T());
    expect((await h.migrator.query("SELECT status FROM alert WHERE rule_id='credentials-expiring' AND status IN ('open','acknowledged','escalated')")).rowCount).toBe(1);     // (already open: sandbox keys are short-lived) and not duplicated
    expect(ev.find((e) => e.ruleId === "enumeration-suspected")).toMatchObject({ action: "alert.opened", severity: "critical" });
    expect((await dash(WIDE())).security.credsNearExpiry).toBeGreaterThanOrEqual(1); expect((await dash(WIDE())).security.abuseFlags).toBeGreaterThanOrEqual(1);
  });
});

describe("alert evaluation edge cases", () => {
  it("an event written in the same millisecond as the evaluator's clock reading is still counted (regression: Postgres microseconds vs JS milliseconds)", async () => {
    const { metricValue } = await import("../../src/ops/alerts.js");
    const before = Number(await metricValue(h.worker, "abuse_flags", 60, new Date()));
    const edge = new Date(); edge.setMilliseconds(0);                                    // a clock reading 0..999 ms EARLIER than the row we are about to write
    await h.migrator.query("INSERT INTO abuse_flag(org_id, client_id, kind, observed, threshold, window_s, correlation_id, ts) VALUES ($1,'bank-a','CONSENT_PROBING',9,5,600,'edge-corr-0001', $2::timestamptz + interval '700 microseconds')", [h.orgA, edge]);
    expect(Number(await metricValue(h.worker, "abuse_flags", 60, edge))).toBe(before + 1);
  });
});

describe("retention and deletion", () => {
  it("expired logs, consents and old sessions are deleted; recent data, usage records and the audit log are kept", async () => {
    await h.migrator.query("INSERT INTO request_log(ts, correlation_id, method, route, http_status, outcome, total_ms) VALUES (now() - interval '200 days','old-corr-0001','POST','/v1/consents',200,'OK',1), (now() - interval '10 days','new-corr-0001','POST','/v1/consents',200,'OK',1)");
    const hash = Buffer.alloc(32, 7);
    await h.migrator.query("INSERT INTO consents(org_id, consent_ref, subject_hash, purpose_code, signals, granted_at, expires_at) VALUES ($1,'OLD-EXPIRED-0001',$2,'FRAUD_PREVENTION','{SIM_SWAP}', now() - interval '400 days', now() - interval '300 days'), ($1,'RECENT-EXPIRED-0001',$2,'FRAUD_PREVENTION','{SIM_SWAP}', now() - interval '20 days', now() - interval '10 days'), ($1,'VALID-0001',$2,'FRAUD_PREVENTION','{SIM_SWAP}', now(), now() + interval '30 days')", [h.orgA, hash]);
    const usage = (await h.migrator.query("SELECT count(*)::int n FROM usage_record")).rows[0].n, audit = (await h.migrator.query("SELECT count(*)::int n FROM audit_log")).rows[0].n;
    const r = await runRetention(h.worker);
    expect(r.requestLog).toBe(1); expect(r.consents).toBe(1);
    const left = (await h.migrator.query("SELECT correlation_id FROM request_log WHERE correlation_id IN ('old-corr-0001','new-corr-0001')")).rows.map((x) => x.correlation_id);
    expect(left).toEqual(["new-corr-0001"]);
    expect((await h.migrator.query("SELECT consent_ref FROM consents WHERE consent_ref IN ('OLD-EXPIRED-0001','RECENT-EXPIRED-0001','VALID-0001') ORDER BY 1")).rows.map((x) => x.consent_ref)).toEqual(["RECENT-EXPIRED-0001", "VALID-0001"]);
    expect((await h.migrator.query("SELECT count(*)::int n FROM usage_record")).rows[0].n).toBe(usage); expect((await h.migrator.query("SELECT count(*)::int n FROM audit_log")).rows[0].n).toBe(audit);
    expect((await runRetention(h.worker)).requestLog).toBe(0);                                              // idempotent
  });
  it("retention is configurable through the two-person process, with a floor so it can never be set to wipe logs", async () => {
    expect((await S["alice"]!.post("/changes/new", { kind: "SETTING", key: "logs.retention_days", value: "3" })).status).toBe(400);
    expect((await S["alice"]!.post("/changes/new", { kind: "SETTING", key: "logs.retention_days", value: '"x"' })).status).toBe(400);
    const r = await S["alice"]!.post("/changes/new", { kind: "SETTING", key: "logs.retention_days", value: "5000" }); expect(r.status).toBe(400);
    const ok = await S["alice"]!.post("/changes/new", { kind: "SETTING", key: "logs.retention_days", value: "30" }); expect(ok.status).toBe(302);
    expect((await S["alice"]!.post(`${ok.location}/approve`, {})).status).toBe(403);                         // not by the requester
    expect((await S["bob"]!.post(`${ok.location}/approve`, {})).status).toBe(302);
    await h.migrator.query("INSERT INTO request_log(ts, correlation_id, method, route, http_status, outcome, total_ms) VALUES (now() - interval '45 days','mid-corr-0001','POST','/v1/consents',200,'OK',1)");
    expect((await runRetention(h.worker)).requestLog).toBe(1);
    await su(async (c) => { await c.query("ALTER TABLE platform_setting DISABLE ROW LEVEL SECURITY"); await c.query("UPDATE platform_setting SET value='1' WHERE key='logs.retention_days'"); await c.query("ALTER TABLE platform_setting ENABLE ROW LEVEL SECURITY"); });
    await h.migrator.query("INSERT INTO request_log(ts, correlation_id, method, route, http_status, outcome, total_ms) VALUES (now() - interval '3 days','young-corr-0001','POST','/v1/consents',200,'OK',1)");
    const swept = await runRetention(h.worker);
    expect(swept.requestLog).toBe(1);                                                                        // the 10-day-old row only: a corrupted setting of 1 day still has a 7-day floor
    expect((await h.migrator.query("SELECT correlation_id FROM request_log WHERE correlation_id IN ('new-corr-0001','young-corr-0001')")).rows.map((x) => x.correlation_id)).toEqual(["young-corr-0001"]);
  });
  it("only the worker role can delete, and only expired rows", async () => {
    for (const pool of [a.pool, h.pool, h.reporting]) await expect(pool.query("DELETE FROM request_log WHERE true")).rejects.toThrow(/permission denied|retention/i);
    await expect(h.worker.query("DELETE FROM usage_record")).rejects.toThrow(/permission denied/i);
    await expect(h.worker.query("DELETE FROM audit_log")).rejects.toThrow(/permission denied/i);
    await expect(h.worker.query("DELETE FROM statement")).rejects.toThrow(/permission denied/i);
  });
});

describe("dependency health", () => {
  it("staff see database, rollup worker, audit chain, alerts and telco connection health; others do not", async () => {
    const r = await S["ian"]!.get("/health"); expect(r.status).toBe(200);
    for (const t of ["Database", "Rollup worker", "Audit chain", "Open or escalated alerts", "Retention", "telco-a", "telco-b", "telco-c"]) expect(r.text).toContain(t);
    for (const u of ["banker-a", "fiona"]) expect((await S[u]!.get("/health")).status, u).toBe(403);
    await h.migrator.query("UPDATE rollup_state SET updated_at = now() - interval '1 hour'");
    expect((await S["ian"]!.get("/health")).text).toContain("STALE");
  });
});
