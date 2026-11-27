import { describe, it, expect, beforeAll, afterAll } from "vitest";
import pg from "pg";
import { startHarness, num, numB, numC, type Harness } from "../helpers/harness.js";
import { startAdmin, type Admin, type Session } from "../helpers/admin-harness.js";
import { csvLine } from "../../src/admin/dashboard.js";
import { CATALOGUE } from "../../src/common/errors.js";
import { classifyReason } from "../../src/resilience/classify.js";

let h: Harness, a: Admin; const S: Record<string, Session> = {};
const NUMS = { fail: num("3", "6001"), ok: num("1", "6002"), unsupported: numB("0", "6003"), noconsent: num("0", "6004"), timeout: num("2", "6005"), kyc: num("0", "6006") };
const corr: Record<string, string> = {};
const su = async <T>(fn: (c: pg.Client) => Promise<T>) => { const c = new pg.Client({ connectionString: h.adminUrl.replace(/\/[^/]*$/, `/${h.dbName}`) }); await c.connect(); try { return await fn(c); } finally { await c.end(); } };
const body = (n: string, ref: string) => ({ phoneNumber: n, consentRef: ref, purposeCode: "FRAUD_PREVENTION" });
beforeAll(async () => {
  h = await startHarness({ telcoTimeoutMs: 500 }); a = await startAdmin(h);
  for (const u of ["alice", "olivia", "sam", "fiona", "ian", "banker-a", "banker-b"]) S[u] = await a.login(u);
  const go = async (key: keyof typeof NUMS, path: string, signal = "sim-swap") => {
    const c = await h.consent(h.bankA, NUMS[key]); const r = await h.call(h.bankA, "POST", `/v1/signals/${signal}/check`, { body: body(NUMS[key], c.ref) });
    corr[key] = r.json.correlationId as string; return r;
  };
  await go("fail", "x"); await go("ok", "x"); await go("unsupported", "x", "device-swap"); await go("timeout", "x");
  const r = await h.call(h.bankA, "POST", "/v1/signals/sim-swap/check", { body: body(NUMS.noconsent, "CONSENT-NOPE-0001") }); corr["noconsent"] = r.json.correlationId;
  const badTok = await h.call(h.bankA, "POST", "/v1/signals/sim-swap/check", { body: body(NUMS.ok, "CONSENT-NOPE-0002"), token: "garbage" }); corr["badtoken"] = badTok.json.correlationId;
  const b = await h.call(h.bankB, "POST", "/v1/signals/sim-swap/check", { body: body(num("0", "6010"), "CONSENT-NOPE-0003") }); corr["bankB"] = b.json.correlationId;
  await h.app.drainLogs();
});
afterAll(async () => { await a.stop(); await h.stop(); });
const stripNonce = (t: string) => t.replace(/nonce="[^"]+"/g, "");

describe("ACCEPTANCE: a seeded failure is traced by correlation id", () => {
  it("the log search finds it by correlation id with the right classification", async () => {
    const r = await S["olivia"]!.get(`/logs?period=1h&correlation_id=${corr["fail"]}`);
    expect(r.status).toBe(200); expect(r.text).toContain(corr["fail"]!); expect(r.text).toContain("UNAVAILABLE"); expect(r.text).toContain("telco-a"); expect(r.text).toContain("telco_fault");
    expect(r.text).toMatch(/subject:[0-9a-f]{8}/);
  });
  it("the trace shows every step with timing, the router decision, the telco time vs platform overhead, and what to do", async () => {
    const r = await S["olivia"]!.get(`/logs/${corr["fail"]}`); expect(r.status).toBe(200);
    for (const step of ["auth", "signature", "validate", "policy", "limits", "consent", "route", "adapter", "finalise"]) expect(r.text, step).toContain(`<td>${step}</td>`);
    expect(r.text).toContain("gateway / WAF"); expect(r.text).toContain("telco status 500"); expect(r.text).toContain("telco-a");
    expect(r.text).toMatch(/platform overhead \d+ ms, telco \d+ ms/); expect(r.text).toContain("Suggested action");
    expect(r.text).toContain("Transport error, HTTP 5xx or an invalid/oversized response");     // the reason-class guidance
    expect(r.text).toContain("Real requests can never be replayed");
    const row = (await h.migrator.query("SELECT total_ms, telco_ms, steps FROM request_log WHERE correlation_id=$1", [corr["fail"]])).rows[0];
    const sum = (row.steps as Array<{ ms: number }>).reduce((x, y) => x + y.ms, 0);
    expect(row.total_ms).toBeGreaterThanOrEqual(row.telco_ms); expect(sum).toBeLessThanOrEqual(row.total_ms + 5);
  });
  it("a timeout, an unsupported signal, a consent rejection and an authentication failure are each traceable and classified", async () => {
    const q = async (k: string) => (await h.migrator.query("SELECT outcome, error_code, reason_class, telco_id, org_id, http_status, steps FROM request_log WHERE correlation_id=$1", [corr[k]])).rows[0];
    expect(await q("timeout")).toMatchObject({ outcome: "UNAVAILABLE", reason_class: "timeout", telco_id: "telco-a" });
    expect(await q("unsupported")).toMatchObject({ outcome: "NOT_SUPPORTED", reason_class: "unsupported", telco_id: "telco-b" });
    const nc = await q("noconsent"); expect(nc).toMatchObject({ outcome: "REJECTED", error_code: "CONSENT_REQUIRED", http_status: 403, reason_class: "rejected" });
    expect((nc.steps as Array<{ s: string }>).map((x) => x.s)).toEqual(["auth", "signature", "validate", "policy", "limits", "consent"]);      // stops where it was rejected
    const bt = await q("badtoken"); expect(bt).toMatchObject({ outcome: "REJECTED", error_code: "AUTHENTICATION_FAILED", http_status: 401, org_id: null });
    const t = await S["alice"]!.get(`/logs/${corr["badtoken"]}`); expect(t.status).toBe(200); expect(t.text).toContain("(unidentified)"); expect(t.text).toContain("AUTHENTICATION_FAILED");
    expect(t.text).toContain("Check credentials (expiry, revocation, certificate thumbprint)");       // the operator view shows the operator action
  });
  it("unknown or malformed correlation ids are a clean 404 and leak nothing", async () => {
    for (const id of ["00000000-0000-4000-8000-000000000000", "short", "x'; DROP TABLE request_log;--", "A".repeat(70)]) expect((await S["olivia"]!.get(`/logs/${encodeURIComponent(id)}`)).status, id).toBe(404);
  });
  it("search filters work and hostile filter input is refused without reaching SQL", async () => {
    const byOutcome = await S["olivia"]!.get("/logs?period=1h&outcome=NOT_SUPPORTED"); expect(byOutcome.text).toContain(corr["unsupported"]!); expect(byOutcome.text).not.toContain(corr["fail"]!);
    const byCode = await S["olivia"]!.get("/logs?period=1h&error_code=CONSENT_REQUIRED"); expect(byCode.text).toContain(corr["noconsent"]!);
    const byTelco = await S["olivia"]!.get("/logs?period=1h&telco=telco-b"); expect(byTelco.text).toContain(corr["unsupported"]!); expect(byTelco.text).not.toContain(corr["ok"]!);
    const bySignal = await S["olivia"]!.get("/logs?period=1h&signal=DEVICE_SWAP"); expect(bySignal.text).toContain(corr["unsupported"]!);
    const byClient = await S["olivia"]!.get("/logs?period=1h&client=bank-b"); expect(byClient.text).toContain(corr["bankB"]!); expect(byClient.text).not.toContain(corr["fail"]!);
    for (const bad of ["outcome=x' OR '1'='1", "error_code=lower", "correlation_id=%27--", "org=not-a-uuid", "period=forever", "from=garbage&to=garbage", "signal=DROP", "telco=A;B"]) expect((await S["olivia"]!.get(`/logs?${bad}`)).status, bad).toBe(400);
  });
});

describe("ACCEPTANCE: no raw phone number appears in any screen or export", () => {
  const PAGES = ["/", "/orgs", "/changes", "/config", "/history", "/credentials", "/killswitches", "/integration", "/dashboard", "/logs", "/alerts", "/audit", "/health", "/errors", "/reports/monthly", "/logs.csv", "/dashboard.csv", "/reports/monthly.csv"];
  const digits = Object.values(NUMS).map((n) => n.slice(1));
  const FULL_NUMBER = /\+[1-9][0-9]{8,14}/;       // a whole subscriber number (route prefixes such as +6099900 are shorter and are configuration, not subscribers)
  it("every page and export, for every role, contains none of the numbers used (nor any full-length number)", async () => {
    for (const u of ["alice", "olivia", "sam", "fiona", "ian", "banker-a", "banker-b"]) {
      const pages = [...PAGES, `/logs/${corr["fail"]}`, `/logs/${corr["noconsent"]}`, `/logs/${corr["ok"]}`];
      for (const p of pages) {
        const r = await S[u]!.get(p); if (r.status !== 200) continue;
        for (const d of digits) expect(r.text.includes(d), `${u} ${p} leaks ${d.slice(0, 5)}…`).toBe(false);
        expect(FULL_NUMBER.test(r.text), `${u} ${p} contains a full number`).toBe(false);
      }
    }
  });
  it("the log search by a number is impossible (there is no unmask or lookup-by-number function)", async () => {
    for (const q of [`correlation_id=${encodeURIComponent(NUMS.fail)}`, `client=${encodeURIComponent(NUMS.fail)}`, `error_code=${encodeURIComponent(NUMS.fail)}`]) expect((await S["olivia"]!.get(`/logs?${q}`)).status).toBe(400);
    for (const p of ["/logs/unmask", "/logs/unmask/x", "/unmask", "/logs?unmask=1&reveal=true"]) { const r = await S["olivia"]!.get(p); expect(r.text).not.toMatch(/\+[1-9][0-9]{8,14}/); }
  });
  it("the database itself rejects any phone number in the request log or incident notes", async () => {
    const ins = (reason: string, route = "/v1/consents", steps = "[]") => h.migrator.query("INSERT INTO request_log(correlation_id, method, route, http_status, outcome, reason, total_ms, steps) VALUES ('cid-12345678','POST',$1,200,'OK',$2,1,$3::jsonb)", [route, reason, steps]);
    await expect(ins("failed for +609990000001")).rejects.toThrow(/check constraint/i);
    await expect(ins("fine", "/v1/x/+609990000001")).rejects.toThrow(/check constraint/i);
    await expect(ins("fine", "/v1/consents", '[{"s":"+609990000001","ms":1}]')).rejects.toThrow(/check constraint/i);
    await expect(h.migrator.query("INSERT INTO request_log(correlation_id, method, route, http_status, outcome, total_ms, subject_ref) VALUES ('cid-12345678','POST','/v1/consents',200,'OK',1,'+60999000')")).rejects.toThrow(/check constraint/i);
    await expect(h.migrator.query("INSERT INTO incident_note(author, body) VALUES ('alice','call +609990000001 back')")).rejects.toThrow(/check constraint/i);
    expect((await ins("fine, no numbers")).rowCount).toBe(1);
  });
  it("neither the request log nor the rollups contain any stored number (full-table scan)", async () => {
    const dump = JSON.stringify([(await h.migrator.query("SELECT * FROM request_log")).rows, (await h.migrator.query("SELECT * FROM usage_record")).rows]);
    for (const d of digits) expect(dump).not.toContain(d);
    expect(FULL_NUMBER.test(dump)).toBe(false);
  });
  it("incident notes with numbers are refused by the portal; clean notes are accepted and permanent", async () => {
    expect((await S["olivia"]!.post("/notes", { correlationId: corr["fail"]!, body: `customer +609990000001 called` })).status).toBe(400);
    expect((await S["olivia"]!.post("/notes", { correlationId: corr["fail"]!, body: "telco A returned 500s; escalated to the telco NOC" })).status).toBe(302);
    expect((await S["olivia"]!.get(`/logs/${corr["fail"]}`)).text).toContain("escalated to the telco NOC");
    await expect(h.migrator.query("UPDATE incident_note SET body='x'")).rejects.toThrow(/append-only|permission denied/i);
    await expect(h.migrator.query("DELETE FROM incident_note")).rejects.toThrow(/append-only|permission denied/i);
    expect((await S["sam"]!.post("/notes", { correlationId: corr["fail"]!, body: "auditor note" })).status).toBe(302);
    expect((await S["fiona"]!.post("/notes", { correlationId: corr["fail"]!, body: "finance note" })).status).toBe(403);
    expect((await S["banker-a"]!.post("/notes", { correlationId: corr["fail"]!, body: "bank note" })).status).toBe(403);
  });
  it("CSV exports cannot carry spreadsheet formulas (CSV injection)", () => {
    expect(csvLine(["=cmd|' /C calc'!A0", "+1+1", "-2+3", "@SUM(A1)", "ok", 'a,"b"'])).toBe(`'=cmd|' /C calc'!A0,'+1+1,'-2+3,'@SUM(A1),ok,"a,""b"""\n`);
  });
});

describe("logs: access control, immutability and retention rules", () => {
  it("a bank user sees only its own organisation's requests; another organisation's correlation id is a 404", async () => {
    const own = await S["banker-a"]!.get("/logs?period=1h"); expect(own.text).toContain(corr["fail"]!); expect(own.text).not.toContain(corr["bankB"]!);
    expect((await S["banker-a"]!.get(`/logs/${corr["bankB"]}`)).status).toBe(404);
    expect((await S["banker-b"]!.get(`/logs/${corr["bankB"]}`)).status).toBe(200);
    expect((await S["banker-a"]!.get(`/logs/${corr["badtoken"]}`)).status).toBe(404);          // unidentified (pre-auth) failures are staff-only
    expect((await S["banker-a"]!.get(`/logs?period=1h&org=${h.orgB}`)).text).not.toContain(corr["bankB"]!);   // the org filter is ignored for restricted users
  });
  it("log exports are restricted to auditors/ops/admins and every export is audited with its row count", async () => {
    for (const u of ["fiona", "ian", "banker-a"]) expect((await S[u]!.get("/logs.csv?period=1h")).status, u).toBe(403);
    const r = await S["sam"]!.get("/logs.csv?period=1h"); expect(r.status).toBe(200); expect(String(r.headers["content-disposition"])).toContain("attachment");
    const lines = r.text.trim().split("\n"); expect(lines[0]).toContain("correlation_id"); expect(lines.length).toBeGreaterThan(5);
    const au = (await h.migrator.query("SELECT detail_text FROM audit_log WHERE action='admin.export' AND actor='sam' ORDER BY seq DESC LIMIT 1")).rows[0].detail_text as string;
    expect(JSON.parse(au)).toMatchObject({ kind: "logs", rows: lines.length - 1 });
  });
  it("logs cannot be edited or deleted by anyone, including administrators and the schema owner, until retention allows", async () => {
    for (const pool of [a.pool, h.pool, h.migrator, h.reporting]) {
      await expect(pool.query("UPDATE request_log SET outcome='OK'")).rejects.toThrow(/permission denied|append-only/i);
      await expect(pool.query("DELETE FROM request_log")).rejects.toThrow(/permission denied|retention/i);
      await expect(pool.query("TRUNCATE request_log")).rejects.toThrow(/permission denied|append-only/i);
    }
    await expect(h.worker.query("DELETE FROM request_log")).rejects.toThrow(/retention/i);            // even the retention job cannot delete recent rows
    await expect(h.worker.query("UPDATE request_log SET outcome='OK'")).rejects.toThrow(/permission denied/i);
  });
  it("observability never breaks serving: if the log write fails the request still succeeds and the failure is itself logged", async () => {
    await su(async (c) => { await c.query("REVOKE INSERT ON request_log FROM ts_app"); });
    try {
      const n = num("0", "6020"); const c = await h.consent(h.bankA, n);
      const r = await h.call(h.bankA, "POST", "/v1/signals/sim-swap/check", { body: body(n, c.ref) });
      expect(r.status).toBe(200); expect(r.json.result).toBe("FALSE");
      await h.app.drainLogs();
      expect((await h.migrator.query("SELECT count(*)::int n FROM request_log WHERE correlation_id=$1", [r.json.correlationId])).rows[0].n).toBe(0);
    } finally { await su(async (c) => { await c.query("GRANT INSERT ON request_log TO ts_app"); }); }
  });
});

describe("audit trail viewer", () => {
  it("auditors see the audit trail with chain verification; everyone else is refused; the view itself is audited", async () => {
    const r = await S["sam"]!.get("/audit"); expect(r.status).toBe(200); expect(r.text).toMatch(/intact \(\d+ records\)/); expect(r.text).toContain("signal.sim_swap.check");
    for (const u of ["fiona", "ian", "olivia", "banker-a"]) expect((await S[u]!.get("/audit")).status, u).toBe(403);
    expect((await h.migrator.query("SELECT 1 FROM audit_log WHERE action='admin.view.audit' AND actor='sam'")).rowCount).toBeGreaterThan(0);
    expect((await S["sam"]!.get("/audit?actor=bank-a&action=signal.sim_swap.check")).text).toContain("bank-a");
    for (const bad of ["actor=x'--", "action=UPPER", "correlation_id=%27"]) expect((await S["sam"]!.get(`/audit?${bad}`)).status).toBe(400);
  });
  it("tampering with the audit log is visible in the portal; the portal cannot write to it", async () => {
    await expect(a.pool.query("UPDATE audit_log SET outcome='OK'")).rejects.toThrow(/permission denied/i);
    await expect(a.pool.query("DELETE FROM audit_log")).rejects.toThrow(/permission denied/i);
    await su(async (c) => { await c.query("ALTER TABLE audit_log DISABLE TRIGGER audit_no_update"); await c.query("UPDATE audit_log SET outcome='TAMPERED' WHERE seq=2"); await c.query("ALTER TABLE audit_log ENABLE TRIGGER audit_no_update"); });
    const r = await S["sam"]!.get("/audit"); expect(r.text).toContain("BROKEN"); expect((await S["alice"]!.get("/health")).text).toContain("BROKEN");
  });
});

describe("error catalogue and reason classes", () => {
  it("every role can read it; it covers every error code with a suggested action", async () => {
    for (const u of Object.keys(S)) { const r = await S[u]!.get("/errors"); expect(r.status, u).toBe(200); for (const e of CATALOGUE) expect(r.text).toContain(e.code); }
    for (const e of CATALOGUE) { expect(e.meaning.length).toBeGreaterThan(20); expect(e.operatorAction.length).toBeGreaterThanOrEqual(5); expect(e.participantAction.length).toBeGreaterThanOrEqual(5); }
    expect(CATALOGUE.map((e) => e.code).sort()).toEqual(["ACCESS_DENIED", "AUTHENTICATION_FAILED", "CONSENT_REQUIRED", "INTERNAL", "INVALID_REQUEST", "NOT_FOUND", "PAYLOAD_TOO_LARGE", "RATE_LIMITED", "REPLAY_REJECTED", "SERVICE_UNAVAILABLE"]);
    expect((await S["sam"]!.get("/errors")).text).toContain("NEVER returned for a timeout, error or unsupported signal");
  });
  it("reason classification is deterministic and never reads request data", () => {
    const c = classifyReason;
    expect([c("FALSE", "ok"), c("UNAVAILABLE", "timeout"), c("UNAVAILABLE", "telco status 500"), c("UNAVAILABLE", "telco status 404"), c("UNAVAILABLE", "circuit open"), c("UNAVAILABLE", "bulkhead full"), c("UNAVAILABLE", "no route"), c("NOT_SUPPORTED", "telco does not cover this signal"), c("UNAVAILABLE", "telco kill switch"), c("UNAVAILABLE", "telco connection rate limit"), c("REJECTED", "consent missing")])
      .toEqual(["ok", "timeout", "telco_fault", "client_data", "circuit_open", "bulkhead", "no_route", "unsupported", "kill_switch", "limit", "rejected"]);
  });
  it("the pages for numbers/ids that look like injection are escaped in the log views", async () => {
    await h.migrator.query("INSERT INTO request_log(correlation_id, method, route, http_status, outcome, reason, total_ms) VALUES ('xss-test-0001','POST','/v1/consents',400,'ERROR','<script>alert(1)</script>',1)");
    const r = await S["alice"]!.get("/logs/xss-test-0001"); expect(r.status).toBe(200);
    expect(stripNonce(r.text)).not.toContain("<script>alert(1)"); expect(r.text).toContain("&lt;script&gt;");
    void numC;
  });
});
