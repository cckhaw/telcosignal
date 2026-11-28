import { describe, it, expect, beforeAll, afterAll } from "vitest";
import { createHash } from "node:crypto";
import { startHarness, num, numB, numC, type Harness } from "../helpers/harness.js";
import { tieredAmount, validateTiers } from "../../src/metering/pricing.js";
import { generateStatements } from "../../src/metering/statements.js";

describe("pricing arithmetic (integer minor units, placeholders)", () => {
  const tiers = [{ upTo: 5, pct: 100 }, { upTo: null, pct: 50 }];
  it("marginal tiers", () => {
    expect(tieredAmount(0, 100, tiers)).toBe(0);
    expect(tieredAmount(5, 100, tiers)).toBe(500);
    expect(tieredAmount(8, 100, tiers)).toBe(650);
    expect(tieredAmount(10, 100, tiers)).toBe(750);
  });
  it("half-up rounding applied once on the total, deterministic", () => {
    expect(tieredAmount(1, 3, [{ upTo: null, pct: 33 }])).toBe(1);       // 0.99 -> 1
    expect(tieredAmount(1, 1, [{ upTo: null, pct: 50 }])).toBe(1);       // 0.5 -> 1 (half-up)
    expect(tieredAmount(3, 1, [{ upTo: null, pct: 33 }])).toBe(1);       // 0.99 -> 1
  });
  it("no floating point: huge counts stay exact", () => {
    expect(tieredAmount(1_000_000_000, 123, [{ upTo: null, pct: 100 }])).toBe(123_000_000_000);
  });
  it("monotonic: more usage never costs less", () => {
    let prev = -1; for (let n = 0; n <= 40; n++) { const a = tieredAmount(n, 7, [{ upTo: 10, pct: 100 }, { upTo: 25, pct: 60 }, { upTo: null, pct: 30 }]); expect(a).toBeGreaterThanOrEqual(prev); prev = a; }
  });
  it("rejects malformed tier definitions and non-integer inputs", () => {
    expect(() => validateTiers([])).toThrow(); expect(() => validateTiers([{ upTo: 5, pct: 100 }])).toThrow();                 // must end open-ended
    expect(() => validateTiers([{ upTo: 10, pct: 100 }, { upTo: 5, pct: 90 }, { upTo: null, pct: 80 }])).toThrow();            // must ascend
    expect(() => validateTiers([{ upTo: null, pct: 101 }])).toThrow();
    expect(() => tieredAmount(1.5, 10, tiers)).toThrow(); expect(() => tieredAmount(1, 0.5, tiers)).toThrow();
  });
});

let h: Harness;
beforeAll(async () => { h = await startHarness(); });
afterAll(async () => { await h.stop(); });
const body = (n: string, ref: string, extra: Record<string, unknown> = {}) => ({ phoneNumber: n, consentRef: ref, purposeCode: "FRAUD_PREVENTION", ...extra });
const PATH = { SIM: "/v1/signals/sim-swap/check", DEV: "/v1/signals/device-swap/check", CF: "/v1/signals/call-forwarding/check", KYC: "/v1/signals/kyc-match/check" };
async function call(c: typeof h.bankA, path: string, n: string, extra: Record<string, unknown> = {}) {
  const k = await h.consent(c, n);
  return h.call(c, "POST", path, { body: body(n, k.ref, extra) });
}
let seqN = 0; const mid = () => String(2000 + seqN++).slice(-4);

describe("metering is append-only and failures are never charged", () => {
  it("generate mixed traffic", async () => {
    // seed placeholder pricing
    await h.migrator.query(`INSERT INTO price_plan(id, currency, platform_fee_minor, signal_price_minor, tiers) VALUES
      ('standard-v1','MYR',5,'{"SIM_SWAP":100,"DEVICE_SWAP":80,"CALL_FORWARDING":40,"KYC_MATCH":200,"NUMBER_RECYCLING":60,"KYC_TENURE":60,"DEVICE_LOCATION":150,"DEVICE_ROAMING":50}','[{"upTo":5,"pct":100},{"upTo":null,"pct":50}]'),
      ('premium-v1','MYR',0,'{"SIM_SWAP":90,"DEVICE_SWAP":70,"CALL_FORWARDING":30,"KYC_MATCH":180,"NUMBER_RECYCLING":55,"KYC_TENURE":55,"DEVICE_LOCATION":140,"DEVICE_ROAMING":45}','[{"upTo":null,"pct":100}]')`);
    await h.migrator.query("INSERT INTO org_price_plan(org_id, plan_id, effective_from) VALUES ($1,'standard-v1', now() - interval '30 days'), ($2,'premium-v1', now() - interval '30 days')", [h.orgA, h.orgB]);
    await h.migrator.query(`INSERT INTO telco_cost(telco_id, signal, cost_minor, effective_from) VALUES
      ('telco-a','SIM_SWAP',30,now()-interval '30 days'),('telco-a','DEVICE_SWAP',25,now()-interval '30 days'),('telco-a','CALL_FORWARDING',10,now()-interval '30 days'),('telco-a','KYC_MATCH',60,now()-interval '30 days'),
      ('telco-b','SIM_SWAP',35,now()-interval '30 days'),('telco-b','CALL_FORWARDING',12,now()-interval '30 days'),
      ('telco-c','SIM_SWAP',28,now()-interval '30 days'),('telco-c','DEVICE_SWAP',22,now()-interval '30 days'),('telco-c','KYC_MATCH',55,now()-interval '30 days')`);
    // bank A: 7 SIM via A, 3 SIM via C, 2 KYC via A  => all billable
    for (let i = 0; i < 7; i++) expect((await call(h.bankA, PATH.SIM, num(i % 2 ? "1" : "0", mid()))).json.result).toMatch(/TRUE|FALSE/);
    for (let i = 0; i < 3; i++) expect((await call(h.bankA, PATH.SIM, numC("0", mid()))).json.result).toBe("FALSE");
    for (let i = 0; i < 2; i++) expect((await call(h.bankA, PATH.KYC, num("0", mid()), { name: "Synthetic Person" })).json.result).toBe("TRUE");
    // bank A: things that must NOT be charged: telco faults, unsupported, consent rejections, unknown subscriber
    for (const d of ["3", "4", "6", "5"]) expect((await call(h.bankA, PATH.SIM, num(d, mid()))).json.result).toBe("UNAVAILABLE");
    for (let i = 0; i < 2; i++) expect((await call(h.bankA, PATH.DEV, numB("0", mid()))).json.result).toBe("NOT_SUPPORTED");
    for (let i = 0; i < 3; i++) expect((await h.call(h.bankA, "POST", PATH.SIM, { body: body(num("0", mid()), "CONSENT-NONE-0001") })).status).toBe(403);
    // bank B: 4 SIM via B, 2 call-forwarding via B, 1 fault
    for (let i = 0; i < 4; i++) expect((await call(h.bankB, PATH.SIM, numB(i % 2 ? "1" : "0", mid()))).json.result).toMatch(/TRUE|FALSE/);
    for (let i = 0; i < 2; i++) expect((await call(h.bankB, PATH.CF, numB("0", mid()))).json.result).toBe("FALSE");
    expect((await call(h.bankB, PATH.SIM, numB("3", mid()))).json.result).toBe("UNAVAILABLE");
  });

  it("usage records are append-only for every role, and only successes are billable", async () => {
    for (const pool of [h.pool, h.migrator, h.billing, h.reporting]) {
      await expect(pool.query("UPDATE usage_record SET billable = true")).rejects.toThrow(/permission denied|append-only/i);
      await expect(pool.query("DELETE FROM usage_record")).rejects.toThrow(/permission denied|append-only/i);
    }
    const { rows } = await h.migrator.query("SELECT outcome, billable, count(*)::int n FROM usage_record GROUP BY 1,2 ORDER BY 1,2");
    const by = Object.fromEntries(rows.map((r) => [`${r.outcome}:${r.billable}`, r.n]));
    expect(by["UNAVAILABLE:true"]).toBeUndefined(); expect(by["NOT_SUPPORTED:true"]).toBeUndefined(); expect(by["REJECTED:true"]).toBeUndefined();
    expect(by["UNAVAILABLE:false"]).toBe(5); expect(by["NOT_SUPPORTED:false"]).toBe(2); expect(by["REJECTED:false"]).toBe(3);
    expect((by["TRUE:true"] ?? 0) + (by["FALSE:true"] ?? 0)).toBe(18);                                    // 12 (A) + 6 (B)
  });
});

describe("statements reconcile with usage records", () => {
  // A billing period is FIXED: the same bounds must be used on every call (idempotency is per exact period).
  const P = { start: new Date(Date.now() - 3_600_000), end: new Date(Date.now() + 3_600_000) };
  const period = () => P;
  let created: string[] = [];

  it("generates participant and telco statements from the billing role in one snapshot", async () => {
    const r = await generateStatements(h.billing, period());
    expect(r.problems).toEqual([]); expect(r.created.length).toBe(2 + 3); created = r.created;     // A, B + telco a/b/c
  });

  it("participant totals equal an independent recomputation from known traffic (hard-coded expectation)", async () => {
    // Bank A: SIM 10 -> 5*100 + 5*50 = 750 (+10*5 fee = 50) = 800 ; KYC 2*200 = 400 (+2*5 = 10) = 410 ; total 1210, 12 billable queries
    // Bank B (premium, fee 0): SIM 4*90 = 360 ; CF 2*30 = 60 ; total 420, 6 billable queries
    const rows = (await h.reporting.query("SELECT org_id, total_minor::int t, usage_count, lines FROM statement WHERE kind='participant'")).rows;
    const a = rows.find((r) => r.org_id === h.orgA)!, b = rows.find((r) => r.org_id === h.orgB)!;
    expect([a.t, a.usage_count]).toEqual([1210, 12]); expect([b.t, b.usage_count]).toEqual([420, 6]);
    expect(a.lines.find((l: { signal: string }) => l.signal === "SIM_SWAP")).toMatchObject({ count: 10, tierAmountMinor: 750, platformFeeMinor: 50, amountMinor: 800, byTelco: { "telco-a": 7, "telco-c": 3 } });
  });

  it("statement counts and digests tie to the exact usage rows (nothing missing, nothing extra, nothing from failures)", async () => {
    for (const [org, expected] of [[h.orgA, 12], [h.orgB, 6]] as const) {
      const ids = (await h.migrator.query("SELECT id FROM usage_record WHERE org_id=$1 AND billable ORDER BY id", [org])).rows.map((r) => r.id);
      expect(ids.length).toBe(expected);
      const digest = createHash("sha256").update(ids.map((i) => `${i}\n`).join("")).digest("hex");
      const st = (await h.reporting.query("SELECT usage_count, encode(usage_digest,'hex') d FROM statement WHERE kind='participant' AND org_id=$1", [org])).rows[0];
      expect(st.usage_count).toBe(expected); expect(st.d).toBe(digest);
    }
  });

  it("telco settlement statements: cost x served volume, and they cross-reconcile with participant statements per telco and signal", async () => {
    // A: SIM 7*30 + KYC 2*60 = 330 ; B: SIM 4*35 + CF 2*12 = 164 ; C: SIM 3*28 = 84
    const t = Object.fromEntries((await h.reporting.query("SELECT telco_id, total_minor::int t, usage_count FROM statement WHERE kind='telco'")).rows.map((r) => [r.telco_id, [r.t, r.usage_count]]));
    expect(t).toEqual({ "telco-a": [330, 9], "telco-b": [164, 6], "telco-c": [84, 3] });
    const part = (await h.reporting.query("SELECT lines FROM statement WHERE kind='participant'")).rows.flatMap((r) => r.lines as Array<{ signal: string; byTelco: Record<string, number> }>);
    const fromParticipants = new Map<string, number>();
    for (const l of part) for (const [telco, n] of Object.entries(l.byTelco)) fromParticipants.set(`${telco}:${l.signal}`, (fromParticipants.get(`${telco}:${l.signal}`) ?? 0) + n);
    const telcoLines = (await h.reporting.query("SELECT telco_id, lines FROM statement WHERE kind='telco'")).rows.flatMap((r) => (r.lines as Array<{ signal: string; count: number }>).map((l) => [`${r.telco_id}:${l.signal}`, l.count] as const));
    expect(new Map(telcoLines)).toEqual(fromParticipants);
    // platform margin = revenue - telco cost, from statements, equals the independent figure
    const rev = (await h.reporting.query("SELECT sum(total_minor)::int s FROM statement WHERE kind='participant'")).rows[0].s;
    const cost = (await h.reporting.query("SELECT sum(total_minor)::int s FROM statement WHERE kind='telco'")).rows[0].s;
    expect([rev, cost, rev - cost]).toEqual([1630, 578, 1052]);
  });

  it("is idempotent and statements are immutable", async () => {
    const again = await generateStatements(h.billing, period());
    expect(again.created).toEqual([]); expect(again.skipped).toBe(5);
    for (const pool of [h.migrator, h.billing, h.pool]) {
      await expect(pool.query("UPDATE statement SET total_minor = 1")).rejects.toThrow(/permission denied|append-only/i);
      await expect(pool.query("DELETE FROM statement")).rejects.toThrow(/permission denied|append-only/i);
    }
    expect((await h.reporting.query("SELECT count(*)::int n FROM statement")).rows[0].n).toBe(created.length);
  });

  it("overlapping periods are refused (double-billing guard): reported as a problem, no new statement, nothing charged twice", async () => {
    const before = (await h.reporting.query("SELECT count(*)::int n FROM statement")).rows[0].n;
    const r = await generateStatements(h.billing, { start: new Date(P.start.getTime() + 60_000), end: new Date(P.end.getTime() + 60_000) });
    expect(r.created).toEqual([]); expect(r.problems.some((x) => x.includes("overlaps"))).toBe(true);
    expect((await h.reporting.query("SELECT count(*)::int n FROM statement")).rows[0].n).toBe(before);
    await expect(h.migrator.query("INSERT INTO statement(kind, org_id, period_start, period_end, currency, lines, usage_count, total_minor, usage_digest) VALUES ('participant',$1,$2,$3,'MYR','[]',0,0,$4)", [h.orgA, new Date(P.start.getTime() + 1000), new Date(P.end.getTime() - 1000), Buffer.alloc(32)])).rejects.toThrow(/exclusion|overlap|conflicting/i);
  });

  it("usage outside the period is excluded; an empty period produces nothing", async () => {
    const past = { start: new Date(Date.now() - 86_400_000 * 10), end: new Date(Date.now() - 86_400_000 * 9) };
    const r = await generateStatements(h.billing, past);
    expect(r.created).toEqual([]);
  });

  it("missing prices are reported, never guessed: no statement is produced for an organisation without a plan", async () => {
    await call(h.bankC, PATH.SIM, num("0", mid())).catch(() => null);        // bank C has no sim-swap scope: nothing metered; create usage for a plan-less org directly
    await h.migrator.query("INSERT INTO usage_record(org_id, signal, telco_id, outcome, billable, total_ms, correlation_id, ts) VALUES ($1,'SIM_SWAP','telco-a','FALSE',true,5,'c', now() + interval '10 minutes')", [h.orgC]);
    const r = await generateStatements(h.billing, { start: new Date(Date.now() + 300_000), end: new Date(Date.now() + 1_200_000) });   // covers only the injected row
    expect(r.problems.some((p) => p.includes(h.orgC) && p.includes("no price plan"))).toBe(true);
    expect((await h.reporting.query("SELECT count(*)::int n FROM statement WHERE org_id=$1", [h.orgC])).rows[0].n).toBe(0);
  });
});

describe("statements: participant access and role separation", () => {
  it("each participant sees only its own statements; another organisation's id is indistinguishable from a nonexistent one; telco statements are invisible", async () => {
    const la = await h.call(h.bankA, "GET", "/v1/statements"), lb = await h.call(h.bankB, "GET", "/v1/statements");
    expect(la.status).toBe(200); expect(la.json.statements.length).toBe(1); expect(la.json.statements[0].totalMinor).toBe(1210);
    expect(lb.json.statements.length).toBe(1); expect(lb.json.statements[0].totalMinor).toBe(420);
    const idA = la.json.statements[0].id as string;
    const own = await h.call(h.bankA, "GET", `/v1/statements/${idA}`);
    expect(own.status).toBe(200); expect(own.json.lines.length).toBe(2);
    const cross = await h.call(h.bankB, "GET", `/v1/statements/${idA}`), none = await h.call(h.bankB, "GET", "/v1/statements/00000000-0000-4000-8000-000000000000");
    expect(cross.status).toBe(404); expect({ ...cross.json, correlationId: 0 }).toEqual({ ...none.json, correlationId: 0 });
    const telcoId = (await h.migrator.query("SELECT id FROM statement WHERE kind='telco' LIMIT 1")).rows[0].id as string;
    expect((await h.call(h.bankA, "GET", `/v1/statements/${telcoId}`)).status).toBe(404);
    expect((await h.pool.query("SELECT count(*)::int n FROM statement")).rows[0].n).toBe(0);               // no tenant context => nothing
    expect((await h.call(h.bankC, "GET", "/v1/statements")).status).toBe(403);                              // scope required
  });
  it("the billing role reads usage and prices only; the application role cannot create statements or change prices", async () => {
    await expect(h.billing.query("SELECT * FROM consents")).rejects.toThrow(/permission denied/i);
    await expect(h.billing.query("SELECT * FROM audit_log")).rejects.toThrow(/permission denied/i);
    await expect(h.billing.query("UPDATE price_plan SET platform_fee_minor = 0")).rejects.toThrow(/permission denied/i);
    await expect(h.pool.query("INSERT INTO statement(kind, org_id, period_start, period_end, currency, lines, usage_count, total_minor, usage_digest) VALUES ('participant',$1,now(),now()+interval '1 day','MYR','[]',0,0,$2)", [h.orgA, Buffer.alloc(32)])).rejects.toThrow(/permission denied|row-level security/i);
    await expect(h.pool.query("UPDATE price_plan SET platform_fee_minor = 0")).rejects.toThrow(/permission denied/i);
    await expect(h.pool.query("UPDATE telco_cost SET cost_minor = 0")).rejects.toThrow(/permission denied/i);
  });
});
