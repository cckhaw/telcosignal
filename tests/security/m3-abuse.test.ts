import { describe, it, expect } from "vitest";
import { startHarness, num, numB, type Harness, type Json } from "../helpers/harness.js";

const body = (n: string, ref: string) => ({ phoneNumber: n, consentRef: ref, purposeCode: "FRAUD_PREVENTION" });
const SIM = "/v1/signals/sim-swap/check";
async function simWithConsent(h: Harness, n: string, c = h.bankA): Promise<{ status: number; json: Json }> {
  const consent = await h.consent(c, n);
  return h.call(c, "POST", SIM, { body: body(n, consent.ref) });
}
/** Sequential numbers: identical except the last three digits (a typical range scan). */
const seq = (i: number) => `+6099900${"10"}${String(i).padStart(3, "0")}`;
const flags = async (h: Harness) => (await h.migrator.query("SELECT kind, observed, threshold, client_id, org_id FROM abuse_flag ORDER BY id")).rows;

describe("quotas and rate limits (participant x signal, subject, telco)", () => {
  it("per participant+signal quota: generic 429 once exceeded; other signals, other participants unaffected; override raises it; rejections are not billed", async () => {
    const h = await startHarness({ limits: { perParticipantSignalPerMinute: 5 } });
    try {
      const results: number[] = [];
      for (let i = 0; i < 8; i++) results.push((await simWithConsent(h, num("0", `03${i}0`))).status);
      expect(results.slice(0, 5).every((s) => s === 200)).toBe(true);
      expect(results.slice(5).every((s) => s === 429)).toBe(true);
      const limited = await simWithConsent(h, num("0", "0399"));
      expect(limited.json.code).toBe("RATE_LIMITED"); expect(Object.keys(limited.json).sort()).toEqual(["code", "correlationId", "message", "status"]);
      // another signal and another participant have their own budgets
      const c = await h.consent(h.bankA, num("0", "0398"));
      expect((await h.call(h.bankA, "POST", "/v1/signals/device-swap/check", { body: body(num("0", "0398"), c.ref) })).status).toBe(200);
      expect((await simWithConsent(h, num("0", "0397"), h.bankB)).status).toBe(200);
      // per-participant override (configurable) raises the limit for this participant only
      await h.migrator.query("INSERT INTO rate_limit_override(org_id, signal, max_per_minute) VALUES ($1,'SIM_SWAP',100)", [h.orgA]);
      expect((await simWithConsent(h, num("0", "0396"))).status).toBe(200);
      const { rows } = await h.migrator.query("SELECT billable FROM usage_record WHERE outcome='REJECTED'");
      expect(rows.length).toBeGreaterThanOrEqual(4); expect(rows.every((r) => r.billable === false)).toBe(true);
    } finally { await h.stop(); }
  });

  it("same participant repeatedly asking about the same number is limited; a different number or participant is not", async () => {
    const h = await startHarness({ limits: { perSubjectPerHour: 3 } });
    try {
      const n = num("0", "0410"); const c = await h.consent(h.bankA, n); const cb = await h.consent(h.bankB, n);
      const codes: number[] = [];
      for (let i = 0; i < 5; i++) codes.push((await h.call(h.bankA, "POST", SIM, { body: body(n, c.ref) })).status);
      expect(codes).toEqual([200, 200, 200, 429, 429]);
      expect((await simWithConsent(h, num("0", "0411"))).status).toBe(200);
      expect((await h.call(h.bankB, "POST", SIM, { body: body(n, cb.ref) })).status).toBe(200);
    } finally { await h.stop(); }
  });

  it("per-telco connection limit protects a telco without denying other telcos (answer is UNAVAILABLE, never a fabricated result)", async () => {
    const h = await startHarness({ limits: { perTelcoPerSecond: 3 } });
    try {
      const consents = await Promise.all(Array.from({ length: 8 }, (_, i) => h.consent(h.bankA, num("0", `042${i}`))));
      const before = h.telco.calls;
      const rs = await Promise.all(consents.map((c, i) => h.call(h.bankA, "POST", SIM, { body: body(num("0", `042${i}`), c.ref) })));
      const results = rs.map((r) => r.json.result as string);
      expect(results.filter((r) => r === "FALSE").length).toBeLessThanOrEqual(3);
      expect(results.filter((r) => r === "UNAVAILABLE").length).toBeGreaterThanOrEqual(5);
      expect(results.every((r) => r === "FALSE" || r === "UNAVAILABLE")).toBe(true);
      expect(h.telco.calls - before).toBeLessThanOrEqual(3);
      expect((await simWithConsent(h, numB("0", "0429"))).json.result).toBe("FALSE");   // telco B has its own budget
    } finally { await h.stop(); }
  });

  it("fails closed when the limiter store is unavailable (no telco call)", async () => {
    const { Redis } = await import("ioredis");
    const dead = new Redis("redis://127.0.0.1:1", { maxRetriesPerRequest: 0, enableOfflineQueue: false, lazyConnect: true, retryStrategy: () => null }); dead.on("error", () => undefined);
    const bad = { setNx: async () => true, incr: async () => { throw new Error("down"); }, get: async () => 0, addToSet: async () => 0, close: async () => undefined };
    const h = await startHarness({ store: bad });
    try {
      const n = num("0", "0430");
      // consent registration is quota-limited too (M5), so it also fails closed when the limiter store is down
      await expect(h.consent(h.bankA, n)).rejects.toThrow(/503/);
      // register the consent directly (as the application would have before the outage) to test the signal path
      const { subjectHash, createConsent } = await import("../../src/consent/consent.js"); const { withOrgTx } = await import("../../src/db/pool.js");
      const hash = await subjectHash(h.kms, n);
      await withOrgTx(h.pool, h.orgA, (tx) => createConsent(tx, h.orgA, { consentRef: "OUTAGE-CONSENT-1", subjectHash: hash, purpose: "FRAUD_PREVENTION", signals: ["SIM_SWAP"], expiresAt: new Date(Date.now() + 3.6e6) }));
      const cc = { ref: "OUTAGE-CONSENT-1" };
      const before = h.telco.calls;
      const r = await h.call(h.bankA, "POST", SIM, { body: body(n, cc.ref) });
      expect(r.status).toBe(503); expect(h.telco.calls).toBe(before);
    } finally { await h.stop(); dead.disconnect(); }
  });
});

describe("enumeration and bulk-lookup detection", () => {
  it("sequential range scan WITHOUT consent: alerted, flagged, audited; responses stay uniform; no number is stored anywhere", async () => {
    const h = await startHarness({ abuse: { sameRangeSubjects: 6, consentFailures: 5, distinctSubjects: 1000 } });
    try {
      const rs = [];
      for (let i = 0; i < 9; i++) rs.push(await h.call(h.bankA, "POST", SIM, { body: body(seq(i), "CONSENT-PROBE-0001") }));
      // uniform: identical status/code for every probe (detection must not turn into an existence oracle)
      expect(new Set(rs.map((r) => `${r.status}:${r.json.code}`)).size).toBe(1);
      expect(rs[0]!.status).toBe(403);
      const f = await flags(h);
      expect(f.map((x) => x.kind).sort()).toEqual(["CONSENT_PROBING", "SEQUENTIAL_RANGE"]);       // exactly one flag per kind per window
      expect(f.every((x) => x.client_id === "bank-a" && x.org_id === h.orgA)).toBe(true);
      const a = await h.migrator.query("SELECT action, outcome, detail_text FROM audit_log WHERE action='abuse.flagged'");
      expect(a.rows.length).toBe(2);
      const sec = h.logs.filter((l) => l.includes("abuse.enumeration_suspected"));
      expect(sec.length).toBe(2);
      // privacy: neither logs, flags, audit nor Redis keys/members contain any phone number
      const dump = JSON.stringify([f, a.rows]) + sec.join("") + h.logs.join("");
      expect(dump).not.toMatch(/\+?609990/);
      const { Redis } = await import("ioredis"); const r = new Redis(process.env["TS_TEST_REDIS_URL"] ?? "redis://127.0.0.1:6379/15");
      const keys = await r.keys("ab:*"); expect(keys.length).toBeGreaterThan(0);
      let members = ""; for (const k of keys) { if (k.startsWith("ab:d:") || k.startsWith("ab:r:")) members += (await r.smembers(k)).join(","); }
      expect(keys.join(",") + members).not.toMatch(/609990/); r.disconnect();
    } finally { await h.stop(); }
  });

  it("bulk lookup WITH valid consents (many distinct subjects) is flagged as HIGH_DISTINCT_SUBJECTS", async () => {
    const h = await startHarness({ abuse: { distinctSubjects: 12, sameRangeSubjects: 1000, consentFailures: 1000 } });
    try {
      for (let i = 0; i < 14; i++) await simWithConsent(h, num("0", `05${String(i).padStart(2, "0")}`));
      const f = await flags(h);
      expect(f.map((x) => x.kind)).toEqual(["HIGH_DISTINCT_SUBJECTS"]);
      expect(f[0]!.observed).toBeGreaterThanOrEqual(12);
    } finally { await h.stop(); }
  });

  it("normal low-volume use by another participant is not flagged, and flags are per organisation", async () => {
    const h = await startHarness({ abuse: { sameRangeSubjects: 6, consentFailures: 5, distinctSubjects: 20 } });
    try {
      for (let i = 0; i < 8; i++) await h.call(h.bankA, "POST", SIM, { body: body(seq(i), "CONSENT-PROBE-0002") });
      for (let i = 0; i < 4; i++) await simWithConsent(h, num("0", `06${i}0`), h.bankB);
      const f = await flags(h);
      expect(f.length).toBeGreaterThan(0);
      expect(f.every((x) => x.org_id === h.orgA)).toBe(true);
    } finally { await h.stop(); }
  });

  it("suspension: manual kill switch works at once; auto-suspend (when enabled) suspends only the offender, via a narrow definer function", async () => {
    const h = await startHarness({ abuse: { consentFailures: 4, sameRangeSubjects: 1000, distinctSubjects: 1000, autoSuspend: true } });
    try {
      for (let i = 0; i < 6; i++) await h.call(h.bankA, "POST", SIM, { body: body(seq(i), "CONSENT-PROBE-0003") });
      const ks = await h.migrator.query("SELECT scope, key, enabled FROM kill_switch");
      expect(ks.rows).toEqual([{ scope: "participant", key: "bank-a", enabled: true }]);
      const after = await h.call(h.bankA, "POST", SIM, { body: body(num("0", "0700"), "CONSENT-XXXX-0001") });
      expect(after.status).toBe(403); expect(after.json.code).toBe("ACCESS_DENIED");
      expect((await simWithConsent(h, num("0", "0701"), h.bankB)).status).toBe(200);              // other participants unaffected
      // the application role cannot write kill switches itself and the function only accepts known clients
      await expect(h.pool.query("INSERT INTO kill_switch(scope,key,enabled) VALUES ('telco','telco-a',true)")).rejects.toThrow(/permission denied/i);
      expect((await h.pool.query("SELECT abuse_suspend('no-such-client') AS ok")).rows[0].ok).toBe(false);
      const au = await h.migrator.query("SELECT action FROM audit_log WHERE action='participant.suspended'");
      expect(au.rows.length).toBeGreaterThanOrEqual(1);
    } finally { await h.stop(); }
  });

  it("participants can never read abuse flags or limit configuration of others (no grants for the application role)", async () => {
    const h = await startHarness();
    try {
      await expect(h.pool.query("SELECT * FROM abuse_flag")).rejects.toThrow(/permission denied/i);
      await expect(h.pool.query("INSERT INTO rate_limit_override(org_id,signal,max_per_minute) VALUES (gen_random_uuid(),'SIM_SWAP',1)")).rejects.toThrow(/permission denied/i);
      expect((await h.reporting.query("SELECT count(*)::int n FROM abuse_flag")).rows[0].n).toBe(0);
    } finally { await h.stop(); }
  });
});
