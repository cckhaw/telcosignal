import { describe, it, expect } from "vitest";
import { startHarness, num, numB, numC, type Harness } from "../helpers/harness.js";
import { isTelcoFault, ResilientAdapter } from "../../src/resilience/breaker.js";
import type { AdapterResult, TelcoAdapter } from "../../src/adapters/types.js";

const body = (n: string, ref: string) => ({ phoneNumber: n, consentRef: ref, purposeCode: "FRAUD_PREVENTION" });
async function sim(h: Harness, n: string, path = "/v1/signals/sim-swap/check") {
  const c = await h.consent(h.bankA, n);
  return h.call(h.bankA, "POST", path, { body: body(n, c.ref) });
}
const cfg = { minRequests: 5, failureRate: 0.5, openMs: 700, windowMs: 10_000, maxConcurrent: 3 };
let m = 0; const uniq = () => String(1000 + m++).slice(-4);     // distinct synthetic numbers

describe("fault injection: circuit breaker", () => {
  it("sustained telco faults open the breaker; open => no telco calls, UNAVAILABLE, not billed; other telcos unaffected", async () => {
    const h = await startHarness({ resilience: cfg });
    try {
      for (let i = 0; i < 6; i++) expect((await sim(h, num("3", uniq()))).json.result).toBe("UNAVAILABLE");     // HTTP 500s
      expect(h.breakers.get("telco-a")!.getState().state).toBe("open");
      const before = h.telco.calls;
      const r = await sim(h, num("0", uniq()));                                       // a perfectly healthy number
      expect(r.status).toBe(200); expect(r.json.result).toBe("UNAVAILABLE");           // never a fabricated FALSE
      expect(h.telco.calls).toBe(before);
      const a = await h.migrator.query("SELECT detail_text FROM audit_log WHERE action='signal.sim_swap.check' ORDER BY seq DESC LIMIT 1");
      expect(a.rows[0].detail_text).toContain("circuit open");
      expect((await sim(h, numB("1", uniq()))).json.result).toBe("TRUE");               // telco B unaffected (bulkheaded per telco)
      expect((await sim(h, numC("1", uniq()))).json.result).toBe("TRUE");
      expect((await h.migrator.query("SELECT count(*)::int n FROM usage_record WHERE outcome='UNAVAILABLE' AND billable")).rows[0].n).toBe(0);
      expect(h.breakers.get("telco-b")!.getState().state).toBe("closed");
    } finally { await h.stop(); }
  });

  it("NOT_SUPPORTED does not need the connection: it is still answered while the telco's breaker is open", async () => {
    const h = await startHarness({ resilience: cfg });
    try {
      for (let i = 0; i < 6; i++) await sim(h, numB("3", uniq()));
      expect(h.breakers.get("telco-b")!.getState().state).toBe("open");
      expect((await sim(h, numB("0", uniq()), "/v1/signals/device-swap/check")).json.result).toBe("NOT_SUPPORTED");
    } finally { await h.stop(); }
  });

  it("recovery: after the open period one probe is allowed; success closes the breaker, failure re-opens it", async () => {
    const h = await startHarness({ resilience: cfg });
    try {
      for (let i = 0; i < 6; i++) await sim(h, num("3", uniq()));
      const br = h.breakers.get("telco-a")!;
      expect(br.getState().state).toBe("open");
      await new Promise((r) => setTimeout(r, 800));
      expect(br.getState().state).toBe("half_open");
      expect((await sim(h, num("3", uniq()))).json.result).toBe("UNAVAILABLE");       // probe fails
      expect(br.getState().state).toBe("open");
      await new Promise((r) => setTimeout(r, 800));
      const before = h.telco.calls;
      expect((await sim(h, num("1", uniq()))).json.result).toBe("TRUE");              // probe succeeds
      expect(h.telco.calls).toBe(before + 1); expect(br.getState().state).toBe("closed");
      expect((await sim(h, num("0", uniq()))).json.result).toBe("FALSE");             // traffic flows again
    } finally { await h.stop(); }
  });

  it("a flood of numbers the telco does not know (404 / rc=14) can NOT trip the breaker (no denial of service via enumeration)", async () => {
    const h = await startHarness({ resilience: cfg });
    try {
      for (let i = 0; i < 12; i++) expect((await sim(h, num("5", uniq()))).json.result).toBe("UNAVAILABLE");
      for (let i = 0; i < 12; i++) expect((await sim(h, numB("5", uniq()))).json.result).toBe("UNAVAILABLE");
      expect(h.breakers.get("telco-a")!.getState().state).toBe("closed");
      expect(h.breakers.get("telco-b")!.getState().state).toBe("closed");
      expect((await sim(h, num("1", uniq()))).json.result).toBe("TRUE");
    } finally { await h.stop(); }
  });

  it("timeouts count as faults and stay bounded (each request finishes within the 2 s budget)", async () => {
    const h = await startHarness({ resilience: { ...cfg, minRequests: 4 }, telcoTimeoutMs: 300 });
    try {
      const t0 = Date.now();
      for (let i = 0; i < 4; i++) expect((await sim(h, num("2", uniq()))).json.result).toBe("UNAVAILABLE");
      expect(Date.now() - t0).toBeLessThan(4 * 1000 + 800);
      expect(h.breakers.get("telco-a")!.getState().state).toBe("open");
      const t1 = Date.now(); await sim(h, num("2", uniq()));
      expect(Date.now() - t1).toBeLessThan(250);                                        // open breaker answers immediately, not after a timeout
    } finally { await h.stop(); }
  });

  it("garbage from a telco (malformed, wrong types, oversized) counts as a fault; a hostile telco cannot be used to get a TRUE/FALSE through", async () => {
    const h = await startHarness({ resilience: { ...cfg, minRequests: 6 } });
    try {
      const out: string[] = [];
      for (const d of ["4", "6", "7", "4", "6", "7"]) out.push((await sim(h, num(d, uniq()))).json.result);
      expect(out.every((x) => x === "UNAVAILABLE")).toBe(true);
      expect(h.breakers.get("telco-a")!.getState().state).toBe("open");
    } finally { await h.stop(); }
  });
});

describe("bulkhead (bounded concurrency per telco)", () => {
  it("at most N calls are in flight to one telco; the rest are refused immediately as UNAVAILABLE", async () => {
    const h = await startHarness({ resilience: { ...cfg, minRequests: 1000 }, telcoTimeoutMs: 600 });
    try {
      const nums = Array.from({ length: 9 }, () => num("2", uniq()));
      const cs = await Promise.all(nums.map((n) => h.consent(h.bankA, n)));
      const before = h.telco.calls;
      const t0 = Date.now();
      const rs = await Promise.all(nums.map((n, i) => h.call(h.bankA, "POST", "/v1/signals/sim-swap/check", { body: body(n, cs[i]!.ref) })));
      expect(h.telco.calls - before).toBeLessThanOrEqual(3);
      expect(rs.every((r) => r.status === 200 && r.json.result === "UNAVAILABLE")).toBe(true);
      expect(Date.now() - t0).toBeLessThan(2000);
      const reasons = (await h.migrator.query("SELECT detail_text FROM audit_log WHERE action='signal.sim_swap.check' ORDER BY seq DESC LIMIT 9")).rows.map((r) => r.detail_text as string);
      expect(reasons.filter((x) => x.includes("bulkhead full")).length).toBeGreaterThanOrEqual(6);
      expect(h.breakers.get("telco-a")!.getState().inFlight).toBe(0);                  // slots are always released
    } finally { await h.stop(); }
  });
});

describe("breaker unit behaviour (deterministic clock)", () => {
  const mk = (script: AdapterResult[]) => { let i = 0; const inner: TelcoAdapter = { telcoId: "t", supports: new Set(["SIM_SWAP"]), call: async () => script[Math.min(i++, script.length - 1)]!, close: async () => undefined }; return inner; };
  const ok: AdapterResult = { status: "FALSE", reason: "ok", telcoMs: 1 }, bad: AdapterResult = { status: "UNAVAILABLE", reason: "timeout", telcoMs: 1 };
  const req = { signal: "SIM_SWAP" as const, msisdn: "+60999", correlationId: "c" };

  it("opens at the failure rate, half-opens after the cool-down, allows exactly one probe at a time", async () => {
    let t = 0; const b = new ResilientAdapter(mk([bad, bad, bad, bad, bad, ok]), { windowMs: 10_000, minRequests: 5, failureRate: 0.5, openMs: 1000, maxConcurrent: 5 }, () => t);
    for (let i = 0; i < 5; i++) await b.call(req);
    expect(b.getState().state).toBe("open");
    expect((await b.call(req)).reason).toBe("circuit open");
    t = 1500; expect(b.getState().state).toBe("half_open");
    const probe = b.call(req); const second = await b.call(req);
    expect(second.reason).toContain("probe in progress"); await probe;
    expect(b.getState().state).toBe("closed");
  });
  it("old events age out of the window (a past incident does not keep the breaker biased)", async () => {
    let t = 0; const b = new ResilientAdapter(mk([bad, bad, bad, bad, ok, ok, ok, ok, ok, ok]), { windowMs: 1000, minRequests: 5, failureRate: 0.5, openMs: 1000, maxConcurrent: 5 }, () => t);
    for (let i = 0; i < 4; i++) await b.call(req);
    t = 5000; for (let i = 0; i < 6; i++) await b.call(req);
    expect(b.getState().state).toBe("closed");
  });
  it("an adapter that throws is handled as a fault, never propagated", async () => {
    const inner: TelcoAdapter = { telcoId: "t", supports: new Set(["SIM_SWAP"]), call: async () => { throw new Error("boom"); }, close: async () => undefined };
    const r = await new ResilientAdapter(inner).call(req);
    expect(r.status).toBe("UNAVAILABLE");
  });
  it("fault classification: client-data answers are not faults; transport/5xx/garbage are", () => {
    const f = (reason: string) => isTelcoFault({ status: "UNAVAILABLE", reason, telcoMs: 0 });
    for (const r of ["telco status 404", "telco status 422", "telco rc 14", "some fields not available"]) expect(f(r), r).toBe(false);
    for (const r of ["timeout", "transport error", "telco status 500", "telco status 503", "malformed json", "response failed schema validation", "response too large", "unparseable response", "aggregator response not bound to this request"]) expect(f(r), r).toBe(true);
    expect(isTelcoFault({ status: "FALSE", reason: "ok", telcoMs: 0 })).toBe(false);
  });
});
