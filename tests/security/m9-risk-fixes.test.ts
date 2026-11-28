// M9: tests for the register items that could be fixed in code: R-009 (sliding-window limits), R-029 (cross-organisation location cap), R-033 (price coverage).
import { describe, it, expect, beforeAll, afterAll } from "vitest";
import { startHarness, num, type Harness } from "../helpers/harness.js";
import { __hitForTest } from "../../src/ratelimit/limits.js";
import type { EphemeralStore } from "../../src/common/store.js";

function memStore(): EphemeralStore {
  const m = new Map<string, number>();
  return { setNx: async () => true, incr: async (k) => { m.set(k, (m.get(k) ?? 0) + 1); return m.get(k)!; }, get: async (k) => m.get(k) ?? 0, addToSet: async () => 0, close: async () => undefined };
}

describe("R-009: rate limits are sliding windows, not fixed windows", () => {
  it("a burst split across a window edge is held to about one window's worth, not two", async () => {
    const s = memStore(); let allowed = 0;
    for (let i = 0; i < 10; i++) if (await __hitForTest(s, "t:a", 10, 10, 9_900)) allowed++;       // end of window 0
    expect(allowed).toBe(10);
    let second = 0;
    for (let i = 0; i < 10; i++) if (await __hitForTest(s, "t:a", 10, 10, 10_100)) second++;       // start of window 1: almost all of window 0 still counts
    expect(second).toBeLessThanOrEqual(2);                                                          // a fixed window would have allowed all 10 (20 in 0.2 s)
  });
  it("the allowance comes back as the old window slides away, and a quiet period resets it", async () => {
    const s = memStore();
    for (let i = 0; i < 10; i++) await __hitForTest(s, "t:b", 10, 10, 9_900);
    expect(await __hitForTest(s, "t:b", 10, 10, 19_000)).toBe(true);        // 9 s into window 1: the 10 earlier requests now weigh about 1
    const q = memStore();
    for (let i = 0; i < 10; i++) await __hitForTest(q, "t:c", 10, 10, 1_000);
    expect(await __hitForTest(q, "t:c", 10, 10, 31_000)).toBe(true);        // two windows later nothing counts
  });
  it("it still fails closed when the store is down", async () => {
    const down: EphemeralStore = { ...memStore(), incr: async () => { throw new Error("down"); } };
    await expect(__hitForTest(down, "t:d", 10, 10)).rejects.toMatchObject({ code: "SERVICE_UNAVAILABLE" });
  });
});

describe("R-029: location checks of one person are capped across all participants", () => {
  let h: Harness;
  beforeAll(async () => { h = await startHarness({ limits: { perSubjectLocationGlobalPerHour: 3 } }); });
  afterAll(async () => { await h.stop(); });
  it("a second organisation cannot restart the count", async () => {
    const n = num("0", "9300");
    const ca = await h.consent(h.bankA, n, { signals: ["DEVICE_LOCATION"] }), cb = await h.consent(h.bankB, n, { signals: ["DEVICE_LOCATION"] });
    const go = (c: typeof h.bankA, ref: string, lat: number) => h.call(c, "POST", "/v1/signals/device-location/check", { body: { phoneNumber: n, consentRef: ref, purposeCode: "FRAUD_PREVENTION", latitude: lat, longitude: 101.6, radiusMeters: 2000 } });
    expect((await go(h.bankA, ca.ref, 3.1)).status).toBe(200);
    expect((await go(h.bankB, cb.ref, 3.2)).status).toBe(200);
    expect((await go(h.bankA, ca.ref, 3.3)).status).toBe(200);
    const fourth = await go(h.bankB, cb.ref, 3.4);       // organisation B has made only 1 of its own allowed checks, but the person has been located 3 times in the hour
    expect(fourth.status).toBe(429); expect(fourth.json.code).toBe("RATE_LIMITED");
  });
});

describe("R-033: a signal must be priced before it can be granted, and a plan must price everything granted", () => {
  let h: Harness;
  beforeAll(async () => { h = await startHarness(); });
  afterAll(async () => { await h.stop(); });
  const plan = (id: string, prices: Record<string, number>) => h.migrator.query("INSERT INTO price_plan(id,currency,platform_fee_minor,signal_price_minor,tiers) VALUES ($1,'MYR',1,$2,'[{\"upTo\":null,\"pct\":100}]')", [id, JSON.stringify(prices)]);
  it("assigning a plan that leaves an entitled signal unpriced is refused, naming the signals", async () => {
    await plan("partial-1", { SIM_SWAP: 10 });
    await expect(h.migrator.query("INSERT INTO org_price_plan(org_id,plan_id,effective_from) VALUES ($1,'partial-1', now() - interval '1 day')", [h.orgC])).rejects.toThrow(/no price for entitled signal\(s\): .*DEVICE_LOCATION/);
  });
  it("granting an entitlement the current plan does not price is refused; a priced one is accepted; an organisation with no plan is not checked here", async () => {
    await h.migrator.query("DELETE FROM org_entitlement WHERE org_id=$1 AND signal <> 'SIM_SWAP'", [h.orgC]);
    await h.migrator.query("INSERT INTO org_price_plan(org_id,plan_id,effective_from) VALUES ($1,'partial-1', now() - interval '1 day')", [h.orgC]);
    await expect(h.migrator.query("INSERT INTO org_entitlement(org_id,signal,purposes) VALUES ($1,'DEVICE_SWAP','{FRAUD_PREVENTION}')", [h.orgC])).rejects.toThrow(/no price for signal DEVICE_SWAP/);
    await expect(h.migrator.query("UPDATE org_entitlement SET signal='KYC_TENURE' WHERE org_id=$1 AND signal='SIM_SWAP'", [h.orgC])).rejects.toThrow(/no price for signal KYC_TENURE/);
    await h.migrator.query("UPDATE org_entitlement SET purposes='{FRAUD_PREVENTION,TRANSACTION_RISK}' WHERE org_id=$1 AND signal='SIM_SWAP'", [h.orgC]);   // already priced: fine
    await h.migrator.query("DELETE FROM org_entitlement WHERE org_id=$1", [h.orgB]); await h.migrator.query("DELETE FROM org_price_plan WHERE org_id=$1", [h.orgB]);
    await h.migrator.query("INSERT INTO org_entitlement(org_id,signal,purposes) VALUES ($1,'DEVICE_ROAMING','{FRAUD_PREVENTION}')", [h.orgB]);          // no plan yet: allowed
  });
});

describe("R-015: the admin portal's request counters can be shared across instances", () => {
  it("two portal instances on one Redis share one budget (and each would allow its own without it)", async () => {
    const { startAdmin } = await import("../helpers/admin-harness.js");
    const { request } = await import("undici");
    const h = await startHarness();
    const redis = (h.store as unknown as { redis: import("ioredis").Redis }).redis;
    const a = await startAdmin(h, { perMinute: 6, rateLimitRedis: redis });
    const b = await startAdmin(h, { perMinute: 6, rateLimitRedis: redis, reuseUsers: true });
    try {
      const hit = async (x: typeof a) => { const r = await request(`${x.origin}/`, { dispatcher: x.agent, maxRedirections: 0 } as never); await r.body.dump(); return r.statusCode; };
      const codes: number[] = [];
      for (let i = 0; i < 3; i++) { codes.push(await hit(a)); codes.push(await hit(b)); }       // 6 requests, split across the two instances
      expect(codes.every((c) => c !== 429)).toBe(true);
      expect(await hit(a)).toBe(429);                                                        // the 7th, on either instance, is refused: the count is shared
      expect(await hit(b)).toBe(429);
    } finally { await a.stop(); await b.stop(); await h.stop(); }
  });
});
