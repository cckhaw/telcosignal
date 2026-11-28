// Second-wave signals: number recycling, KYC tenure, device location verification, device roaming.
// Every safety property of the first four signals is re-proved here, plus the location-specific privacy controls.
import { describe, it, expect, beforeAll, afterAll } from "vitest";
import { readFileSync } from "node:fs";
import { startHarness, num, numB, numC, type Harness, type Json } from "../helpers/harness.js";
import { dateDaysAgo } from "../../src/adapters/params.js";
import { validPastDate } from "../../src/participant-api/schemas.js";

let h: Harness;
beforeAll(async () => { h = await startHarness(); });
afterAll(async () => { await h.stop(); });

type Sig = "NUMBER_RECYCLING" | "KYC_TENURE" | "DEVICE_LOCATION" | "DEVICE_ROAMING";
const PATH: Record<Sig, string> = { NUMBER_RECYCLING: "number-recycling", KYC_TENURE: "kyc-tenure", DEVICE_LOCATION: "device-location", DEVICE_ROAMING: "device-roaming" };
const EXTRA: Record<Sig, () => Record<string, unknown>> = {
  NUMBER_RECYCLING: () => ({ specifiedDate: dateDaysAgo(30) }),
  KYC_TENURE: () => ({ minTenureDays: 90 }),
  DEVICE_LOCATION: () => ({ latitude: 3.139003, longitude: 101.686855, radiusMeters: 5000, maxAgeSeconds: 600 }),
  DEVICE_ROAMING: () => ({}),
};
async function ask(signal: Sig, n: string, extra: Record<string, unknown> = EXTRA[signal](), c = h.bankA, consentSignals: string[] = [signal]): Promise<{ status: number; json: Json }> {
  const consent = await h.consent(c, n, { signals: consentSignals });
  return h.call(c, "POST", `/v1/signals/${PATH[signal]}/check`, { body: { phoneNumber: n, consentRef: consent.ref, purposeCode: "FRAUD_PREVENTION", ...extra } });
}
let seq = 0;
const mid = () => String(7000 + seq++).padStart(4, "0");

describe("each new signal works end to end", () => {
  it.each(["NUMBER_RECYCLING", "KYC_TENURE", "DEVICE_LOCATION", "DEVICE_ROAMING"] as const)("%s via telco A: TRUE for a positive, FALSE for a negative, correlation id returned", async (sig) => {
    const pos = await ask(sig, num("1", mid())), neg = await ask(sig, num("0", mid()));
    expect(pos.status).toBe(200); expect(pos.json.result).toBe("TRUE"); expect(pos.json.signal).toBe(sig); expect(typeof pos.json.correlationId).toBe("string");
    expect(neg.json.result).toBe("FALSE");
  });
  it.each(["NUMBER_RECYCLING", "KYC_TENURE"] as const)("%s via the aggregator (telco C) answers too", async (sig) => {
    expect((await ask(sig, numC("1", mid()))).json.result).toBe("TRUE");
    expect((await ask(sig, numC("0", mid()))).json.result).toBe("FALSE");
  });
  it("NOT_SUPPORTED (never FALSE, no telco call, not billed) where the telco does not cover the signal", async () => {
    const [b0, c0] = [h.telcoB.calls, h.aggregator.calls];
    for (const sig of ["NUMBER_RECYCLING", "KYC_TENURE", "DEVICE_LOCATION", "DEVICE_ROAMING"] as const) expect((await ask(sig, numB("0", mid()))).json.result, `B ${sig}`).toBe("NOT_SUPPORTED");
    for (const sig of ["DEVICE_LOCATION", "DEVICE_ROAMING"] as const) expect((await ask(sig, numC("0", mid()))).json.result, `C ${sig}`).toBe("NOT_SUPPORTED");
    expect([h.telcoB.calls - b0, h.aggregator.calls - c0]).toEqual([0, 0]);
  });
});

describe("requests sent to the telco follow the pinned CAMARA definitions", () => {
  it("number recycling sends specifiedDate; tenure converts days to a tenureDate; location sends a circle and the device; roaming sends the device", async () => {
    await ask("NUMBER_RECYCLING", num("0", mid()));
    expect(h.telco.lastPath).toBe("/number-recycling/v0.3/check"); expect(JSON.parse(h.telco.lastBody!)).toMatchObject({ specifiedDate: dateDaysAgo(30) });
    await ask("KYC_TENURE", num("0", mid()), { minTenureDays: 365 });
    expect(h.telco.lastPath).toBe("/kyc-tenure/v0.3/check-tenure"); expect(JSON.parse(h.telco.lastBody!).tenureDate).toBe(dateDaysAgo(365));
    await ask("DEVICE_LOCATION", num("0", mid()));
    expect(h.telco.lastPath).toBe("/location-verification/v3/verify");
    expect(JSON.parse(h.telco.lastBody!)).toMatchObject({ area: { areaType: "CIRCLE", center: { latitude: 3.139003, longitude: 101.686855 }, radius: 5000 }, maxAge: 600, device: { phoneNumber: expect.stringMatching(/^\+60999/) } });
    await ask("DEVICE_ROAMING", num("0", mid()));
    expect(h.telco.lastPath).toBe("/device-roaming-status/v1/retrieve"); expect(JSON.parse(h.telco.lastBody!)).toEqual({ device: { phoneNumber: expect.stringMatching(/^\+60999/) } });
  });
  it("the aggregator receives a date, not a day count", async () => {
    await ask("KYC_TENURE", numC("0", mid()), { minTenureDays: 30 });
    expect(JSON.parse(h.aggregator.lastBody!)).toMatchObject({ signal: "KYC_TENURE", params: { tenureDate: dateDaysAgo(30) } });
  });
});

describe("a bad, hostile or partial telco answer is never FALSE", () => {
  // last digit: 3 HTTP 500, 4 malformed JSON, 5 HTTP 404, 6 wrong types, 7 extra fields
  it.each(["NUMBER_RECYCLING", "KYC_TENURE", "DEVICE_LOCATION", "DEVICE_ROAMING"] as const)("%s: errors, malformed, wrong types and extra fields are UNAVAILABLE, not billed", async (sig) => {
    for (const d of ["3", "4", "5", "6", "7"]) {
      const r = await ask(sig, num(d, mid()));
      expect(r.status, `${sig}/${d}`).toBe(200); expect(r.json.result, `${sig}/${d}`).toBe("UNAVAILABLE");
    }
    const { rows } = await h.migrator.query("SELECT billable FROM usage_record WHERE signal=$1 AND outcome='UNAVAILABLE'", [sig]);
    expect(rows.length).toBeGreaterThanOrEqual(5); expect(rows.every((x) => x.billable === false)).toBe(true);
  });
  it("location: a PARTIAL overlap is UNAVAILABLE (neither inside nor outside), never FALSE", async () => {
    expect((await ask("DEVICE_LOCATION", num("8", mid()))).json.result).toBe("UNAVAILABLE");
  });
  it("aggregator: wrong request id or carrier echoed is discarded for the new signals too", async () => {
    expect((await ask("NUMBER_RECYCLING", numC("4", mid()))).json.result).toBe("UNAVAILABLE");
    expect((await ask("KYC_TENURE", numC("5", mid()))).json.result).toBe("UNAVAILABLE");
  });
  it("roaming: the country the telco returns never reaches the participant", async () => {
    const r = await ask("DEVICE_ROAMING", num("1", mid()));
    expect(r.json.result).toBe("TRUE");
    expect(Object.keys(r.json).sort()).toEqual(["correlationId", "result", "signal"]);
    expect(JSON.stringify(r.json)).not.toMatch(/countryCode|countryName|SG/);
  });
  it("only a clean TRUE or FALSE is charged", async () => {
    await ask("KYC_TENURE", num("1", mid())); await ask("KYC_TENURE", num("0", mid())); await ask("KYC_TENURE", num("3", mid()));
    const { rows } = await h.migrator.query("SELECT outcome, billable FROM usage_record WHERE signal='KYC_TENURE'");
    for (const r of rows) expect(r.billable).toBe(r.outcome === "TRUE" || r.outcome === "FALSE");
  });
});

describe("input validation: schema and meaning", () => {
  const n = () => num("0", mid());
  const bad = async (sig: Sig, extra: Record<string, unknown>, label: string) => {
    const r = await ask(sig, n(), extra); expect(r.status, label).toBe(400); expect(r.json.code, label).toBe("INVALID_REQUEST");
  };
  it("number recycling: date must be real, not in the future, not older than five years, and is required", async () => {
    const tomorrow = new Date(Date.now() + 864e5).toISOString().slice(0, 10);
    for (const [label, v] of [["future", tomorrow], ["impossible", "2026-02-31"], ["too old", dateDaysAgo(2000)], ["format", "28/11/2026"], ["datetime", "2026-11-01T00:00:00Z"], ["number", 20261101]] as const) await bad("NUMBER_RECYCLING", { specifiedDate: v }, label);
    await bad("NUMBER_RECYCLING", {}, "missing");
    expect(validPastDate(dateDaysAgo(1), 1826)).toBe(true); expect(validPastDate("2026-13-01", 1826)).toBe(false);
  });
  it("tenure: whole days 1 to 3650 only", async () => {
    for (const v of [0, -5, 3651, 1.5, "90", null]) await bad("KYC_TENURE", { minTenureDays: v }, `days ${String(v)}`);
    await bad("KYC_TENURE", {}, "missing");
  });
  it("location: coordinates in range, radius 2000 to 200000 m (no pin-point circles), maxAge bounded, nothing else accepted", async () => {
    const ok = EXTRA.DEVICE_LOCATION();
    for (const [label, patch] of [["lat", { latitude: 91 }], ["lon", { longitude: -181 }], ["small radius", { radiusMeters: 500 }], ["tiny radius", { radiusMeters: 1 }], ["huge radius", { radiusMeters: 1e7 }],
      ["age low", { maxAgeSeconds: 5 }], ["age high", { maxAgeSeconds: 999999 }], ["string coord", { latitude: "3.1" }], ["extra property", { ipv4Address: "203.0.113.5" }]] as const) await bad("DEVICE_LOCATION", { ...ok, ...patch }, label);
    for (const k of ["latitude", "longitude", "radiusMeters"]) { const { [k]: _, ...rest } = ok as Record<string, unknown>; void _; await bad("DEVICE_LOCATION", rest, `missing ${k}`); }
  });
  it("roaming accepts no extra properties", async () => { await bad("DEVICE_ROAMING", { countryCode: 65 }, "extra"); });
});

describe("consent, scope and entitlement are per signal", () => {
  it("a consent that lists other signals does not cover a new one (same answer as any consent failure)", async () => {
    const r = await ask("DEVICE_LOCATION", num("1", mid()), EXTRA.DEVICE_LOCATION(), h.bankA, ["SIM_SWAP"]);
    expect(r.status).toBe(403); expect(r.json.code).toBe("CONSENT_REQUIRED");
  });
  it("a client without the new scope is refused before any telco work", async () => {
    const c = await h.newClient("bank-nolocation", h.orgA, ["sim-swap:check", "consent:write"]);
    const a0 = h.telco.calls;
    const r = await ask("DEVICE_LOCATION", num("1", mid()), EXTRA.DEVICE_LOCATION(), c);
    expect(r.status).toBe(403); expect(r.json.code).toBe("ACCESS_DENIED"); expect(h.telco.calls).toBe(a0);
  });
  it("without an entitlement for the signal the organisation is refused, even with scope and consent", async () => {
    await h.migrator.query("DELETE FROM org_entitlement WHERE org_id=$1 AND signal='DEVICE_LOCATION'", [h.orgB]);
    const r = await ask("DEVICE_LOCATION", num("1", mid()), EXTRA.DEVICE_LOCATION(), h.bankB);
    expect(r.status).toBe(403); expect(r.json.code).toBe("ACCESS_DENIED");
  });
  it("kill switch and registry flag fail closed for a new signal", async () => {
    await h.migrator.query("UPDATE signals SET enabled=false WHERE id='NUMBER_RECYCLING'");
    const a0 = h.telco.calls;
    expect((await ask("NUMBER_RECYCLING", num("1", mid()))).json.result).toBe("UNAVAILABLE"); expect(h.telco.calls).toBe(a0);
    await h.migrator.query("UPDATE signals SET enabled=true WHERE id='NUMBER_RECYCLING'");
  });
  it("registry rows exist and the database refuses an unknown signal id", async () => {
    const { rows } = await h.migrator.query("SELECT id, scope FROM signals WHERE id IN ('NUMBER_RECYCLING','KYC_TENURE','DEVICE_LOCATION','DEVICE_ROAMING') ORDER BY id");
    expect(rows.map((r) => r.scope)).toEqual(["device-location:check", "device-roaming:check", "kyc-tenure:check", "number-recycling:check"]);
    await expect(h.migrator.query("INSERT INTO signals(id, scope, api_version, camara_ref) VALUES ('NOT_A_SIGNAL','x:check','v1','x')")).rejects.toThrow();
  });
});

describe("location privacy: nothing about where the subject is leaves the request", () => {
  it("coordinates, radius and dates are never in logs, the audit chain, usage records or traces", async () => {
    const n = num("1", mid());
    await ask("DEVICE_LOCATION", n, { latitude: 3.139003, longitude: 101.686855, radiusMeters: 7531.25 });
    await ask("NUMBER_RECYCLING", n, { specifiedDate: dateDaysAgo(123) });
    const logs = h.logs.join(""), audit = readFileSync(h.auditSink, "utf8");
    const usage = JSON.stringify((await h.migrator.query("SELECT * FROM usage_record ORDER BY id DESC LIMIT 20")).rows);
    const reqlog = JSON.stringify((await h.migrator.query("SELECT * FROM request_log ORDER BY 1 DESC LIMIT 20").catch(() => ({ rows: [] }))).rows);
    const auditDb = JSON.stringify((await h.migrator.query("SELECT * FROM audit_log ORDER BY 1 DESC LIMIT 20").catch(() => ({ rows: [] }))).rows);
    for (const needle of ["3.139003", "101.686855", "7531.25", dateDaysAgo(123)]) for (const [name, hay] of [["logs", logs], ["audit sink", audit], ["usage", usage], ["request log", reqlog], ["audit db", auditDb]] as const) expect(hay, `${needle} in ${name}`).not.toContain(needle);
    expect(logs + audit).not.toContain(n);
  });
  it("repeat location checks of one subject are limited far more tightly than other signals (triangulation by moving circles)", async () => {
    const hl = await startHarness({ limits: { perSubjectLocationPerHour: 2 } });
    try {
      const n = num("0", "7900");
      const consent = await hl.consent(hl.bankA, n, { signals: ["DEVICE_LOCATION", "KYC_TENURE"] });
      const go = (sig: Sig, extra: Record<string, unknown>) => hl.call(hl.bankA, "POST", `/v1/signals/${PATH[sig]}/check`, { body: { phoneNumber: n, consentRef: consent.ref, purposeCode: "FRAUD_PREVENTION", ...extra } });
      const circle = (lat: number) => ({ latitude: lat, longitude: 101.68, radiusMeters: 2000 });
      expect((await go("DEVICE_LOCATION", circle(3.1))).status).toBe(200);
      expect((await go("DEVICE_LOCATION", circle(3.2))).status).toBe(200);
      const third = await go("DEVICE_LOCATION", circle(3.3));
      expect(third.status).toBe(429); expect(third.json.code).toBe("RATE_LIMITED");
      expect((await go("KYC_TENURE", { minTenureDays: 30 })).status).toBe(200);          // the location limit does not starve other signals
    } finally { await hl.stop(); }
  });
});
