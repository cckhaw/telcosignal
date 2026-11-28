// Audit (M8): seeded fuzzing of the four second-wave endpoints through the full authenticated pipeline.
// Properties: never a 5xx, never a stack trace or internal word in the answer, never an accepted value outside the documented ranges,
// and nothing the caller sent is echoed back. Deterministic (seeded) so a failure reproduces.
import { describe, it, expect, beforeAll, afterAll } from "vitest";
import { startHarness, num, type Harness } from "../helpers/harness.js";

let h: Harness;
beforeAll(async () => { h = await startHarness(); });
afterAll(async () => { await h.stop(); });

const LEAK = /(\bat\s+[\w.<>]+\s+\(.*:\d+:\d+\)|node_modules|\.ts:\d+|postgres|ECONN|fastify|undici|stack|syntax error|SELECT |pg_|ajv|must match|must be)/i;
const ROUTES = ["number-recycling", "kyc-tenure", "device-location", "device-roaming"] as const;

// small deterministic PRNG (mulberry32)
function rng(seed: number) { let a = seed; return () => { a |= 0; a = (a + 0x6d2b79f5) | 0; let t = Math.imul(a ^ (a >>> 15), 1 | a); t = (t + Math.imul(t ^ (t >>> 7), 61 | t)) ^ t; return ((t ^ (t >>> 14)) >>> 0) / 4294967296; }; }
const NASTY: unknown[] = [null, true, false, 0, -0, 1, -1, 1.5, 1e308, -1e308, 1e-308, 2 ** 53, "", " ", "0", "NaN", "Infinity", "-1", "2026-02-31", "9999-12-31", "0000-01-01", "2026-11-28T00:00:00Z",
  "'; DROP TABLE signals; --", "\u0000", "\ud800", "‮", "../../etc/passwd", "<script>alert(1)</script>", "${7*7}", "{{7*7}}", "__proto__", "constructor", [], [1, 2], {}, { a: 1 }, { "__proto__": { x: 1 } }, "A".repeat(5000)];
const KEYS = ["phoneNumber", "purposeCode", "consentRef", "specifiedDate", "minTenureDays", "latitude", "longitude", "radiusMeters", "maxAgeSeconds", "__proto__", "constructor", "prototype", "extra", "device", "area", "countryCode"];

describe("second-wave endpoints under fuzzing", () => {
  it("random bodies: never 5xx, never an internal detail, never accepted out of range, the input is never echoed", async () => {
    const rand = rng(20261128);
    const pick = <T,>(a: readonly T[]): T => a[Math.floor(rand() * a.length)] as T;
    const n = num("0", "8100");
    const consent = await h.consent(h.bankA, n, { signals: ["NUMBER_RECYCLING", "KYC_TENURE", "DEVICE_LOCATION", "DEVICE_ROAMING"] });
    const valid: Record<string, Record<string, unknown>> = {
      "number-recycling": { specifiedDate: "2026-11-01" }, "kyc-tenure": { minTenureDays: 90 },
      "device-location": { latitude: 3.1, longitude: 101.6, radiusMeters: 5000 }, "device-roaming": {},
    };
    const seen: Record<number, number> = {};
    for (let i = 0; i < 240; i++) {
      const route = pick(ROUTES);
      const body: Record<string, unknown> = { phoneNumber: n, consentRef: consent.ref, purposeCode: "FRAUD_PREVENTION", ...valid[route] };
      for (let k = 0, m = 1 + Math.floor(rand() * 3); k < m; k++) body[pick(KEYS)] = pick(NASTY);
      if (rand() < 0.1) delete body[pick(Object.keys(body))];
      const r = await h.call(h.bankA, "POST", `/v1/signals/${route}/check`, { body });
      seen[r.status] = (seen[r.status] ?? 0) + 1;
      expect([200, 400, 403, 413, 429], `${route} ${JSON.stringify(body).slice(0, 120)} -> ${r.status}`).toContain(r.status);
      const text = JSON.stringify(r.json);
      expect(LEAK.test(text), `leak in ${text.slice(0, 200)}`).toBe(false);
      if (r.status === 400 || r.status === 413) expect(Object.keys(r.json).sort()).toEqual(["code", "correlationId", "message", "status"]);
      for (const echo of ["DROP TABLE", "<script>", "etc/passwd", "AAAAAAAAAA"]) expect(text).not.toContain(echo);
      if (r.status === 200) {      // accepted: it must have been a fully valid request (the validators are the only gate)
        const b = body as Record<string, unknown>;
        if (route === "device-location") { expect(Number(b["radiusMeters"])).toBeGreaterThanOrEqual(2000); expect(Number(b["radiusMeters"])).toBeLessThanOrEqual(200000); expect(Math.abs(Number(b["latitude"]))).toBeLessThanOrEqual(90); expect(Math.abs(Number(b["longitude"]))).toBeLessThanOrEqual(180); }
        if (route === "kyc-tenure") { expect(Number.isInteger(b["minTenureDays"])).toBe(true); expect(Number(b["minTenureDays"])).toBeGreaterThanOrEqual(1); expect(Number(b["minTenureDays"])).toBeLessThanOrEqual(3650); }
        expect(Object.keys(b).every((k) => ["phoneNumber", "purposeCode", "consentRef", "specifiedDate", "minTenureDays", "latitude", "longitude", "radiusMeters", "maxAgeSeconds"].includes(k))).toBe(true);
      }
    }
    expect(Object.keys(seen).length).toBeGreaterThan(0);
  });

  it("wrong content types, oversized and truncated bodies, and a body-less POST are refused cleanly", async () => {
    const n = num("0", "8101");
    const consent = await h.consent(h.bankA, n, { signals: ["DEVICE_LOCATION"] });
    const good = { phoneNumber: n, consentRef: consent.ref, purposeCode: "FRAUD_PREVENTION", latitude: 3.1, longitude: 101.6, radiusMeters: 5000 };
    for (const ct of ["text/plain", "application/x-www-form-urlencoded", "application/xml", "multipart/form-data; boundary=x"]) {
      const r = await h.call(h.bankA, "POST", "/v1/signals/device-location/check", { rawBody: JSON.stringify(good), contentType: ct });
      expect(r.status, ct).toBeLessThan(500); expect(JSON.stringify(r.json)).not.toMatch(LEAK);
    }
    const big = await h.call(h.bankA, "POST", "/v1/signals/device-location/check", { rawBody: JSON.stringify({ ...good, extra: "x".repeat(2_000_000) }) });
    expect([400, 413]).toContain(big.status);
    const cut = await h.call(h.bankA, "POST", "/v1/signals/device-location/check", { rawBody: JSON.stringify(good).slice(0, 40) });
    expect(cut.status).toBe(400);
    // F-M8-1 (found by this fuzz run): a signed POST with no body used to be a 500 on every authenticated POST route
    for (const path of ["/v1/signals/device-location/check", "/v1/signals/sim-swap/check", "/v1/signals/kyc-match/check", "/v1/consents"]) for (const contentType of [undefined, "application/json"]) {
      const empty = await h.call(h.bankA, "POST", path, { rawBody: "", ...(contentType ? { contentType } : {}) });
      expect(empty.status, `${path} empty body ${String(contentType)}`).toBe(400); expect(empty.json.code).toBe("INVALID_REQUEST");
    }
    const deep = await h.call(h.bankA, "POST", "/v1/signals/device-location/check", { rawBody: "[".repeat(3000) });      // deeply nested but inside the 4 KB body limit
    expect(deep.status).toBe(400);
    const deeper = await h.call(h.bankA, "POST", "/v1/signals/device-location/check", { rawBody: "[".repeat(20000) });
    expect(deeper.status).toBe(413);
  });

  it("an unauthenticated, unsigned or replayed request to a new route reveals nothing and is never served", async () => {
    const n = num("1", "8102");
    const consent = await h.consent(h.bankA, n, { signals: ["DEVICE_ROAMING"] });
    const body = { phoneNumber: n, consentRef: consent.ref, purposeCode: "FRAUD_PREVENTION" };
    const a0 = h.telco.calls;
    expect((await h.call(h.bankA, "POST", "/v1/signals/device-roaming/check", { body, token: null })).status).toBe(401);
    const unsigned = await h.call(h.bankA, "POST", "/v1/signals/device-roaming/check", { body, sign: false });
    expect([401, 403]).toContain(unsigned.status);
    const jti = "replay-" + Math.random().toString(36).slice(2, 14).padEnd(12, "x");
    expect((await h.call(h.bankA, "POST", "/v1/signals/device-roaming/check", { body, jti })).status).toBe(200);
    const again = await h.call(h.bankA, "POST", "/v1/signals/device-roaming/check", { body, jti });
    expect(again.status).toBe(401); expect(again.json.code).toBe("REPLAY_REJECTED");
    expect(h.telco.calls - a0).toBe(1);       // only the one genuine request reached the telco
    const other = await h.call(h.bankB, "POST", "/v1/signals/device-roaming/check", { body });     // another organisation cannot use bank A's consent
    expect(other.status).toBe(403); expect(other.json.code).toBe("CONSENT_REQUIRED");
  });
});
