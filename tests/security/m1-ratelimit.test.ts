import { describe, it, expect } from "vitest";
import { Redis } from "ioredis";
import { startHarness, num } from "../helpers/harness.js";

describe("rate limiting (baseline; per-signal/number-hash limits and enumeration detection follow in M3)", () => {
  it("limits per client certificate with a generic 429, and one participant's burst does not throttle another", async () => {
    const h = await startHarness({ rps: 8, tokenRps: 1000 });
    try {
      const n = num("0", "0100");
      const c = await h.consent(h.bankA, n);
      const tokenA = await h.token(h.bankA);
      const burst = await Promise.all(Array.from({ length: 30 }, () => h.call(h.bankA, "GET", `/v1/consents/${c.id}`, { token: tokenA })));
      const limited = burst.filter((r) => r.status === 429);
      expect(limited.length).toBeGreaterThan(0);
      expect(limited[0]!.json.code).toBe("RATE_LIMITED");
      expect(Object.keys(limited[0]!.json).sort()).toEqual(["code", "correlationId", "message", "status"]);
      // a different participant (different certificate) is unaffected
      const b = await h.call(h.bankB, "GET", "/v1/consents/00000000-0000-4000-8000-000000000000");
      expect(b.status).toBe(404);
      // and it recovers after the window
      await new Promise((r) => setTimeout(r, 1100));
      expect((await h.call(h.bankA, "GET", `/v1/consents/${c.id}`, { token: tokenA })).status).toBe(200);
    } finally { await h.stop(); }
  });
  it("the token endpoint has a stricter limit (credential-stuffing / brute-force resistance)", async () => {
    const h = await startHarness({ rps: 5000, tokenRps: 3 });
    try {
      const { request } = await import("undici");
      const attempt = async () => {
        const form = new URLSearchParams({ grant_type: "client_credentials", client_id: "bank-a", client_assertion_type: "urn:ietf:params:oauth:client-assertion-type:jwt-bearer", client_assertion: "not.a.jwt" });
        const r = await request(h.cfg.tokenEndpoint, { method: "POST", dispatcher: h.bankA.agent, headers: { "content-type": "application/x-www-form-urlencoded" }, body: form.toString() });
        await r.body.dump(); return r.statusCode;
      };
      const codes = await Promise.all(Array.from({ length: 12 }, attempt));
      expect(codes.filter((c) => c === 429).length).toBeGreaterThanOrEqual(6);
      expect(codes.filter((c) => c === 401).length).toBeLessThanOrEqual(6);
    } finally { await h.stop(); }
  });
  it("fails closed when the rate-limit store is unavailable (requests are refused, not served unlimited)", async () => {
    const dead = new Redis("redis://127.0.0.1:1", { maxRetriesPerRequest: 0, enableOfflineQueue: false, lazyConnect: true, retryStrategy: () => null });
    dead.on("error", () => undefined);
    const h = await startHarness({ rateLimitRedis: dead });
    try {
      const r = await h.call(h.bankA, "GET", "/.well-known/jwks.json", { token: null, sign: false });
      expect(r.status).toBeGreaterThanOrEqual(500);
      expect(h.telco.calls).toBe(0);
    } finally { await h.stop(); dead.disconnect(); }
  });
});
