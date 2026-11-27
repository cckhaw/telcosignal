import { describe, it, expect, beforeAll, afterAll } from "vitest";
import { SignJWT, generateKeyPair } from "jose";
import { startHarness, num, type Harness } from "../helpers/harness.js";

let h: Harness;
beforeAll(async () => { h = await startHarness(); });
afterAll(async () => { await h.stop(); });

const check = (number: string, ref: string, extra: Record<string, unknown> = {}) => ({ phoneNumber: number, consentRef: ref, purposeCode: "FRAUD_PREVENTION", ...extra });

describe("M1 happy path", () => {
  it("returns TRUE / FALSE from Telco A under valid token, signature and consent", async () => {
    const swapped = num("1"), clean = num("0");
    const c1 = await h.consent(h.bankA, swapped), c2 = await h.consent(h.bankA, clean);
    const r1 = await h.call(h.bankA, "POST", "/v1/signals/sim-swap/check", { body: check(swapped, c1.ref) });
    const r2 = await h.call(h.bankA, "POST", "/v1/signals/sim-swap/check", { body: check(clean, c2.ref, { maxAge: 24 }) });
    expect(r1.status).toBe(200); expect(r1.json.result).toBe("TRUE");
    expect(r2.status).toBe(200); expect(r2.json.result).toBe("FALSE");
    expect(r1.json.correlationId).toMatch(/^[0-9a-f-]{36}$/);
    expect(h.telco.lastBody).not.toContain("consent");           // outbound minimisation: telco gets only number + maxAge
  });
});

describe("M1 acceptance: bad token", () => {
  const n = num("0", "0002");
  let ref: string;
  beforeAll(async () => { ref = (await h.consent(h.bankA, n)).ref; });
  const attempt = (token: string | null) => h.call(h.bankA, "POST", "/v1/signals/sim-swap/check", { body: check(n, ref), token });

  it("rejects missing, garbage and truncated tokens", async () => {
    expect((await attempt(null)).status).toBe(401);
    expect((await attempt("garbage")).status).toBe(401);
    const good = await h.token(h.bankA);
    expect((await attempt(good.slice(0, -5))).status).toBe(401);
  });
  it("rejects a token signed by an unknown key", async () => {
    const { privateKey } = await generateKeyPair("ES256");
    const forged = await new SignJWT({ scope: "sim-swap:check", client_id: "bank-a", cnf: { "x5t#S256": h.bankA.thumb } })
      .setProtectedHeader({ alg: "ES256", kid: "ts-sig-v1", typ: "at+jwt" }).setIssuer(h.cfg.issuer).setAudience(h.cfg.audience).setSubject("bank-a")
      .setIssuedAt().setExpirationTime("2m").setJti("forged-jti-0000000000").sign(privateKey);
    expect((await attempt(forged)).status).toBe(401);
  });
  it("rejects alg=none and HS256 tokens", async () => {
    const hdr = Buffer.from(JSON.stringify({ alg: "none", typ: "at+jwt" })).toString("base64url");
    const body = Buffer.from(JSON.stringify({ iss: h.cfg.issuer, aud: h.cfg.audience, sub: "bank-a", client_id: "bank-a", scope: "sim-swap:check", exp: Math.floor(Date.now() / 1000) + 100, iat: Math.floor(Date.now() / 1000), jti: "x".repeat(20), cnf: { "x5t#S256": h.bankA.thumb } })).toString("base64url");
    expect((await attempt(`${hdr}.${body}.`)).status).toBe(401);
    const hs = await new SignJWT({ scope: "sim-swap:check" }).setProtectedHeader({ alg: "HS256", typ: "at+jwt" }).setIssuer(h.cfg.issuer).setAudience(h.cfg.audience).setSubject("bank-a").setExpirationTime("2m").sign(new TextEncoder().encode("0123456789abcdef0123456789abcdef"));
    expect((await attempt(hs)).status).toBe(401);
  });
  it("rejects wrong audience, wrong issuer, expired, over-long-lifetime and missing-cnf tokens (signed with the real platform key)", async () => {
    const { kid, privateKey } = await h.kms.currentSigningKey();
    const mk = (o: { aud?: string; iss?: string; iat?: number; exp?: number; cnf?: unknown; typ?: string }) => {
      const iat = o.iat ?? Math.floor(Date.now() / 1000);
      const claims: Record<string, unknown> = { scope: "sim-swap:check", client_id: "bank-a" };
      if (o.cnf !== null) claims["cnf"] = o.cnf ?? { "x5t#S256": h.bankA.thumb };
      return new SignJWT(claims).setProtectedHeader({ alg: "ES256", kid, typ: o.typ ?? "at+jwt" }).setIssuer(o.iss ?? h.cfg.issuer).setAudience(o.aud ?? h.cfg.audience)
        .setSubject("bank-a").setIssuedAt(iat).setExpirationTime(o.exp ?? iat + 120).setJti("jti-0123456789abcdef").sign(privateKey);
    };
    expect((await attempt(await mk({ aud: "someone-else" }))).status).toBe(401);
    expect((await attempt(await mk({ iss: "https://evil.test" }))).status).toBe(401);
    const past = Math.floor(Date.now() / 1000) - 3600;
    expect((await attempt(await mk({ iat: past, exp: past + 120 }))).status).toBe(401);
    expect((await attempt(await mk({ exp: Math.floor(Date.now() / 1000) + 7200 }))).status).toBe(401);
    expect((await attempt(await mk({ cnf: null }))).status).toBe(401);
    expect((await attempt(await mk({ typ: "JWT" }))).status).toBe(401);
    expect((await attempt(await mk({}))).status).toBe(200);        // control: the same construction with valid claims is accepted
  });
  it("sender constraint: a token stolen from bank-a is useless with bank-b's certificate", async () => {
    const stolen = await h.token(h.bankA);
    const r = await h.call(h.bankB, "POST", "/v1/signals/sim-swap/check", { body: check(n, ref), token: stolen });
    expect(r.status).toBe(401);
  });
  it("a revoked client is refused immediately even with an unexpired token", async () => {
    const c = await h.newClient("bank-revoked", h.orgA, ["sim-swap:check"]);
    const t = await h.token(c);
    await h.migrator.query("UPDATE clients SET state='revoked' WHERE client_id='bank-revoked'");
    const r = await h.call(c, "POST", "/v1/signals/sim-swap/check", { body: check(n, ref), token: t });
    expect(r.status).toBe(401);
  });
});

describe("M1 acceptance: wrong scope", () => {
  it("token endpoint refuses scopes the client was not registered for", async () => {
    await expect(h.token(h.bankC, "sim-swap:check")).rejects.toThrow(/403/);
  });
  it("API refuses a function outside the client's scopes", async () => {
    const n = num("0", "0003");
    const r = await h.call(h.bankC, "POST", "/v1/signals/sim-swap/check", { body: check(n, "CONSENT-NOPE-1") });
    expect(r.status).toBe(403); expect(r.json.code).toBe("ACCESS_DENIED");
  });
  it("a token with a narrower scope cannot call a wider function", async () => {
    const t = await h.token(h.bankA, "consent:read");
    const r = await h.call(h.bankA, "POST", "/v1/signals/sim-swap/check", { body: check(num("0", "0003"), "CONSENT-NOPE-1"), token: t });
    expect(r.status).toBe(403);
  });
});

describe("M1 acceptance: replay and request integrity", () => {
  const n = num("0", "0004");
  let ref: string;
  beforeAll(async () => { ref = (await h.consent(h.bankA, n)).ref; });
  const body = () => check(n, ref);

  it("rejects an identical signed request replayed (same jti)", async () => {
    const jti = "replay-jti-" + Math.random().toString(36).slice(2, 12) + "abcdef";
    const t = await h.token(h.bankA);
    const first = await h.call(h.bankA, "POST", "/v1/signals/sim-swap/check", { body: body(), token: t, jti });
    const second = await h.call(h.bankA, "POST", "/v1/signals/sim-swap/check", { body: body(), token: t, jti });
    expect(first.status).toBe(200);
    expect(second.status).toBe(401); expect(second.json.code).toBe("REPLAY_REJECTED");
  });
  it("rejects stale and future-dated signatures", async () => {
    const now = Math.floor(Date.now() / 1000);
    expect((await h.call(h.bankA, "POST", "/v1/signals/sim-swap/check", { body: body(), iat: now - 600 })).status).toBe(401);
    expect((await h.call(h.bankA, "POST", "/v1/signals/sim-swap/check", { body: body(), iat: now + 600 })).status).toBe(401);
  });
  it("rejects a missing signature and a body altered after signing", async () => {
    expect((await h.call(h.bankA, "POST", "/v1/signals/sim-swap/check", { body: body(), sign: false })).status).toBe(401);
    const r = await h.call(h.bankA, "POST", "/v1/signals/sim-swap/check", { body: body(), tamperAfterSign: JSON.stringify(check(num("1", "0004"), ref)) });
    expect(r.status).toBe(401);
  });
  it("rejects a signature made by another participant's key", async () => {
    const r = await h.call(h.bankA, "POST", "/v1/signals/sim-swap/check", { body: body(), signAs: h.bankB });
    expect(r.status).toBe(401);
  });
  it("replayed client assertion at the token endpoint is rejected", async () => {
    const a = await h.assertion(h.bankA);
    const form = () => new URLSearchParams({ grant_type: "client_credentials", client_id: "bank-a", client_assertion_type: "urn:ietf:params:oauth:client-assertion-type:jwt-bearer", client_assertion: a }).toString();
    const { request } = await import("undici");
    const go = () => request(h.cfg.tokenEndpoint, { method: "POST", dispatcher: h.bankA.agent, headers: { "content-type": "application/x-www-form-urlencoded" }, body: form() }).then(async (r) => { await r.body.dump(); return r.statusCode; });
    expect(await go()).toBe(200);
    expect(await go()).toBe(401);
  });
});

describe("M1 acceptance: missing / invalid consent", () => {
  const n = num("0", "0005");
  const before = () => h.telco.calls;
  it("rejects when no consent exists, with zero telco calls and no billing", async () => {
    const c0 = before();
    const r = await h.call(h.bankA, "POST", "/v1/signals/sim-swap/check", { body: check(n, "CONSENT-DOES-NOT-EXIST") });
    expect(r.status).toBe(403); expect(r.json.code).toBe("CONSENT_REQUIRED");
    expect(h.telco.calls).toBe(c0);
  });
  it("rejects expired, revoked, wrong-purpose, wrong-signal and wrong-subject consent identically", async () => {
    const c0 = before();
    const exp = await h.consent(h.bankA, n, { expiresInMs: 1500 });
    await h.migrator.query("UPDATE consents SET expires_at = now() - interval '1 second' WHERE consent_ref=$1", [exp.ref]);
    const rev = await h.consent(h.bankA, n);
    expect((await h.call(h.bankA, "POST", `/v1/consents/${rev.id}/revoke`)).status).toBe(200);
    const purpose = await h.consent(h.bankA, n, { purpose: "TRANSACTION_RISK" });
    const signal = await h.consent(h.bankA, n, { signals: ["DEVICE_SWAP"] });
    const other = await h.consent(h.bankA, num("0", "0099"));
    const results = [];
    for (const ref of [exp.ref, rev.ref, purpose.ref, signal.ref, other.ref]) results.push(await h.call(h.bankA, "POST", "/v1/signals/sim-swap/check", { body: check(n, ref) }));
    for (const r of results) { expect(r.status).toBe(403); expect(r.json.code).toBe("CONSENT_REQUIRED"); expect(Object.keys(r.json).sort()).toEqual(["code", "correlationId", "message", "status"]); }
    expect(h.telco.calls).toBe(c0);
    const { rows } = await h.migrator.query("SELECT count(*)::int AS n FROM usage_record WHERE outcome='REJECTED' AND billable=false");
    expect(rows[0].n).toBeGreaterThanOrEqual(6);
  });
  it("rejects missing purpose or consent reference at schema validation", async () => {
    for (const b of [{ phoneNumber: n, consentRef: "CONSENT-XXXX" }, { phoneNumber: n, purposeCode: "FRAUD_PREVENTION" }, { ...check(n, "CONSENT-XXXX"), purposeCode: "MARKETING" }])
      expect((await h.call(h.bankA, "POST", "/v1/signals/sim-swap/check", { body: b })).status).toBe(400);
  });
});

describe("M1 acceptance: cross-participant access", () => {
  const n = num("0", "0006");
  it("bank-b cannot read, revoke or use bank-a's consent (same answer as nonexistent)", async () => {
    const mine = await h.consent(h.bankA, n);
    const read = await h.call(h.bankB, "GET", `/v1/consents/${mine.id}`);
    const none = await h.call(h.bankB, "GET", `/v1/consents/00000000-0000-4000-8000-000000000000`);
    expect(read.status).toBe(404); expect(none.status).toBe(404);
    expect({ ...read.json, correlationId: 0 }).toEqual({ ...none.json, correlationId: 0 });
    expect((await h.call(h.bankB, "POST", `/v1/consents/${mine.id}/revoke`)).status).toBe(404);
    expect((await h.call(h.bankB, "POST", "/v1/signals/sim-swap/check", { body: check(n, mine.ref) })).json.code).toBe("CONSENT_REQUIRED");
    // and it is still intact for the owner
    expect((await h.call(h.bankA, "GET", `/v1/consents/${mine.id}`)).json.revoked).toBe(false);
  });
  it("two organisations may reuse a consent reference without colliding or leaking", async () => {
    const ref = "SHARED-REF-0001";
    await h.consent(h.bankA, n, { ref }); await h.consent(h.bankB, n, { ref });
  });
});
