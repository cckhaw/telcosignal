import { describe, it, expect, beforeAll, afterAll } from "vitest";
import { createHash } from "node:crypto";
import { request } from "undici";
import { startHarness, type Harness } from "../helpers/harness.js";
import { startAdmin, type Admin } from "../helpers/admin-harness.js";

let h: Harness, a: Admin;
beforeAll(async () => { h = await startHarness(); a = await startAdmin(h); });
afterAll(async () => { await a.stop(); await h.stop(); });
const audits = async (action: string) => (await h.migrator.query("SELECT actor, outcome, detail_text FROM audit_log WHERE action=$1 ORDER BY seq", [action])).rows;

describe("no default accounts", () => {
  it("a freshly migrated database has no admin accounts and an unknown identity cannot sign in", async () => {
    const s = await a.login("mallory");                                   // valid IdP account, strong MFA, but not provisioned in the portal
    expect(s.ok).toBe(false); expect(s.status).toBe(401);
    expect((await audits("admin.login")).some((r) => r.actor === "mallory" && r.outcome === "DENIED")).toBe(true);
  });
  it("a disabled account cannot sign in, and disabling ends live sessions", async () => {
    const s = await a.login("olivia"); expect(s.ok).toBe(true);
    await h.migrator.query("UPDATE admin_user SET state='disabled' WHERE sub='olivia'");
    expect((await s.get("/orgs")).status).toBe(302);                      // session no longer resolves
    expect((await a.login("olivia")).ok).toBe(false);
    await h.migrator.query("UPDATE admin_user SET state='active' WHERE sub='olivia'");
  });
});

describe("phishing-resistant MFA is mandatory (fail closed)", () => {
  it("accepts a hardware-key (WebAuthn) sign-in", async () => { const s = await a.login("alice"); expect(s.ok).toBe(true); expect((await s.get("/")).status).toBe(200); });
  it.each([["none", "password only"], ["totp", "one-time-code MFA (phishable)"]])("refuses %s (%s)", async (mfa) => {
    const s = await a.login("alice", { mock_mfa: mfa }); expect(s.ok).toBe(false); expect(s.status).toBe(401); expect(s.cookie).toBe("");
  });
  it("refuses a stale authentication (SSO session reuse)", async () => { expect((await a.login("alice", { mock_auth_age: "3600" })).ok).toBe(false); });
});

describe("ID token validation (hostile IdP responses)", () => {
  it.each(["aud", "iss", "nonce", "expired", "unsigned", "hs256", "wrongkey"])("rejects a token with tampered: %s", async (t) => {
    const s = await a.login("alice", { mock_tamper: t }); expect(s.ok).toBe(false); expect(s.cookie).toBe("");
  });
  it("rejects a mismatched state (login CSRF) and a missing login cookie", async () => {
    expect((await a.login("alice", {}, { state: "attacker-state" })).ok).toBe(false);
    expect((await a.login("alice", {}, { noLoginCookie: "1" })).ok).toBe(false);
  });
  it("an authorization code cannot be replayed", async () => {
    const raw = (url: string, headers: Record<string, string> = {}) => request(url, { method: "GET", dispatcher: a.agent, headers, maxRedirections: 0 } as never).then(async (r) => { await r.body.dump(); return { status: r.statusCode, headers: r.headers }; });
    const l = await raw(`${a.origin}/login?login_hint=alice`); const cookie = ([] as string[]).concat(l.headers["set-cookie"] ?? []).map((c) => c.split(";")[0]).join("; ");
    const cb = String((await raw(String(l.headers["location"]))).headers["location"]);
    expect((await raw(cb, { cookie })).status).toBe(302);
    expect((await raw(cb, { cookie })).status).toBe(401);
  });
});

describe("sessions", () => {
  it("cookie is __Host- prefixed, HttpOnly, Secure, SameSite=Strict, Path=/, no Domain; the id is never stored (only its hash)", async () => {
    const s = await a.login("alice"); const c = s.setCookie.find((x) => x.startsWith("__Host-ts_admin="))!;
    expect(c).toMatch(/; Secure/); expect(c).toMatch(/; HttpOnly/); expect(c).toMatch(/; SameSite=Strict/); expect(c).toMatch(/; Path=\//); expect(c).not.toMatch(/Domain=/i);
    const id = c.split(";")[0]!.split("=")[1]!;
    expect(id.length).toBeGreaterThanOrEqual(43);
    const rows = (await h.migrator.query("SELECT encode(id_hash,'hex') hh, csrf FROM admin_session")).rows;
    expect(JSON.stringify(rows)).not.toContain(id);
    expect(rows.some((r) => r.hh === createHash("sha256").update(id).digest("hex"))).toBe(true);
  });
  it("every login issues a new session id (no fixation) and logout ends the session server-side", async () => {
    const s1 = await a.login("alice"), s2 = await a.login("alice");
    expect(s1.cookie).not.toBe(s2.cookie);
    expect((await s1.post("/logout", {})).status).toBe(302);
    expect((await s1.get("/orgs")).status).toBe(302);                     // the old cookie no longer works
    expect((await s2.get("/orgs")).status).toBe(200);
  });
  it("idle timeout (15 min) and absolute timeout (8 h) are enforced", async () => {
    const s = await a.login("alice"); expect((await s.get("/orgs")).status).toBe(200);
    await h.migrator.query("UPDATE admin_session SET last_seen_at = now() - interval '20 minutes' WHERE ended_at IS NULL AND sub='alice'");
    expect((await s.get("/orgs")).status).toBe(302);
    const t = await a.login("alice");
    await h.migrator.query("UPDATE admin_session SET expires_at = now() - interval '1 second' WHERE ended_at IS NULL AND sub='alice'");
    expect((await t.get("/orgs")).status).toBe(302);
  });
  it("garbage, truncated and forged cookies never authenticate", async () => {
    const mk = (c: string) => request(`${a.origin}/orgs`, { dispatcher: a.agent, headers: { cookie: `__Host-ts_admin=${c}` }, maxRedirections: 0 } as never).then(async (r) => { await r.body.dump(); return r.statusCode; });
    for (const c of ["x", "A".repeat(43), "' OR 1=1 --", "%00", "A".repeat(5000)]) expect(await mk(c)).toBe(302);
  });
});

describe("web application hardening", () => {
  it("strict headers: CSP forbids script entirely, no framing, no caching", async () => {
    const s = await a.login("alice"); const r = await s.get("/orgs");
    const csp = String(r.headers["content-security-policy"]);
    expect(csp).toContain("default-src 'none'"); expect(csp).not.toMatch(/script-src/); expect(csp).toContain("frame-ancestors 'none'"); expect(csp).toContain("form-action 'self'");
    expect(csp).not.toContain("unsafe-inline"); expect(csp).not.toContain("unsafe-eval");
    expect(r.headers["cache-control"]).toBe("no-store"); expect(r.headers["x-frame-options"]).toBe("DENY"); expect(r.headers["x-content-type-options"]).toBe("nosniff");
    expect(r.text).not.toMatch(/<script/i);
  });
  it("CSRF: a state-changing request needs a valid token, a same-origin Origin and a form content type", async () => {
    const s = await a.login("alice"); const body = { name: "CSRF Test Org", kind: "bank" };
    expect((await s.post("/orgs", body, { csrf: null })).status).toBe(403);
    expect((await s.post("/orgs", body, { csrf: "wrong-token" })).status).toBe(403);
    expect((await s.post("/orgs", body, { origin: "https://evil.example" })).status).toBe(403);
    expect((await s.post("/orgs", body, { origin: null })).status).toBe(403);
    expect((await s.post("/orgs", body, { contentType: "application/json", raw: JSON.stringify({ ...body, _csrf: s.csrf }) })).status).toBe(415);
    expect((await h.migrator.query("SELECT count(*)::int n FROM organisations WHERE name='CSRF Test Org'")).rows[0].n).toBe(0);
    expect((await s.post("/orgs", body)).status).toBe(302);                // control: the legitimate request works
  });
  it("a CSRF token from one session does not work in another", async () => {
    const s1 = await a.login("alice"), s2 = await a.login("bob");
    expect((await s1.post("/orgs", { name: "Cross Session", kind: "bank" }, { csrf: s2.csrf })).status).toBe(403);
  });
  it("XSS: hostile data is escaped everywhere it is rendered", async () => {
    const evil = `<script>alert(1)</script><img src=x onerror=alert(2)>"'\``;
    const s = await a.login("alice");
    const r = await s.post("/orgs", { name: evil, kind: "bank" }); expect(r.status).toBe(302);
    const list = await s.get("/orgs"); const detail = await s.get(r.location!);
    for (const page of [list, detail]) { expect(page.text).not.toContain("<script>alert(1)"); expect(page.text).not.toContain("<img src=x"); expect(page.text).toContain("&lt;script&gt;alert(1)&lt;/script&gt;"); }
    const t = await s.post("/changes/new", { kind: "SETTING", key: "consent.max_days", value: "<script>1</script>" });   // invalid input is refused and reflected safely
    expect(t.text).not.toContain("<script>1");
  });
  it("source-address allow-list: the isolated admin interface refuses other networks (and still serves the allowed one)", async () => {
    const locked = await startAdmin(h, { allowedCidrs: ["10.99.0.0/16"], reuseUsers: true });
    try {
      const r = await request(`${locked.origin}/login`, { dispatcher: locked.agent, maxRedirections: 0 } as never); await r.body.dump();
      expect(r.statusCode).toBe(403);
      const ok = await request(`${a.origin}/login`, { dispatcher: a.agent, maxRedirections: 0 } as never); await ok.body.dump();
      expect(ok.statusCode).toBe(302);
    } finally { await locked.stop(); }
  });
});

describe("rate limiting on the admin interface", () => {
  it("limits per session and per source address; sign-in endpoints are stricter; other sessions are unaffected", async () => {
    const lim = await startAdmin(h, { reuseUsers: true, perMinute: 12, loginPerMinute: 6 });
    try {
      const s1 = await lim.login("alice"), s2 = await lim.login("bob");
      const codes: number[] = []; for (let i = 0; i < 20; i++) codes.push((await s1.get("/orgs")).status);
      expect(codes.filter((c) => c === 429).length).toBeGreaterThan(0); expect(codes[0]).toBe(200);
      const limited = await s1.get("/orgs"); expect(limited.status).toBe(429); expect(limited.text).not.toMatch(/stack|postgres|rate-limit/i);
      expect((await s2.get("/orgs")).status).toBe(200);                                  // a different session has its own budget
      const logins: number[] = []; for (let i = 0; i < 10; i++) { const r = await request(`${lim.origin}/login`, { dispatcher: lim.agent, maxRedirections: 0 } as never); await r.body.dump(); logins.push(r.statusCode); }
      expect(logins.filter((c) => c === 429).length).toBeGreaterThan(0);                // sign-in brute force / flooding is throttled harder
    } finally { await lim.stop(); }
  });
});

describe("the participant and admin planes are separate", () => {
  it("the admin listener has no participant routes, the participant listener has no admin routes", async () => {
    const s = await a.login("alice");
    expect((await s.get("/v1/signals/sim-swap/check")).status).toBe(404);
    expect((await s.post("/v1/consents", {})).status).toBe(404);
    const r = await request(`https://localhost:${h.port}/orgs`, { dispatcher: h.bankA.agent, maxRedirections: 0 } as never); await r.body.dump();
    expect(r.statusCode).toBe(404);
  });
  it("an admin session cookie is not a participant credential and a participant token is not an admin credential", async () => {
    const s = await a.login("alice");
    const r = await request(`https://localhost:${h.port}/v1/consents/00000000-0000-4000-8000-000000000000`, { dispatcher: h.bankA.agent, headers: { cookie: s.cookie, authorization: `Bearer ${s.cookie.split("=")[1]}` } } as never); await r.body.dump();
    expect(r.statusCode).toBe(401);
    const tok = await h.token(h.bankA);
    const q = await request(`${a.origin}/orgs`, { dispatcher: a.agent, headers: { authorization: `Bearer ${tok}` }, maxRedirections: 0 } as never); await q.body.dump();
    expect(q.statusCode).toBe(302);
  });
});

describe("auditing of access", () => {
  it("sign-ins, refusals, views and logouts are audited with the actor; no secrets or session ids in the audit trail", async () => {
    const s = await a.login("bob"); await s.get("/config"); await s.get("/history");
    const { rows } = await h.migrator.query("SELECT actor, action, outcome, detail_text FROM audit_log WHERE actor='bob' ORDER BY seq");
    const acts = rows.map((r) => r.action);
    expect(acts).toContain("admin.login"); expect(acts).toContain("admin.view.config"); expect(acts).toContain("admin.view.history");
    expect(JSON.stringify(rows)).not.toMatch(/__Host-|csrf|client_secret|eyJ/);
    expect((await audits("admin.login")).filter((r) => r.outcome === "DENIED").length).toBeGreaterThanOrEqual(10);
    expect(a.logs.join("")).not.toMatch(/__Host-ts_admin=[A-Za-z0-9_-]{20,}/);
  });
});
