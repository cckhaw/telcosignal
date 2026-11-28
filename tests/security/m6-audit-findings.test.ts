// M6 security audit + penetration test: regression tests for defects found by reading the code and attacking the running implementation.
// Every test here failed before its fix (see docs/security/audit-and-pentest-report.md). Synthetic data only.
import { describe, it, expect } from "vitest";
import { SignJWT, exportJWK, generateKeyPair } from "jose";
import { startHarness, num } from "../helpers/harness.js";
import { startAdmin } from "../helpers/admin-harness.js";
import { verifyAuditChain } from "../../src/audit/audit.js";
import { isBlockedAddress, validateTelcoEndpoint } from "../../src/common/ssrf.js";
import { OutboundClient } from "../../src/adapters/outbound.js";
import { buildAdmin } from "../../src/admin/index.js";

const SIM = "/v1/signals/sim-swap/check";

describe("F-A4: the audit verifier is correct under concurrent writers", () => {
  it("300 concurrent audit writes leave a chain that verifies (the external copy is compared by sequence number, not position) and tampering is still caught", async () => {
    const h = await startHarness();
    try {
      await Promise.all(Array.from({ length: 300 }, (_, i) => h.audit.record({ correlationId: `c${i}`, actor: "probe", action: "probe.write", outcome: "OK" })));
      expect((await verifyAuditChain(h.migrator, h.auditSink)).ok).toBe(true);
      // tampering is still detected: altered hash, a duplicated line, a missing line
      const { readFileSync, writeFileSync } = await import("node:fs");
      const lines = readFileSync(h.auditSink, "utf8").split("\n").filter(Boolean);
      const orig = lines.join("\n") + "\n";
      writeFileSync(h.auditSink, [...lines].reverse().join("\n") + "\n");                       // deterministic: out-of-order lines are what concurrency produces
      expect((await verifyAuditChain(h.migrator, h.auditSink)).ok).toBe(true);
      const bad = [...lines]; const o = JSON.parse(bad[10]!) as { hash: string }; o.hash = "00".repeat(32); bad[10] = JSON.stringify({ ...JSON.parse(lines[10]!), hash: o.hash });
      writeFileSync(h.auditSink, bad.join("\n") + "\n"); expect((await verifyAuditChain(h.migrator, h.auditSink)).ok).toBe(false);
      const dup = [...lines]; dup[11] = dup[10]!; writeFileSync(h.auditSink, dup.join("\n") + "\n"); expect((await verifyAuditChain(h.migrator, h.auditSink)).ok).toBe(false);
      writeFileSync(h.auditSink, lines.slice(0, -1).join("\n") + "\n"); expect((await verifyAuditChain(h.migrator, h.auditSink)).ok).toBe(false);
      writeFileSync(h.auditSink, orig); expect((await verifyAuditChain(h.migrator, h.auditSink)).ok).toBe(true);
    } finally { await h.stop(); }
  });
});

describe("F-A1 / F-A2: admin sign-in", () => {
  it("the post-sign-in return target can never leave this site (//host, numeric hosts, backslashes, schemes)", async () => {
    const h = await startHarness(); const a = await startAdmin(h);
    try {
      for (const bad of ["//evil", "//2130706433", "//0x7f000001", "///evil", "/\\evil", "https://evil.example", "javascript:alert(1)", "/a//b/../../x?y", "/ok%0d%0aSet-Cookie:x=y"]) {
        const s = await a.login("alice", { return: bad });
        expect(s.ok, bad).toBe(true); expect(s.location, bad).toBe("/");
      }
      expect((await a.login("alice", { return: "/orgs" })).location).toBe("/orgs");
    } finally { await a.stop(); await h.stop(); }
  });
  it("refuses to start with the mock-IdP test parameters enabled against a non-local identity provider", async () => {
    const h = await startHarness(); const a = await startAdmin(h);
    try {
      const cfg = { ...a.cfg, oidc: { ...a.cfg.oidc, issuer: "https://idp.example.com", allowMockParams: true } };
      await expect(buildAdmin({ cfg, pool: a.pool, audit: h.audit, kms: h.kms, log: (await import("../../src/common/log.js")).makeLogger("error") })).rejects.toThrow(/not local/);
    } finally { await a.stop(); await h.stop(); }
  });
});

describe("F-A3: outbound connections check the RESOLVED address (internal addresses, DNS rebinding)", () => {
  it("address classification covers IPv4 private ranges and every IPv6 form that carries one", () => {
    for (const a of ["127.0.0.1", "10.1.2.3", "172.16.0.1", "172.31.255.255", "192.168.1.1", "169.254.169.254", "100.64.0.1", "0.0.0.0", "224.0.0.1", "::1", "::", "fd00::1", "fe80::1", "::ffff:10.0.0.1", "::ffff:7f00:1", "::ffff:a9fe:a9fe", "64:ff9b::a00:1", "2002:7f00:1::", "2001:0:4136:e378::1", "ff02::1", "not-an-ip"]) expect(isBlockedAddress(a), a).toBe(true);
    for (const a of ["8.8.8.8", "93.184.216.34", "2606:4700:4700::1111"]) expect(isBlockedAddress(a), a).toBe(false);
    expect(isBlockedAddress("127.0.0.1", true)).toBe(false);            // sandbox flag
  });
  it("a name that resolves to loopback is refused at connect time (no connection is made), a private literal is refused at construction; the sandbox flag is the only way through", async () => {
    const h = await startHarness();
    try {
      const origin = `https://localhost:${h.telco.port}`;
      const mtls = { ca: h.pki.caCert, cert: h.platformOut.cert, key: h.platformOut.key };
      const strict = new OutboundClient(origin, [origin], mtls, 800);          // validateTelcoEndpoint would also refuse "localhost"; here the allow-list says yes, DNS is the only guard left
      const before = h.telco.calls;
      const r = await strict.post("/sim-swap/v2/check", "{}", { "content-type": "application/json" }, /json/);
      expect(r.ok).toBe(false); expect(h.telco.calls).toBe(before);
      await strict.close();
      expect(() => new OutboundClient("https://169.254.169.254", ["https://169.254.169.254"], mtls, 500)).toThrow(/private|loopback|link-local/);
      expect(() => new OutboundClient("https://[::ffff:10.0.0.1]", ["https://[::ffff:a00:1]"], mtls, 500)).toThrow();
      const sandbox = new OutboundClient(origin, [origin], { ...mtls, allowPrivateAddresses: true }, 800);
      expect((await sandbox.post("/sim-swap/v2/check", JSON.stringify({ phoneNumber: num("0", "0001") }), { "content-type": "application/json" }, /json/)).ok).toBe(true);
      await sandbox.close();
      expect(validateTelcoEndpoint("https://127.0.0.1.nip.io").ok).toBe(true);    // a syntactically public name: only the connect-time check can stop it (proved above)
    } finally { await h.stop(); }
  });
});

describe("pentest: races (atomic single-use controls)", () => {
  it("one signed request replayed 40 times in parallel succeeds exactly once", async () => {
    const h = await startHarness();
    try {
      const n = num("0", "0600"); const c = await h.consent(h.bankA, n); const token = await h.token(h.bankA);
      const jti = "race-jti-" + "x".repeat(20); const iat = Math.floor(Date.now() / 1000);
      const rs = await Promise.all(Array.from({ length: 40 }, () => h.call(h.bankA, "POST", "/v1/signals/sim-swap/check", { token, jti, iat, body: { phoneNumber: n, consentRef: c.ref, purposeCode: "FRAUD_PREVENTION" } })));
      expect(rs.filter((r) => r.status === 200).length).toBe(1);
      expect(rs.filter((r) => r.status === 401).length).toBe(39);
    } finally { await h.stop(); }
  });
  it("one client assertion presented 40 times in parallel yields exactly one token", async () => {
    const h = await startHarness();
    try {
      const { request } = await import("undici");
      const assertion = await h.assertion(h.bankA);
      const body = new URLSearchParams({ grant_type: "client_credentials", client_id: "bank-a", client_assertion_type: "urn:ietf:params:oauth:client-assertion-type:jwt-bearer", client_assertion: assertion }).toString();
      const rs = await Promise.all(Array.from({ length: 40 }, async () => { const r = await request(h.cfg.tokenEndpoint, { method: "POST", dispatcher: h.bankA.agent, headers: { "content-type": "application/x-www-form-urlencoded" }, body }); await r.body.dump(); return r.statusCode; }));
      expect(rs.filter((s) => s === 200).length).toBe(1);
    } finally { await h.stop(); }
  });
  it("after a revocation is acknowledged no later request is served (revoke racing 60 in-flight checks)", async () => {
    const h = await startHarness();
    try {
      const n = num("0", "0610"); const c = await h.consent(h.bankA, n); const token = await h.token(h.bankA);
      const check = () => h.call(h.bankA, "POST", "/v1/signals/sim-swap/check", { token, body: { phoneNumber: n, consentRef: c.ref, purposeCode: "FRAUD_PREVENTION" } });
      const inflight = Array.from({ length: 60 }, () => check());
      const rev = await h.call(h.bankA, "POST", `/v1/consents/${c.id}/revoke`, { token });
      await Promise.all(inflight);
      expect(rev.status).toBe(200);
      for (let i = 0; i < 10; i++) expect((await check()).status).toBe(403);       // everything after the acknowledgement is refused
    } finally { await h.stop(); }
  });
});

describe("pentest: token and signature header attacks", () => {
    it("forged headers (jku, x5u, embedded jwk, kid tricks, crit, b64, alg confusion with the public key as an HMAC secret) never authenticate", async () => {
    const h = await startHarness();
    try {
      const n = num("0", "0620"); const c = await h.consent(h.bankA, n);
      const { publicKey, privateKey } = await generateKeyPair("ES256", { extractable: true });
      const jwk = await exportJWK(publicKey);
      const claims = { scope: "sim-swap:check", client_id: "bank-a", cnf: { "x5t#S256": h.bankA.thumb } };
      const mk = (hdr: Record<string, unknown>, key: unknown = privateKey) => new SignJWT(claims).setProtectedHeader({ alg: "ES256", typ: "at+jwt", ...hdr } as never).setIssuer(h.cfg.issuer).setAudience(h.cfg.audience).setSubject("bank-a").setIssuedAt().setExpirationTime("2m").setJti("forged-jti-0001").sign(key as never);
      const attempts: Array<[string, string]> = [
        ["jku", await mk({ kid: "ts-sig-v1", jku: "https://evil.example/jwks" })], ["x5u", await mk({ kid: "ts-sig-v1", x5u: "https://evil.example/c.pem" })],
        ["embedded jwk", await mk({ jwk })], ["kid traversal", await mk({ kid: "../../../etc/passwd" })], ["kid sqli", await mk({ kid: "x' OR '1'='1" })],
        ["kid of the real key, wrong signature", await mk({ kid: "ts-sig-v1" })], ["crit + b64=false (hand-built, jose refuses to sign it)", `${Buffer.from(JSON.stringify({ alg: "ES256", kid: "ts-sig-v1", typ: "at+jwt", crit: ["b64"], b64: false })).toString("base64url")}.${Buffer.from(JSON.stringify({ scope: "sim-swap:check", client_id: "bank-a" })).toString("base64url")}.${Buffer.alloc(64, 7).toString("base64url")}`],
        ["hmac with public key as secret", await new SignJWT(claims).setProtectedHeader({ alg: "HS256", kid: "ts-sig-v1", typ: "at+jwt" }).setIssuer(h.cfg.issuer).setAudience(h.cfg.audience).setSubject("bank-a").setIssuedAt().setExpirationTime("2m").setJti("forged-jti-0002").sign(new TextEncoder().encode(JSON.stringify(jwk)))],
      ];
      for (const [name, tok] of attempts) { const r = await h.call(h.bankA, "POST", SIM, { token: tok, body: { phoneNumber: n, consentRef: c.ref, purposeCode: "FRAUD_PREVENTION" } }); expect(r.status, name).toBe(401); }
    } finally { await h.stop(); }
  });
  it("a request signature with the wrong algorithm family, a missing kid, or a header that tries to embed a key is refused", async () => {
    const h = await startHarness();
    try {
      const n = num("0", "0630"); const c = await h.consent(h.bankA, n); const token = await h.token(h.bankA);
      const { CompactSign } = await import("jose"); const { createHash } = await import("node:crypto");
      const raw = JSON.stringify({ phoneNumber: n, consentRef: c.ref, purposeCode: "FRAUD_PREVENTION" });
      const payload = () => new TextEncoder().encode(JSON.stringify({ htm: "POST", htu: SIM, dig: createHash("sha256").update(raw).digest("base64url"), iat: Math.floor(Date.now() / 1000), jti: "sig-attack-" + Math.random().toString(36).slice(2, 12).padEnd(10, "0") }));
      const { publicKey, privateKey } = await generateKeyPair("ES256", { extractable: true }); const jwk = await exportJWK(publicKey);
      const send = async (jws: string) => (await h.call(h.bankA, "POST", SIM, { token, rawBody: raw, sign: false, headers: { "x-request-signature": jws } })).status;
      expect(await send(await new CompactSign(payload()).setProtectedHeader({ alg: "ES256" }).sign(privateKey))).toBe(401);                          // no kid
      expect(await send(await new CompactSign(payload()).setProtectedHeader({ alg: "ES256", kid: h.bankA.kid, jwk } as never).sign(privateKey))).toBe(401);   // right kid, attacker's key
      expect(await send(await new CompactSign(payload()).setProtectedHeader({ alg: "HS256", kid: h.bankA.kid }).sign(new TextEncoder().encode("secret")))).toBe(401);
    } finally { await h.stop(); }
  });
});

describe("pentest: admin plane races and request-header abuse", () => {
  it("two administrators deciding the same change at the same moment: exactly one decision wins and the change is applied once", async () => {
    const h = await startHarness(); const a = await startAdmin(h);
    try {
      const alice = await a.login("alice"), bob = await a.login("bob"), olivia = await a.login("olivia");
      const mk = async () => (await alice.post("/changes/new", { kind: "RATE_LIMIT", orgId: h.orgA, signal: "SIM_SWAP", maxPerMinute: "77" })).location!.split("/").pop()!;
      for (const mode of ["approve-approve", "approve-reject"]) {
        const id = await mk();
        const second = mode === "approve-approve" ? "approve" : "reject";
        const rs = await Promise.all([bob.post(`/changes/${id}/approve`, { note: "x" }), olivia.post(`/changes/${id}/${second}`, { note: "x" })]);
        const st = (await h.migrator.query("SELECT status FROM config_change WHERE id=$1", [id])).rows[0].status as string;
        expect(["applied", "rejected"], mode).toContain(st);
        expect(rs.filter((r) => r.status === 302).length, mode).toBe(1);             // exactly one succeeded, the other was refused
        const hist = (await h.migrator.query("SELECT count(*)::int n FROM config_history WHERE change_id=$1", [id])).rows[0].n as number;
        expect(hist, mode).toBe(st === "applied" ? 1 : 0);                           // applied at most once
      }
    } finally { await a.stop(); await h.stop(); }
  });
  it("host-header poisoning, TRACE, Origin: null, a pre-set session cookie (fixation) and X-Forwarded-* spoofing do not help an attacker", async () => {
    const h = await startHarness(); const a = await startAdmin(h);
    try {
      const { request } = await import("undici");
      const raw = async (method: string, path: string, headers: Record<string, string>) => { const r = await request(`${a.origin}${path}`, { method: method as "GET", dispatcher: a.agent, headers, maxRedirections: 0 } as never); const t = await r.body.text(); return { status: r.statusCode, headers: r.headers, text: t }; };
      const { connect } = await import("node:tls");
      const rawHttp = (payload: string) => new Promise<string>((resolve) => { const sk = connect({ host: "127.0.0.1", port: a.port, servername: "localhost", ca: h.pki.caCert }, () => sk.write(payload)); let o = ""; sk.on("data", (d) => { o += d.toString(); }); sk.on("close", () => resolve(o)); sk.on("error", () => resolve(o)); setTimeout(() => { sk.destroy(); resolve(o); }, 1500); });
      const p = await rawHttp("GET /login HTTP/1.1\r\nhost: evil.example\r\nx-forwarded-host: evil.example\r\nx-forwarded-proto: http\r\nx-forwarded-for: 10.0.0.1\r\nconnection: close\r\n\r\n");
      expect(p).toMatch(/^HTTP\/1\.1 302/); expect(p).not.toMatch(/location: [^\r]*evil\.example/i); expect(p).not.toMatch(/Domain=/i);
      expect([404, 405, 400]).toContain((await raw("TRACE", "/", {})).status);
      // fixation: an attacker-chosen cookie value is never adopted; a new id is issued at login
      const fixed = "A".repeat(43);
      const alice = await a.login("alice"); expect(alice.cookie).not.toContain(fixed);
      expect((await raw("GET", "/", { cookie: `__Host-ts_admin=${fixed}` })).status).toBe(302);
      // Origin null (sandboxed iframe / data: URL) is not the portal's origin
      expect((await alice.post("/logout", {}, { origin: "null" })).status).toBe(403);
      // spoofed forwarding headers do not satisfy the source-address allow-list (the TCP peer is what counts)
      const closed = await startAdmin(h, { allowedCidrs: ["203.0.113.0/24"], reuseUsers: true });
      try { expect((await (await request(`${closed.origin}/login`, { method: "GET", dispatcher: closed.agent, headers: { "x-forwarded-for": "203.0.113.9", "x-real-ip": "203.0.113.9" } })).body.text())).toBe("forbidden"); } finally { await closed.stop(); }
    } finally { await a.stop(); await h.stop(); }
  });
});

describe("pentest: protocol abuse on both listeners (F-P1 HTTP/0.9 and 1.0, F-P2 Expect, F-P3 slow headers)", () => {
  it("participant plane: only HTTP/1.1 is served, Expect is refused before any upload invitation, slow-header clients are reaped within seconds", async () => {
    const h = await startHarness();
    try {
      const { connect } = await import("node:tls");
      const sock = (payload: string, ms = 2500) => new Promise<string>((resolve) => { const s = connect({ host: "127.0.0.1", port: h.port, servername: "localhost", ca: h.pki.caCert, cert: h.bankA.pem.cert, key: h.bankA.pem.key }, () => s.write(payload)); let o = ""; s.on("data", (d) => { o += d.toString("latin1"); }); s.on("close", () => resolve(o)); s.on("error", () => undefined); setTimeout(() => { s.destroy(); resolve(o); }, ms); });
      expect(await sock("GET /v1/statements\r\n\r\n")).toMatch(/^HTTP\/1\.1 505/);                           // HTTP/0.9 style: not processed
      expect(await sock("GET /v1/statements HTTP/1.0\r\n\r\n")).toMatch(/^HTTP\/1\.1 505/);
      const ex = await sock("POST /v1/consents HTTP/1.1\r\nhost: localhost\r\nexpect: 100-continue\r\ncontent-length: 999999999\r\nconnection: close\r\n\r\n");
      expect(ex).toMatch(/^HTTP\/1\.1 417/); expect(ex).not.toContain("100 Continue");
      const t0 = Date.now();
      const closedAt = await Promise.all(Array.from({ length: 20 }, () => new Promise<number>((resolve) => {
        const s = connect({ host: "127.0.0.1", port: h.port, servername: "localhost", ca: h.pki.caCert, cert: h.bankA.pem.cert, key: h.bankA.pem.key }, () => { s.write("POST /v1/consents HTTP/1.1\r\nhost: localhost\r\ncontent-length: 100\r\n"); const iv = setInterval(() => { try { s.write("x-slow: 1\r\n"); } catch { /* closed */ } }, 250); s.on("close", () => { clearInterval(iv); resolve(Date.now() - t0); }); });
        s.on("error", () => undefined); setTimeout(() => { s.destroy(); resolve(60_000); }, 20_000);
      })));
      expect(Math.max(...closedAt)).toBeLessThan(12_000);
      // idle connections (valid handshake, then silence) are reaped too: a stolen certificate must not be able to hold thousands of sockets open
      const t1 = Date.now();
      const idleClosed = await Promise.all(Array.from({ length: 30 }, () => new Promise<number>((resolve) => { const s = connect({ host: "127.0.0.1", port: h.port, servername: "localhost", ca: h.pki.caCert, cert: h.bankA.pem.cert, key: h.bankA.pem.key }); s.on("close", () => resolve(Date.now() - t1)); s.on("error", () => undefined); setTimeout(() => { s.destroy(); resolve(60_000); }, 14_000); })));
      expect(Math.max(...idleClosed)).toBeLessThan(13_000);
      expect((await h.call(h.bankA, "GET", "/v1/statements")).status).toBe(200);       // and the service is still healthy
    } finally { await h.stop(); }
  }, 50_000);
  it("admin plane: HTTP/0.9 and 1.0 are refused and Expect is refused", async () => {
    const h = await startHarness(); const a = await startAdmin(h);
    try {
      const { connect } = await import("node:tls");
      const sock = (payload: string) => new Promise<string>((resolve) => { const s = connect({ host: "127.0.0.1", port: a.port, servername: "localhost", ca: h.pki.caCert }, () => s.write(payload)); let o = ""; s.on("data", (d) => { o += d.toString("latin1"); }); s.on("close", () => resolve(o)); s.on("error", () => undefined); setTimeout(() => { s.destroy(); resolve(o); }, 2000); });
      expect(await sock("GET /login\r\n\r\n")).toMatch(/^HTTP\/1\.1 505/);
      expect(await sock("GET /login HTTP/1.0\r\n\r\n")).toMatch(/^HTTP\/1\.1 505/);
      expect(await sock("POST /logout HTTP/1.1\r\nhost: localhost\r\nexpect: 100-continue\r\ncontent-length: 5\r\nconnection: close\r\n\r\n")).toMatch(/^HTTP\/1\.1 417/);
    } finally { await a.stop(); await h.stop(); }
  });
});
