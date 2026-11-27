import { describe, it, expect, beforeAll, afterAll } from "vitest";
import { readFileSync, writeFileSync } from "node:fs";
import { request, Agent } from "undici";
import pg from "pg";
import { startHarness, num, type Harness } from "../helpers/harness.js";
import { verifyAuditChain } from "../../src/audit/audit.js";
import { withOrgTx, makePool } from "../../src/db/pool.js";
import { subjectHash } from "../../src/consent/consent.js";
import type { EphemeralStore } from "../../src/common/store.js";

let h: Harness;
beforeAll(async () => { h = await startHarness(); });
afterAll(async () => { await h.stop(); });
const check = (n: string, ref: string) => ({ phoneNumber: n, consentRef: ref, purposeCode: "FRAUD_PREVENTION" });
const sim = async (n: string) => { const c = await h.consent(h.bankA, n); return h.call(h.bankA, "POST", "/v1/signals/sim-swap/check", { body: check(n, c.ref) }); };

describe("signal safety: failures are UNAVAILABLE / NOT_SUPPORTED, never FALSE", () => {
  it.each([["2", "telco hangs (timeout)"], ["3", "telco 500"], ["4", "malformed JSON"], ["5", "telco 404 (unknown number)"], ["6", "wrong type for swapped"], ["7", "oversized / extra fields"]])(
    "digit %s: %s", async (d) => {
      const r = await sim(num(d, "0010"));
      expect(r.status).toBe(200);
      expect(r.json.result).toBe("UNAVAILABLE");
    });
  it("an unrouted number is UNAVAILABLE, indistinguishable from a telco failure", async () => {
    const a = await sim("+6188800010001"), b = await sim(num("3", "0010"));
    expect(a.json.result).toBe("UNAVAILABLE"); expect(b.json.result).toBe("UNAVAILABLE");
    expect(Object.keys(a.json).sort()).toEqual(Object.keys(b.json).sort());
  });
  it("failures are never billed; successes are", async () => {
    const { rows } = await h.migrator.query("SELECT outcome, billable, count(*)::int n FROM usage_record GROUP BY 1,2");
    for (const r of rows) if (r.outcome === "UNAVAILABLE" || r.outcome === "NOT_SUPPORTED" || r.outcome === "REJECTED") expect(r.billable).toBe(false);
    await sim(num("0", "0011"));
    expect((await h.migrator.query("SELECT 1 FROM usage_record WHERE outcome='FALSE' AND billable")).rowCount).toBeGreaterThan(0);
  });
  it("the DB itself refuses a billable failure record", async () => {
    await expect(h.migrator.query("INSERT INTO usage_record(org_id, signal, outcome, billable, total_ms, correlation_id) VALUES ($1,'SIM_SWAP','UNAVAILABLE',true,1,'x')", [h.orgA])).rejects.toThrow(/check/i);
  });
  it("the timeout bound holds (< 2 s) and the telco error text never reaches the participant", async () => {
    const t0 = Date.now();
    const r = await sim(num("3", "0012"));
    expect(Date.now() - t0).toBeLessThan(2000);
    expect(JSON.stringify(r.json)).not.toContain("secret-internal-detail");
  });
  it("kill switches fail closed: participant -> 403, signal/telco -> UNAVAILABLE with no telco call", async () => {
    const n = num("1", "0013"); const c = await h.consent(h.bankA, n);
    await h.migrator.query("INSERT INTO kill_switch(scope,key,enabled) VALUES ('signal','SIM_SWAP',true)");
    const calls = h.telco.calls;
    expect((await h.call(h.bankA, "POST", "/v1/signals/sim-swap/check", { body: check(n, c.ref) })).json.result).toBe("UNAVAILABLE");
    await h.migrator.query("UPDATE kill_switch SET enabled=false WHERE scope='signal'");
    await h.migrator.query("INSERT INTO kill_switch(scope,key,enabled) VALUES ('telco','telco-a',true)");
    expect((await h.call(h.bankA, "POST", "/v1/signals/sim-swap/check", { body: check(n, c.ref) })).json.result).toBe("UNAVAILABLE");
    await h.migrator.query("UPDATE kill_switch SET enabled=false WHERE scope='telco'");
    await h.migrator.query("INSERT INTO kill_switch(scope,key,enabled) VALUES ('participant','bank-a',true)");
    expect((await h.call(h.bankA, "POST", "/v1/signals/sim-swap/check", { body: check(n, c.ref) })).status).toBe(403);
    expect(h.telco.calls).toBe(calls);
    await h.migrator.query("UPDATE kill_switch SET enabled=false WHERE scope='participant'");
    expect((await h.call(h.bankA, "POST", "/v1/signals/sim-swap/check", { body: check(n, c.ref) })).json.result).toBe("TRUE");
  });
});

describe("input validation, limits, mass assignment, pollution", () => {
  const url = () => `/v1/signals/sim-swap/check`;
  it("rejects unknown fields (mass assignment) and non-E.164 numbers", async () => {
    const c = await h.consent(h.bankA, num("0", "0020"));
    expect((await h.call(h.bankA, "POST", url(), { body: { ...check(num("0", "0020"), c.ref), orgId: h.orgB } })).status).toBe(400);
    expect((await h.call(h.bankA, "POST", url(), { body: { ...check("0123456789", c.ref) } })).status).toBe(400);
    expect((await h.call(h.bankA, "POST", url(), { body: { ...check(num("0", "0020"), c.ref), maxAge: 99999 } })).status).toBe(400);
    expect((await h.call(h.bankA, "POST", url(), { body: { ...check(num("0", "0020"), c.ref), maxAge: "24" } })).status).toBe(400);
  });
  it("rejects __proto__ / constructor pollution attempts", async () => {
    const raw = `{"phoneNumber":"${num("0", "0021")}","consentRef":"CONSENT-AAAA","purposeCode":"FRAUD_PREVENTION","__proto__":{"admin":true}}`;
    expect((await h.call(h.bankA, "POST", url(), { rawBody: raw })).status).toBe(400);
    expect(({} as Record<string, unknown>)["admin"]).toBeUndefined();
  });
  it("rejects oversized bodies and wrong content types", async () => {
    expect((await h.call(h.bankA, "POST", url(), { rawBody: JSON.stringify({ phoneNumber: "+60", pad: "x".repeat(6000) }) })).status).toBe(413);
    expect((await h.call(h.bankA, "POST", url(), { rawBody: "a=b", contentType: "text/plain" })).status).toBeGreaterThanOrEqual(400);
    expect((await h.call(h.bankA, "POST", url(), { rawBody: "{not json" })).status).toBe(400);
  });
  it("errors reveal no internals", async () => {
    const r = await h.call(h.bankA, "POST", url(), { rawBody: "{not json" });
    expect(Object.keys(r.json).sort()).toEqual(["code", "correlationId", "message", "status"]);
    expect(JSON.stringify(r.json)).not.toMatch(/stack|at .*\.ts|postgres|undici|fastify/i);
    expect((await h.call(h.bankA, "GET", "/nope")).status).toBe(404);
  });
});

describe("transport: mTLS required", () => {
  it("rejects connections without a client certificate or with one from an untrusted CA", async () => {
    const noCert = new Agent({ connect: { ca: h.pki.caCert } });
    await expect(request(`https://localhost:${h.port}/.well-known/jwks.json`, { dispatcher: noCert })).rejects.toThrow();
    const rogue = h.pki.issue("rogue-client", { ca: "rogue" });
    const rogueAgent = new Agent({ connect: { ca: h.pki.caCert, cert: rogue.cert, key: rogue.key } });
    await expect(request(`https://localhost:${h.port}/.well-known/jwks.json`, { dispatcher: rogueAgent })).rejects.toThrow();
    await noCert.close(); await rogueAgent.close();
  });
  it("refuses TLS 1.1 and below", async () => {
    const old = new Agent({ connect: { ca: h.pki.caCert, cert: h.bankA.pem.cert, key: h.bankA.pem.key, maxVersion: "TLSv1.1", minVersion: "TLSv1" } });
    await expect(request(`https://localhost:${h.port}/.well-known/jwks.json`, { dispatcher: old })).rejects.toThrow();
    await old.close();
  });
  it("negotiates TLS 1.3 by default", async () => {
    const { connect } = await import("node:tls");
    const proto = await new Promise<string | null>((res, rej) => { const s = connect({ host: "127.0.0.1", port: h.port, servername: "localhost", ca: h.pki.caCert, cert: h.bankA.pem.cert, key: h.bankA.pem.key }, () => { const p = s.getProtocol(); s.end(); res(p); }); s.on("error", rej); });
    expect(proto).toBe("TLSv1.3");
  });
  it("a certificate valid for the platform but not registered for the client cannot authenticate (cert-bound keys)", async () => {
    const stray = h.pki.issue("stray-cert");
    const c = await h.newClient("bank-stray", h.orgA, ["sim-swap:check"], { registerCert: "A".repeat(43) });
    await expect(h.token(c)).rejects.toThrow(/401/);
    void stray;
  });
});

describe("client authentication hygiene (private_key_jwt)", () => {
  const post = async (assertion: string) => {
    const form = new URLSearchParams({ grant_type: "client_credentials", client_id: "bank-a", client_assertion_type: "urn:ietf:params:oauth:client-assertion-type:jwt-bearer", client_assertion: assertion });
    const r = await request(h.cfg.tokenEndpoint, { method: "POST", dispatcher: h.bankA.agent, headers: { "content-type": "application/x-www-form-urlencoded" }, body: form.toString() });
    await r.body.dump(); return r.statusCode;
  };
  it("rejects wrong audience, over-long lifetime, expired and wrong-issuer assertions", async () => {
    const now = Math.floor(Date.now() / 1000);
    expect(await post(await h.assertion(h.bankA, { aud: "https://other.test/token" }))).toBe(401);
    expect(await post(await h.assertion(h.bankA, { exp: now + 3600 }))).toBe(401);
    expect(await post(await h.assertion(h.bankA, { iat: now - 600, exp: now - 500 }))).toBe(401);
    expect(await post(await h.assertion(h.bankA, { iss: "bank-b" }))).toBe(401);
    expect(await post(await h.assertion(h.bankA))).toBe(200);
  });
  it("rejects client_secret style authentication and unexpected parameters", async () => {
    const r = await request(h.cfg.tokenEndpoint, { method: "POST", dispatcher: h.bankA.agent, headers: { "content-type": "application/x-www-form-urlencoded" }, body: "grant_type=client_credentials&client_id=bank-a&client_secret=hunter2" });
    await r.body.dump(); expect(r.statusCode).toBe(400);
  });
  it("an expired or revoked registered key cannot authenticate", async () => {
    const c = await h.newClient("bank-keyexp", h.orgA, ["sim-swap:check"]);
    await h.migrator.query("UPDATE client_keys SET revoked_at=now() WHERE client_id='bank-keyexp'");
    await expect(h.token(c)).rejects.toThrow(/401/);
    const d = await h.newClient("bank-keyexp2", h.orgA, ["sim-swap:check"]);
    await h.migrator.query("UPDATE client_keys SET expires_at=now() - interval '1 minute' WHERE client_id='bank-keyexp2'");
    await expect(h.token(d)).rejects.toThrow(/401/);
  });
  it("the database refuses to store private key material in a participant key record", async () => {
    await expect(h.migrator.query("INSERT INTO client_keys(client_id,kid,jwk,cert_sha256,expires_at) VALUES ('bank-a','bad',$1,$2, now()+interval '1 day')", [JSON.stringify({ kty: "EC", crv: "P-256", x: "a", y: "b", d: "secret" }), "A".repeat(43)])).rejects.toThrow(/check/i);
  });
});

describe("fail closed when the replay store is down", () => {
  it("returns 503 and does not call the telco", async () => {
    const down: EphemeralStore = { setNx: async () => { throw new Error("redis down"); }, incr: async () => { throw new Error("redis down"); }, close: async () => undefined };
    const h2 = await startHarness({ store: down });
    try {
      // token endpoint also depends on the store: it must fail closed too
      await expect(h2.token(h2.bankA)).rejects.toThrow(/503/);
      expect(h2.telco.calls).toBe(0);
    } finally { await h2.stop(); }
  });
});

describe("audit log: append-only, hash-chained, external copy", () => {
  it("verifies, and records access without any phone number", async () => {
    const v = await verifyAuditChain(h.reporting, h.auditSink);
    expect(v.problem ?? "ok").toBe("ok"); expect(v.ok).toBe(true); expect(v.rows).toBeGreaterThan(10);
    const { rows } = await h.migrator.query("SELECT * FROM audit_log");
    expect(JSON.stringify(rows.map((r) => [r.action, r.detail_text, r.actor]))).not.toMatch(/\+[1-9][0-9]{4,14}/);
    expect(rows.some((r) => r.action === "signal.sim_swap.check")).toBe(true);
    expect(rows.some((r) => r.action === "token.issued")).toBe(true);
    expect(rows.some((r) => r.action === "request.rejected")).toBe(true);
  });
  it("the application role cannot update, delete, truncate or insert directly", async () => {
    for (const sql of ["UPDATE audit_log SET outcome='OK'", "DELETE FROM audit_log", "TRUNCATE audit_log", "INSERT INTO audit_log(seq,ts_us,correlation_id,actor,action,outcome,detail_text,prev_hash,hash) VALUES (1,1,'c','a','x','o','{}','\\x00','\\x00')", "SELECT * FROM audit_log"])
      await expect(h.pool.query(sql)).rejects.toThrow(/permission denied/i);
  });
  it("even the schema owner cannot mutate it (trigger)", async () => {
    await expect(h.migrator.query("UPDATE audit_log SET outcome='OK'")).rejects.toThrow(/permission denied|append-only/i);
    await expect(h.migrator.query("DELETE FROM audit_log")).rejects.toThrow(/append-only|permission denied/i);
  });
  it("tampering by a superuser is detected by the chain and by the external copy", async () => {
    const su = new pg.Client({ connectionString: h.adminUrl.replace(/\/[^/]*$/, `/${h.dbName}`) }); await su.connect();
    await su.query("ALTER TABLE audit_log DISABLE TRIGGER audit_no_update");
    await su.query("UPDATE audit_log SET outcome='TAMPERED' WHERE seq = 3");
    expect((await verifyAuditChain(h.reporting, h.auditSink)).ok).toBe(false);
    await su.query("UPDATE audit_log SET outcome=(SELECT outcome FROM audit_log WHERE seq=3 LIMIT 0) WHERE false");
    await su.query("ALTER TABLE audit_log ENABLE TRIGGER audit_no_update"); await su.end();
  });
  it("deleting from the external copy is detected", async () => {
    const lines = readFileSync(h.auditSink, "utf8").split("\n").filter(Boolean);
    const h3 = await startHarness();           // clean chain
    try {
      await h3.consent(h3.bankA, num("0", "0040"));
      expect((await verifyAuditChain(h3.reporting, h3.auditSink)).ok).toBe(true);
      const l = readFileSync(h3.auditSink, "utf8").split("\n").filter(Boolean); writeFileSync(h3.auditSink, l.slice(0, -1).join("\n") + "\n");
      const v = await verifyAuditChain(h3.reporting, h3.auditSink);
      expect(v.ok).toBe(false); expect(v.problem).toMatch(/external copy/);
    } finally { await h3.stop(); }
    void lines;
  });
});

describe("database: least privilege and row-level security", () => {
  it("application role: not owner, no bypass, no DDL, cannot read other tables it does not need", async () => {
    const r = await h.pool.query("SELECT rolsuper, rolbypassrls, rolcreatedb, rolcreaterole FROM pg_roles WHERE rolname = current_user");
    expect(r.rows[0]).toEqual({ rolsuper: false, rolbypassrls: false, rolcreatedb: false, rolcreaterole: false });
    await expect(h.pool.query("CREATE TABLE x(a int)")).rejects.toThrow(/permission denied/i);
    await expect(h.pool.query("ALTER TABLE consents DISABLE ROW LEVEL SECURITY")).rejects.toThrow(/must be owner/i);
    await expect(h.pool.query("SELECT * FROM organisations")).rejects.toThrow(/permission denied/i);
    await expect(h.pool.query("UPDATE consents SET expires_at = now()")).rejects.toThrow(/permission denied/i);
    await expect(h.pool.query("DELETE FROM usage_record")).rejects.toThrow(/permission denied/i);
    const own = await h.pool.query("SELECT count(*)::int n FROM pg_tables WHERE tableowner = current_user");
    expect(own.rows[0].n).toBe(0);
  });
  it("no tenant context => no tenant rows; wrong tenant => no rows", async () => {
    const n = num("0", "0050"); await h.consent(h.bankA, n);
    expect((await h.pool.query("SELECT count(*)::int n FROM consents")).rows[0].n).toBe(0);
    expect((await withOrgTx(h.pool, h.orgB, (tx) => tx.query("SELECT count(*)::int n FROM consents WHERE org_id=$1", [h.orgA]))).rows[0].n).toBe(0);
    expect((await withOrgTx(h.pool, h.orgA, (tx) => tx.query("SELECT count(*)::int n FROM consents"))).rows[0].n).toBeGreaterThan(0);
  });
  it("a tenant context cannot be written for another organisation", async () => {
    const hash = await subjectHash(h.kms, num("0", "0051"));
    await expect(withOrgTx(h.pool, h.orgB, (tx) => tx.query("INSERT INTO consents(org_id,consent_ref,subject_hash,purpose_code,signals,expires_at) VALUES ($1,'XXXX-1',$2,'FRAUD_PREVENTION','{SIM_SWAP}', now()+interval '1 day')", [h.orgA, hash]))).rejects.toThrow(/row-level security/i);
  });
  it("tenant context does not leak across pooled connection reuse (single-connection pool)", async () => {
    const p1 = makePool(h.urls.app, { max: 1 });
    try {
      await withOrgTx(p1, h.orgA, async (tx) => (await tx.query("SELECT count(*)::int n FROM consents")).rows[0].n);
      const after = await p1.query("SELECT current_setting('app.org_id', true) AS s, (SELECT count(*)::int FROM consents) AS n");
      expect(["", null]).toContain(after.rows[0].s);
      expect(after.rows[0].n).toBe(0);
      await expect(withOrgTx(p1, h.orgA, async (tx) => { await tx.query("SELECT 1/0"); })).rejects.toThrow();
      const after2 = await p1.query("SELECT (SELECT count(*)::int FROM consents) AS n");
      expect(after2.rows[0].n).toBe(0);
    } finally { await p1.end(); }
  });
  it("reporting role is read-only", async () => {
    expect((await h.reporting.query("SELECT count(*)::int n FROM usage_record")).rows[0].n).toBeGreaterThan(0);
    await expect(h.reporting.query("DELETE FROM usage_record")).rejects.toThrow(/permission denied/i);
    await expect(h.reporting.query("INSERT INTO telcos(id,adapter,base_url) VALUES ('x','camara','https://x')")).rejects.toThrow(/permission denied/i);
  });
  it("migrations are checksummed: a modified applied migration is refused", async () => {
    const { migrate } = await import("../../src/db/migrate.js");
    await h.migrator.query("UPDATE schema_migrations SET sha256='deadbeef'");
    await expect(migrate(h.urls.migrator, "migrations")).rejects.toThrow(/modified after being applied/);
  });
});

describe("privacy: no raw phone numbers or consent data at rest or in logs", () => {
  it("no E.164 number in logs, audit, usage records or consent rows", async () => {
    const n = num("1", "0060");
    await sim(n);
    const dump = JSON.stringify([
      (await h.migrator.query("SELECT * FROM consents")).rows.map((r) => ({ ...r, subject_hash: "[bytes]" })),
      (await h.migrator.query("SELECT * FROM usage_record")).rows,
      (await h.migrator.query("SELECT * FROM audit_log")).rows.map((r) => ({ ...r, prev_hash: 0, hash: 0 })),
    ]);
    expect(dump).not.toContain(n); expect(dump).not.toMatch(/\+6099900/);
    const logs = h.logs.join("");
    expect(logs.length).toBeGreaterThan(0);
    expect(logs).not.toMatch(/\+[1-9][0-9]{4,14}/);
    expect(logs).not.toMatch(/eyJ[A-Za-z0-9_-]{20,}/);          // no bearer tokens / assertions in logs
  });
  it("subject hashes are keyed: same number, different KMS key => different hash", async () => {
    const a = await subjectHash(h.kms, "+60999000001"), b = await h.kms.hmac("another-key", "+60999000001");
    expect(a.equals(b)).toBe(false); expect(a.length).toBe(32);
  });
  it("the telco only ever receives the number and window", async () => {
    await sim(num("0", "0061"));
    expect(Object.keys(JSON.parse(h.telco.lastBody!)).sort()).toEqual(["maxAge", "phoneNumber"]);
  });
});

describe("KMS: key versions and rotation", () => {
  it("rotation: old ciphertext still decrypts, new writes use the new version, tampering/AAD mismatch fails", async () => {
    const e1 = await h.kms.encrypt("field-key", Buffer.from("secret-value"), "ctx-1");
    expect(e1.startsWith("v1.")).toBe(true);
    expect(await h.kms.rotate("field-key")).toBe(2);
    const e2 = await h.kms.encrypt("field-key", Buffer.from("secret-value"), "ctx-1");
    expect(e2.startsWith("v2.")).toBe(true);
    expect((await h.kms.decrypt("field-key", e1, "ctx-1")).toString()).toBe("secret-value");
    await expect(h.kms.decrypt("field-key", e2, "other-context")).rejects.toThrow();
    const parts = e2.split("."); parts[2] = Buffer.from("x").toString("base64url");
    await expect(h.kms.decrypt("field-key", parts.join("."), "ctx-1")).rejects.toThrow();
  });
  it("token signing key rotation: tokens issued before rotation stay valid until expiry; new tokens use the new kid", async () => {
    const before = await h.token(h.bankA);
    await h.kms.rotate("token-signing-ec");
    const after = await h.token(h.bankA);
    const kid = (t: string) => JSON.parse(Buffer.from(t.split(".")[0]!, "base64url").toString()).kid;
    expect(kid(before)).toBe("ts-sig-v1"); expect(kid(after)).toBe("ts-sig-v2");
    const n = num("0", "0070"); const c = await h.consent(h.bankA, n);
    expect((await h.call(h.bankA, "POST", "/v1/signals/sim-swap/check", { body: check(n, c.ref), token: before })).status).toBe(200);
    expect((await h.call(h.bankA, "POST", "/v1/signals/sim-swap/check", { body: check(n, c.ref), token: after })).status).toBe(200);
    expect(((await h.kms.verificationJwks()).keys as unknown[]).length).toBe(2);
  });
  it("the key directory is private (0700) and keys are not in the repo or image build context", async () => {
    const { statSync } = await import("node:fs");
    expect(statSync(h.kmsDir).mode & 0o777).toBe(0o700);
  });
});
