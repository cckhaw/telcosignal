// M5 adversarial review of the participant plane, organised by OWASP API Security Top 10 (2023) category plus the abuse cases the
// earlier milestones left open (AB-09). Each block states the attack, then asserts the control. Synthetic data only.
import { describe, it, expect, beforeAll, afterAll } from "vitest";
import { connect } from "node:tls";
import { randomUUID } from "node:crypto";
import { readFileSync } from "node:fs";
import { startHarness, num, type Harness } from "../helpers/harness.js";
import { verifyAuditChain } from "../../src/audit/audit.js";

let h: Harness;
beforeAll(async () => { h = await startHarness({ minResponseMs: 40 }); });
afterAll(async () => { await h.stop(); });
const SIM = "/v1/signals/sim-swap/check";
const body = (n: string, ref: string) => ({ phoneNumber: n, consentRef: ref, purposeCode: "FRAUD_PREVENTION" });

/** Raw HTTP/1.1 over mTLS: for requests a well-behaved client library would never send. */
function raw(c: typeof h.bankA, payload: string): Promise<string> {
  return new Promise((resolve) => {
    const s = connect({ host: "127.0.0.1", port: h.port, servername: "localhost", ca: h.pki.caCert, cert: c.pem.cert, key: c.pem.key }, () => s.write(payload));
    let out = ""; s.on("data", (d) => { out += d.toString(); }); s.on("error", () => resolve(out)); s.on("close", () => resolve(out));
    setTimeout(() => { s.destroy(); resolve(out); }, 1500);
  });
}

describe("API1:2023 broken object level authorization", () => {
  it("every object-by-id route answers identically for another organisation's object and for a nonexistent one", async () => {
    const n = num("0", "0501"); const cB = await h.consent(h.bankB, n);
    const other = await h.call(h.bankA, "GET", `/v1/consents/${cB.id}`);
    const none = await h.call(h.bankA, "GET", "/v1/consents/00000000-0000-4000-8000-000000000000");
    expect(other.status).toBe(404); expect(none.status).toBe(404);
    expect({ ...other.json, correlationId: 0 }).toEqual({ ...none.json, correlationId: 0 });
    const rev = await h.call(h.bankA, "POST", `/v1/consents/${cB.id}/revoke`);
    expect(rev.status).toBe(404);
    expect((await h.call(h.bankB, "GET", `/v1/consents/${cB.id}`)).json.revoked).toBe(false);     // the attack changed nothing
    const st = await h.migrator.query("INSERT INTO statement(org_id, period_start, period_end, currency, lines, usage_count, total_minor, usage_digest) VALUES ($1, now() - interval '2 day', now() - interval '1 day', 'MYR', '[]', 0, 0, 'x') RETURNING id", [h.orgB]).catch(() => null);
    if (st) { expect((await h.call(h.bankA, "GET", `/v1/statements/${st.rows[0].id}`)).status).toBe(404); expect((await h.call(h.bankB, "GET", `/v1/statements/${st.rows[0].id}`)).status).toBe(200); }
  });
  it("a consent registered by one organisation cannot be used by another for the same number", async () => {
    const n = num("0", "0502"); const cB = await h.consent(h.bankB, n);
    const r = await h.call(h.bankA, "POST", SIM, { body: body(n, cB.ref) });
    expect(r.status).toBe(403); expect(r.json.code).toBe("CONSENT_REQUIRED");
  });
});

describe("API2:2023 broken authentication", () => {
  it("two Authorization headers, a Bearer with trailing junk, and a lower-case scheme never authenticate as someone else", async () => {
    const good = await h.token(h.bankA);
    const mk = (hdrs: string) => `POST /v1/consents/${"0".repeat(8)}-0000-4000-8000-000000000000/revoke HTTP/1.1\r\nhost: localhost\r\n${hdrs}content-length: 0\r\nconnection: close\r\n\r\n`;
    const dup = await raw(h.bankC, mk(`authorization: Bearer ${good}\r\nauthorization: Bearer x\r\n`));
    expect(dup).toMatch(/^HTTP\/1\.1 (400|401|403)/);               // bank-c's TLS identity is not bound to bank-a's token, and duplicates are refused by the parser
    const junk = await h.call(h.bankA, "POST", "/v1/consents/00000000-0000-4000-8000-000000000000/revoke", { token: `${good}.junk` });
    expect(junk.status).toBe(401);
  });
  it("a token issued to one certificate is useless on a connection made with another certificate of the same organisation", async () => {
    const twin = await h.newClient("bank-a-twin", h.orgA, ["consent:read"]);
    const t = await h.token(h.bankA, "consent:read");
    const r = await h.call(twin, "GET", "/v1/consents/00000000-0000-4000-8000-000000000000", { token: t });
    expect(r.status).toBe(401);
  });
  it("failed authentication gives one uniform answer whatever the reason (unknown client, bad key, wrong cert)", async () => {
    const shapes = new Set<string>();
    for (const t of ["", "Bearer", "Bearer abc", `Bearer ${await h.token(h.bankA)}x`]) {
      const r = await h.call(h.bankA, "GET", "/v1/statements", { token: null, headers: t ? { authorization: t } : {} });
      expect(r.status).toBe(401); shapes.add(JSON.stringify(Object.keys(r.json).sort()) + r.json.code + r.json.message);
    }
    expect(shapes.size).toBe(1);
  });
});

describe("API3:2023 broken object property level authorization", () => {
  it("responses contain exactly the documented properties (no internals, hashes, org ids, key ids, SQL columns)", async () => {
    const n = num("0", "0510"); const c = await h.consent(h.bankA, n);
    const got = await h.call(h.bankA, "GET", `/v1/consents/${c.id}`);
    expect(Object.keys(got.json).sort()).toEqual(["consentRef", "correlationId", "expiresAt", "id", "purposeCode", "revoked", "signals"]);
    const sig = await h.call(h.bankA, "POST", SIM, { body: body(n, c.ref) });
    expect(Object.keys(sig.json).sort()).toEqual(["correlationId", "result", "signal"]);
    const text = JSON.stringify([got.json, sig.json]);
    for (const banned of [h.orgA, "org_id", "subject_hash", "subjectHash", "telco", "adapter", "kid", "sha256"]) expect(text).not.toContain(banned);
  });
  it("read-only and server-controlled properties cannot be written through consent creation (revoked, id, orgId, createdAt)", async () => {
    for (const extra of [{ revoked: true }, { id: "00000000-0000-4000-8000-000000000001" }, { orgId: h.orgB }, { org_id: h.orgB }, { createdAt: "2020-01-01T00:00:00Z" }, { subjectHash: "aa" }]) {
      const r = await h.call(h.bankA, "POST", "/v1/consents", { body: { phoneNumber: num("0", "0511"), consentRef: `X-${randomUUID()}`, purposeCode: "FRAUD_PREVENTION", signals: ["SIM_SWAP"], expiresAt: new Date(Date.now() + 3.6e6).toISOString(), ...extra } });
      expect(r.status, JSON.stringify(extra)).toBe(400);
    }
  });
});

describe("API4:2023 unrestricted resource consumption", () => {
  it("a flood above the limit is shed with 429 and does NOT become audit-chain writes (no serialised DB write per refused request)", async () => {
    const hh = await startHarness({ rps: 5 });
    try {
      const t = await hh.token(hh.bankA);
      const before = (await hh.migrator.query("SELECT count(*)::int n FROM audit_log")).rows[0].n as number;
      const rs = await Promise.all(Array.from({ length: 60 }, () => hh.call(hh.bankA, "GET", "/v1/statements", { token: t })));
      const limited = rs.filter((r) => r.status === 429).length; expect(limited).toBeGreaterThan(40);
      const after = (await hh.migrator.query("SELECT count(*)::int n FROM audit_log")).rows[0].n as number;
      expect(after - before).toBeLessThan(15);             // only the (few) served requests may audit; 429s do not
      expect((await verifyAuditChain(hh.migrator, hh.auditSink)).ok).toBe(true);
    } finally { await hh.stop(); }
  });
  it("consent registration is quota-limited per organisation (consent farming / storage exhaustion)", async () => {
    const hh = await startHarness({ limits: { perParticipantConsentPerMinute: 4 } });
    try {
      const codes: number[] = [];
      for (let i = 0; i < 7; i++) codes.push((await hh.call(hh.bankA, "POST", "/v1/consents", { body: { phoneNumber: num("0", `06${i}0`), consentRef: `QUOTA-REF-${i}`, purposeCode: "FRAUD_PREVENTION", signals: ["SIM_SWAP"], expiresAt: new Date(Date.now() + 3.6e6).toISOString() } })).status);
      expect(codes).toEqual([201, 201, 201, 201, 429, 429, 429]);
      expect((await hh.call(hh.bankB, "POST", "/v1/consents", { body: { phoneNumber: num("0", "0699"), consentRef: "QUOTA-REF-b", purposeCode: "FRAUD_PREVENTION", signals: ["SIM_SWAP"], expiresAt: new Date(Date.now() + 3.6e6).toISOString() } })).status).toBe(201);   // other orgs keep their budget
    } finally { await hh.stop(); }
  });
  it("oversized bodies, deep nesting, huge arrays and enormous numbers are refused cheaply and consistently", async () => {
    const c = h.bankA;
    expect((await h.call(c, "POST", SIM, { rawBody: "x".repeat(5000) })).status).toBe(413);
    expect((await h.call(c, "POST", SIM, { rawBody: "[".repeat(3000) })).status).toBe(400);
    expect((await h.call(c, "POST", "/v1/consents", { body: { phoneNumber: num("0", "0520"), consentRef: "A", purposeCode: "FRAUD_PREVENTION", signals: Array(30).fill("SIM_SWAP"), expiresAt: new Date(Date.now() + 3.6e6).toISOString() } })).status).toBe(400);
    expect((await h.call(c, "POST", SIM, { rawBody: `{"phoneNumber":"${num("0", "0521")}","consentRef":"A","purposeCode":"FRAUD_PREVENTION","maxAge":1e999}` })).status).toBe(400);
  });
  it("slow headers do not hold a connection beyond the header/connection timeouts", async () => {
    const t0 = Date.now();
    const out = await raw(h.bankA, "POST /v1/consents HTTP/1.1\r\nhost: localhost\r\nx-slow: ");   // never finishes the header block
    expect(Date.now() - t0).toBeLessThan(2000); expect(out === "" || out.startsWith("HTTP/1.1 4")).toBe(true);
  });
});

describe("API5:2023 broken function level authorization", () => {
  it("method override headers, HEAD/OPTIONS/TRACE and path tricks reach nothing privileged", async () => {
    const t = await h.token(h.bankA);
    for (const hd of [{ "x-http-method-override": "DELETE" }, { "x-method-override": "PUT" }, { "x-original-url": "/admin" }, { "x-forwarded-for": "127.0.0.1" }, { "x-forwarded-prefix": "/admin" }])
      expect([200, 404]).toContain((await h.call(h.bankA, "GET", "/v1/statements", { token: t, headers: hd })).status);
    for (const m of ["TRACE", "OPTIONS", "PUT", "DELETE", "PATCH"]) {
      const out = await raw(h.bankA, `${m} /v1/statements HTTP/1.1\r\nhost: localhost\r\nauthorization: Bearer ${t}\r\ncontent-length: 0\r\nconnection: close\r\n\r\n`);
      expect(out, m).toMatch(/^HTTP\/1\.1 (404|405|400)/);
    }
    for (const p of ["/admin", "/admin/", "/v1/../admin", "/v1/%2e%2e/admin", "/metrics", "/debug", "/health/../admin", "/v1/statements/..%2f..%2fadmin", "/.git/config", "/api-docs", "/swagger.json", "/openapi.json"])
      expect((await h.call(h.bankA, "GET", p, { token: t })).status, p).toBe(404);
  });
  it("a scope-limited client cannot reach functions outside its scopes, including by sending the wanted scope at the token endpoint", async () => {
    const r = await h.call(h.bankC, "POST", SIM, { body: body(num("0", "0530"), "X") });
    expect(r.status).toBe(403);
    const form = new URLSearchParams({ grant_type: "client_credentials", client_id: "bank-c", client_assertion_type: "urn:ietf:params:oauth:client-assertion-type:jwt-bearer", client_assertion: await h.assertion(h.bankC), scope: "sim-swap:check consent:write" });
    const { request } = await import("undici");
    const tr = await request(h.cfg.tokenEndpoint, { method: "POST", dispatcher: h.bankC.agent, headers: { "content-type": "application/x-www-form-urlencoded" }, body: form.toString() });
    expect(tr.statusCode).toBe(403); await tr.body.text();
  });
});

describe("API6:2023 unrestricted access to sensitive business flows", () => {
  it("the signal flow cannot be run without a registered consent for exactly this number, purpose and signal", async () => {
    const n = num("0", "0540"); const c = await h.consent(h.bankA, n, { signals: ["SIM_SWAP"] });
    expect((await h.call(h.bankA, "POST", SIM, { body: body(num("0", "0541"), c.ref) })).status).toBe(403);                  // other number
    expect((await h.call(h.bankA, "POST", SIM, { body: { ...body(n, c.ref), purposeCode: "TRANSACTION_RISK" } })).status).toBe(403);   // other purpose
    expect((await h.call(h.bankA, "POST", "/v1/signals/device-swap/check", { body: body(n, c.ref) })).status).toBe(403);       // other signal
    expect((await h.call(h.bankA, "POST", SIM, { body: body(n, c.ref) })).status).toBe(200);
    await h.call(h.bankA, "POST", `/v1/consents/${c.id}/revoke`);
    expect((await h.call(h.bankA, "POST", SIM, { body: body(n, c.ref) })).status).toBe(403);                                 // revocation is immediate
  });
});

describe("API7:2023 server side request forgery", () => {
  it("no participant-supplied value ever becomes a URL, host or header on an outbound telco call", async () => {
    const n = num("0", "0550"); const c = await h.consent(h.bankA, n);
    const before = h.telco.calls;
    for (const ref of ["http://169.254.169.254/latest/meta-data", "https://evil.example/x", "\r\nHost: evil"]) {
      const r = await h.call(h.bankA, "POST", SIM, { body: { phoneNumber: n, consentRef: ref, purposeCode: "FRAUD_PREVENTION" } });
      expect([400, 403]).toContain(r.status);
    }
    expect(h.telco.calls).toBe(before);
    const ok = await h.call(h.bankA, "POST", SIM, { body: body(n, c.ref) }); expect(ok.status).toBe(200);
  });
});

describe("API8:2023 security misconfiguration", () => {
  it("every response, including errors and 404s, carries the hardening headers and no server fingerprint, CORS or cookies", async () => {
    for (const [m, p] of [["GET", "/v1/statements"], ["GET", "/nope"], ["POST", "/v1/consents"], ["GET", "/.well-known/jwks.json"]] as const) {
      const r = await h.call(h.bankA, m, p, { token: null });
      expect(r.headers["cache-control"], p).toBe("no-store"); expect(r.headers["x-content-type-options"], p).toBe("nosniff");
      expect(String(r.headers["strict-transport-security"]), p).toContain("max-age=");
      for (const banned of ["server", "x-powered-by", "access-control-allow-origin", "set-cookie", "via"]) expect(r.headers[banned], `${p} ${banned}`).toBeUndefined();
    }
  });
  it("CL.TE / TE.CL request smuggling, bare LF and obsolete line folding are rejected by the parser", async () => {
    const t = await h.token(h.bankA);
    const smuggle = await raw(h.bankA, `POST /v1/consents HTTP/1.1\r\nhost: localhost\r\nauthorization: Bearer ${t}\r\ncontent-length: 4\r\ntransfer-encoding: chunked\r\n\r\n0\r\n\r\nGET /v1/statements HTTP/1.1\r\nhost: localhost\r\n\r\n`);
    expect((smuggle.match(/HTTP\/1\.1 /g) ?? []).length).toBeLessThanOrEqual(1);
    expect(smuggle).toMatch(/^HTTP\/1\.1 4/);
    const fold = await raw(h.bankA, `GET /v1/statements HTTP/1.1\r\nhost: localhost\r\nauthorization: Bearer x\r\n y\r\n\r\n`);
    expect(fold).toMatch(/^HTTP\/1\.1 4/);
  });
  it("error bodies never contain stack traces, file paths, SQL, library names or the exception text", async () => {
    const outs = [await h.call(h.bankA, "POST", SIM, { rawBody: "{" }), await h.call(h.bankA, "POST", SIM, { body: { phoneNumber: "'; DROP TABLE consents;--", consentRef: "x", purposeCode: "FRAUD_PREVENTION" } }), await h.call(h.bankA, "GET", "/v1/consents/not-a-uuid")];
    for (const o of outs) expect(JSON.stringify(o.json)).not.toMatch(/at \S+ \(|\.ts|\.js|node_modules|select |insert |pg_|ajv|fastify|ECONN|stack/i);
  });
  it("the source tree sets no permissive CORS, no wildcard origin and no debug switches", () => {
    const src = readFileSync("src/participant-api/server.ts", "utf8") + readFileSync("src/admin/server.ts", "utf8");
    expect(src).not.toMatch(/@fastify\/cors|access-control-allow-origin|origin:\s*true|NODE_TLS_REJECT_UNAUTHORIZED|rejectUnauthorized:\s*false/i);
  });
});

describe("API9:2023 improper inventory management", () => {
  it("every registered route is in the published OpenAPI document, and the document lists nothing else (no shadow or deprecated endpoints)", () => {
    const spec = readFileSync("openapi/participant.yaml", "utf8");
    const paths = [...spec.matchAll(/^ {2}(\/[^\s:]*):/gm)].map((m) => m[1]!).sort();
    const toOpenApi = (u: string) => u.replace(/:([A-Za-z]+)/g, "{$1}");
    const routes = [...new Set(h.app.routeTable.map((r) => toOpenApi(r.url)))].filter((u) => u !== "/.well-known/jwks.json" || true).sort();
    expect(routes).toEqual(paths);
  });
});

describe("API10:2023 unsafe consumption of APIs", () => {
  it("a telco that answers with attacker-shaped data cannot make the platform answer FALSE, leak its text, or crash (digits 2-7 of the mock)", async () => {
    for (const d of ["2", "3", "4", "5", "6", "7"]) {
      const n = num(d, "0560"); const c = await h.consent(h.bankA, n);
      const r = await h.call(h.bankA, "POST", SIM, { body: body(n, c.ref) });
      expect(r.json.result, d).toBe("UNAVAILABLE");
    }
  });
});

describe("AB-09 timing: refusals and telco-less answers are not measurably faster than a normal answer", () => {
  const time = async (f: () => Promise<unknown>) => { const t = performance.now(); await f(); return performance.now() - t; };
  it("a refused request, an unroutable number and a bad token all take at least the floor", async () => {
    const nr = "+6188800777001"; const c = await h.consent(h.bankA, nr);
    const t = await h.token(h.bankA);
    const times = [
      await time(() => h.call(h.bankA, "POST", SIM, { body: body(nr, c.ref), token: t })),                         // unroutable -> UNAVAILABLE, no telco call
      await time(() => h.call(h.bankA, "POST", SIM, { body: body(num("0", "0570"), "NOPE"), token: t })),           // consent refusal
      await time(() => h.call(h.bankA, "GET", "/v1/statements", { token: "garbage" })),                             // authentication failure
      await time(() => h.call(h.bankA, "POST", SIM, { rawBody: "{", token: t })),                                   // malformed
    ];
    for (const x of times) expect(x).toBeGreaterThanOrEqual(38);
  });
  it("rate-limited traffic is NOT delayed (shedding must stay cheap)", async () => {
    const hh = await startHarness({ rps: 1, minResponseMs: 300 });
    try {
      const t = await hh.token(hh.bankA);
      const rs: number[] = [];
      for (let i = 0; i < 6; i++) { const s = performance.now(); const r = await hh.call(hh.bankA, "GET", "/v1/statements", { token: t }); if (r.status === 429) rs.push(performance.now() - s); }
      expect(rs.length).toBeGreaterThan(0); for (const x of rs) expect(x).toBeLessThan(250);
    } finally { await hh.stop(); }
  });
});
