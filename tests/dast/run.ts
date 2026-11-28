// Black-box DAST against a RUNNING sandbox (real TLS, real mTLS, real DB/Redis). Own-sandbox only. Exit 1 on any failed check.
// Usage: npx tsx tests/dast/run.ts [.sandbox] [https://localhost:8443]
import { readFileSync, writeFileSync } from "node:fs";
import { createHash, randomBytes } from "node:crypto";
import { connect } from "node:tls";
import { CompactSign, SignJWT, importJWK, type JWK } from "jose";
import { Agent, request } from "undici";

const dir = process.argv[2] ?? ".sandbox";
const target = process.argv[3] ?? "https://localhost:8443";
const cfgPart = JSON.parse(readFileSync(`${dir}/participants.json`, "utf8")) as { caFile: string; participants: Array<{ clientId: string; kid: string; certFile: string; keyFile: string; privateJwk: string }> };
const ca = readFileSync(cfgPart.caFile, "utf8");
const tokenEndpoint = `${target}/oauth/token`;
const results: Array<{ category: string; check: string; ok: boolean; detail?: string }> = [];
const check = (category: string, name: string, ok: boolean, detail?: string) => { results.push({ category, check: name, ok, ...(detail ? { detail } : {}) }); if (!ok) console.error(`FAIL [${category}] ${name} ${detail ?? ""}`); };

interface P { id: string; kid: string; agent: Agent; key: CryptoKey | Uint8Array; cert: string; keyPem: string }
async function load(i: number): Promise<P> {
  const p = cfgPart.participants[i]!;
  const cert = readFileSync(p.certFile, "utf8"), keyPem = readFileSync(p.keyFile, "utf8");
  return { id: p.clientId, kid: p.kid, agent: new Agent({ connect: { ca, cert, key: keyPem } }), key: await importJWK(JSON.parse(p.privateJwk) as JWK, "ES256"), cert, keyPem };
}
const b64 = (n: number) => randomBytes(n).toString("base64url");
async function token(p: P, scope?: string): Promise<string> {
  const now = Math.floor(Date.now() / 1000);
  const a = await new SignJWT({}).setProtectedHeader({ alg: "ES256", kid: p.kid }).setIssuer(p.id).setSubject(p.id).setAudience(tokenEndpoint).setIssuedAt(now).setExpirationTime(now + 30).setJti(b64(18)).sign(p.key as never);
  const form = new URLSearchParams({ grant_type: "client_credentials", client_id: p.id, client_assertion_type: "urn:ietf:params:oauth:client-assertion-type:jwt-bearer", client_assertion: a, ...(scope ? { scope } : {}) });
  const r = await request(tokenEndpoint, { method: "POST", dispatcher: p.agent, headers: { "content-type": "application/x-www-form-urlencoded" }, body: form.toString() });
  const j = (await r.body.json()) as { access_token?: string };
  if (!j.access_token) throw new Error(`token request failed: ${r.statusCode}`);
  return j.access_token;
}
const cache = new Map<string, { t: string; at: number }>();
async function cachedToken(p: P): Promise<string> {
  const c = cache.get(p.id);
  if (c && Date.now() - c.at < 120_000) return c.t;
  const t = await token(p); cache.set(p.id, { t, at: Date.now() }); return t;
}
interface Resp { status: number; text: string; headers: Record<string, unknown> }
async function send(p: P, method: string, path: string, o: { token?: string | null; raw?: string; sign?: boolean; contentType?: string; headers?: Record<string, string> } = {}): Promise<Resp> {
  const raw = o.raw ?? "";
  const headers: Record<string, string> = { ...(o.headers ?? {}) };
  const t = o.token === undefined ? await cachedToken(p) : o.token;
  if (t) headers["authorization"] = `Bearer ${t}`;
  if (raw) headers["content-type"] = o.contentType ?? "application/json";
  if (o.sign !== false && method === "POST") {
    const payload = JSON.stringify({ htm: method, htu: path, dig: createHash("sha256").update(raw).digest("base64url"), iat: Math.floor(Date.now() / 1000), jti: b64(18) });
    headers["x-request-signature"] = await new CompactSign(new TextEncoder().encode(payload)).setProtectedHeader({ alg: "ES256", kid: p.kid }).sign(p.key as never);
  }
  try {
    const r = await request(`${target}${path}`, { method: method as "GET", dispatcher: p.agent, headers, body: raw || null });
    return { status: r.statusCode, text: await r.body.text(), headers: r.headers };
  } catch (e) { return { status: 0, text: String((e as Error).message), headers: {} }; }
}
const LEAK = /(at\s+[\w.<>]+\s+\(.*:\d+:\d+\)|node_modules|\.ts:\d+|postgres|ECONN|fastify|undici|stack|syntax error|SELECT |pg_)/i;
const safeBody = (r: Resp) => !LEAK.test(r.text);
const ROUTES = ["/v1/signals/sim-swap/check", "/v1/signals/device-swap/check", "/v1/signals/call-forwarding/check", "/v1/signals/kyc-match/check", "/v1/signals/number-recycling/check", "/v1/signals/kyc-tenure/check", "/v1/signals/device-location/check", "/v1/signals/device-roaming/check", "/v1/consents"];

const sleep = (ms: number) => new Promise((r) => setTimeout(r, ms));
// Attack fixture built at runtime (policy: no secret-shaped literals in the repo, so the secret scanner needs no allow-list).
const algNoneToken = `${Buffer.from(JSON.stringify({ alg: "none" })).toString("base64url")}.${Buffer.from("{}").toString("base64url")}.`;
const a = await load(0), b = await load(1);

// ---- API2 / ASVS: authentication ----
for (const r of ROUTES) {
  await sleep(30);
  const x = await send(a, "POST", r, { token: null, raw: "{}", sign: false });
  check("API2-broken-authn", `no token on ${r}`, x.status === 401 && safeBody(x), `status ${x.status}`);
  const y = await send(a, "POST", r, { token: algNoneToken, raw: "{}", sign: false });
  check("API2-broken-authn", `alg=none token on ${r}`, y.status === 401, `status ${y.status}`);
}
const noCert = new Agent({ connect: { ca } });
let tlsRefused = false; try { await request(`${target}/.well-known/jwks.json`, { dispatcher: noCert }); } catch { tlsRefused = true; }
check("API2-broken-authn", "connection without client certificate refused (mTLS)", tlsRefused);

// ---- transport ----
const refusedOld = await new Promise<boolean>((res) => { const s = connect({ host: "localhost", port: Number(new URL(target).port), ca, cert: a.cert, key: a.keyPem, maxVersion: "TLSv1.1", minVersion: "TLSv1" }, () => { s.end(); res(false); }); s.on("error", () => res(true)); });
check("TLS", "TLS 1.1 and below refused", refusedOld);
const weak = await new Promise<boolean>((res) => { const s = connect({ host: "localhost", port: Number(new URL(target).port), ca, cert: a.cert, key: a.keyPem, maxVersion: "TLSv1.2", ciphers: "AES128-SHA:DES-CBC3-SHA:RC4-SHA" }, () => { s.end(); res(false); }); s.on("error", () => res(true)); });
check("TLS", "weak/non-AEAD TLS 1.2 cipher suites refused", weak);

// ---- headers / info disclosure ----
const hh = await send(a, "GET", "/.well-known/jwks.json", { token: null });
check("API8-misconfig", "security headers present", hh.headers["cache-control"] === "no-store" && hh.headers["x-content-type-options"] === "nosniff" && String(hh.headers["strict-transport-security"] ?? "").includes("max-age"));
check("API8-misconfig", "no server/x-powered-by banner", !hh.headers["server"] && !hh.headers["x-powered-by"]);
check("API8-misconfig", "JWKS exposes public keys only", !/"d"\s*:/.test(hh.text));
for (const m of ["GET", "PUT", "DELETE", "PATCH", "TRACE", "OPTIONS"]) {
  const x = await send(a, m, "/v1/signals/sim-swap/check", {});
  check("API8-misconfig", `${m} on a POST-only route is not a 5xx and leaks nothing`, x.status > 0 && x.status < 500 && safeBody(x), `status ${x.status}`);
}
for (const path of ["/v1/consents/../../etc/passwd", "/%2e%2e/%2e%2e/etc/passwd", "/v1/consents/" + "a".repeat(5000), "/v1/consents/%00", "/admin", "/metrics", "/.env", "/debug/pprof", "/v1/../oauth/token"]) {
  const x = await send(a, "GET", path, {});
  check("API8-misconfig", `odd path ${path.slice(0, 30)}`, x.status >= 400 && x.status < 500 && safeBody(x), `status ${x.status}`);
}

// ---- API3/API6: injection & input handling fuzz (valid auth, valid signature) ----
const PAY = ["' OR '1'='1", "'; DROP TABLE consents;--", "\" OR 1=1 --", "${7*7}", "{{7*7}}", "<script>alert(1)</script>", "../../etc/passwd", "\u0000", "%00", "A".repeat(3000), "\r\nX-Injected: 1", "$(id)", "`id`", "{\"$ne\":null}", "__proto__", "constructor"];
const bodies: string[] = [];
for (const s of PAY) {
  bodies.push(JSON.stringify({ phoneNumber: s, consentRef: "CONSENT-0001", purposeCode: "FRAUD_PREVENTION" }));
  bodies.push(JSON.stringify({ phoneNumber: "+609990000010", consentRef: s, purposeCode: "FRAUD_PREVENTION" }));
  bodies.push(JSON.stringify({ phoneNumber: "+609990000010", consentRef: "CONSENT-0001", purposeCode: s, name: s }));
}
// maxAge below is raw JSON text: a 1e309 literal in JS would become null
bodies.push("[]", "null", "123", '"str"', "{", '{"a":' + "[".repeat(5000),
  '{"phoneNumber":"+609990000010","phoneNumber":"+609990000011","consentRef":"CONSENT-0001","purposeCode":"FRAUD_PREVENTION"}',
  '{"phoneNumber":"+609990000010","consentRef":"CONSENT-0001","purposeCode":"FRAUD_PREVENTION","maxAge":1e309}',
  '{"__proto__":{"admin":true}}', '{"constructor":{"prototype":{"x":1}}}');
const tok = await token(a);
let bad5xx = 0, leaks = 0, echoes = 0, n = 0;
for (const r of ROUTES.slice(0, 4)) for (const raw of bodies) {
  const x = await send(a, "POST", r, { token: tok, raw }); n++; await sleep(25);   // stay under the per-certificate rate limit
  if (x.status === 0 || x.status >= 500) bad5xx++;
  if (!safeBody(x)) leaks++;
  if (raw.includes("<script>") && x.text.includes("<script>")) echoes++;
}
check("API10-unsafe-input", `fuzz corpus (${n} requests): no 5xx / dropped connections`, bad5xx === 0, `${bad5xx} bad`);
check("API10-unsafe-input", "fuzz corpus: no stack/SQL/internal detail in any response", leaks === 0, `${leaks} leaks`);
check("API10-unsafe-input", "fuzz corpus: payloads never reflected", echoes === 0);
const big = await send(a, "POST", ROUTES[0]!, { token: tok, raw: JSON.stringify({ pad: "x".repeat(20000) }) });
check("API4-resource-consumption", "oversized body rejected with 413", big.status === 413, `status ${big.status}`);
const ct = await send(a, "POST", ROUTES[0]!, { token: tok, raw: "<xml/>", contentType: "application/xml" });
check("API8-misconfig", "unsupported content type rejected (4xx)", ct.status >= 400 && ct.status < 500, `status ${ct.status}`);
const crlf = await send(a, "POST", ROUTES[0]!, { token: tok, raw: "{}", headers: { "x-correlator": "a\r\nSet-Cookie: x=1" } }).catch(() => ({ status: 0 }));
check("API8-misconfig", "CRLF in header cannot inject a response header", crlf.status === 0 || crlf.status >= 400);

await sleep(1300);
// ---- API1/API5: object & function level authorisation (two participants) ----
const num = "+609990000030";
const cons = await send(a, "POST", "/v1/consents", { raw: JSON.stringify({ phoneNumber: num, consentRef: "DAST-" + b64(6), purposeCode: "FRAUD_PREVENTION", signals: ["SIM_SWAP"], expiresAt: new Date(Date.now() + 3600e3).toISOString() }) });
const cid = (JSON.parse(cons.text) as { id?: string }).id ?? "";
check("API1-BOLA", "participant A can create a consent", cons.status === 201 && !!cid, `status ${cons.status}`);
const own = await send(a, "GET", `/v1/consents/${cid}`, {});
const foreign = await send(b, "GET", `/v1/consents/${cid}`, {});
const missing = await send(b, "GET", "/v1/consents/00000000-0000-4000-8000-000000000000", {});
check("API1-BOLA", "owner can read own consent", own.status === 200);
check("API1-BOLA", "participant B cannot read A's consent (same response as nonexistent)", foreign.status === 404 && missing.status === 404 && JSON.stringify({ ...JSON.parse(foreign.text), correlationId: 0 }) === JSON.stringify({ ...JSON.parse(missing.text), correlationId: 0 }));
const rev = await send(b, "POST", `/v1/consents/${cid}/revoke`, {});
check("API1-BOLA", "participant B cannot revoke A's consent", rev.status === 404, `status ${rev.status}`);
const wrongScope = await send(a, "POST", "/v1/consents", { token: await token(a, "consent:read"), raw: "{}" });
check("API5-BFLA", "token without write scope cannot create consents", wrongScope.status === 403, `status ${wrongScope.status}`);
for (const p of ["/admin", "/admin/config", "/v1/admin/clients", "/internal/health"]) { const x = await send(a, "GET", p, {}); check("API5-BFLA", `no admin/internal route exposed on participant interface: ${p}`, x.status === 404); }

// ---- replay ----
const sigBody = JSON.stringify({ phoneNumber: num, consentRef: "DAST-NOPE-01", purposeCode: "FRAUD_PREVENTION" });
const jti = b64(18);
const payload = JSON.stringify({ htm: "POST", htu: ROUTES[0], dig: createHash("sha256").update(sigBody).digest("base64url"), iat: Math.floor(Date.now() / 1000), jti });
const jws = await new CompactSign(new TextEncoder().encode(payload)).setProtectedHeader({ alg: "ES256", kid: a.kid }).sign(a.key as never);
const go = async () => (await request(`${target}${ROUTES[0]}`, { method: "POST", dispatcher: a.agent, headers: { authorization: `Bearer ${tok}`, "content-type": "application/json", "x-request-signature": jws }, body: sigBody }).then(async (r) => { await r.body.dump(); return r.statusCode; }));
const first = await go(), second = await go();
check("replay", "identical signed request is rejected the second time", first !== 401 && second === 401, `${first} then ${second}`);

await sleep(1300);
// ---- API4: rate limiting ----
const burst = await Promise.all(Array.from({ length: 150 }, () => send(a, "GET", "/v1/consents/00000000-0000-4000-8000-000000000000", { token: tok })));
check("API4-resource-consumption", "burst of 150 requests triggers 429 (rate limiting active)", burst.some((x) => x.status === 429), `statuses: ${[...new Set(burst.map((x) => x.status))].join(",")}`);
const limited = burst.find((x) => x.status === 429);
check("API4-resource-consumption", "429 body is generic", !limited || (safeBody(limited) && Object.keys(JSON.parse(limited.text)).sort().join() === "code,correlationId,message,status"));

await sleep(1300);
// ---- M3: quotas, enumeration handling, statements ----
const repeatNum = "+609990000077";
const repeatCons = await send(a, "POST", "/v1/consents", { raw: JSON.stringify({ phoneNumber: repeatNum, consentRef: "DAST-REP-" + b64(6), purposeCode: "FRAUD_PREVENTION", signals: ["SIM_SWAP"], expiresAt: new Date(Date.now() + 3600e3).toISOString() }) });
const repRef = (JSON.parse(repeatCons.text) as { consentRef?: string }).consentRef ?? "";
const repeatCodes: number[] = [];
for (let i = 0; i < 30; i++) { repeatCodes.push((await send(a, "POST", ROUTES[0]!, { token: tok, raw: JSON.stringify({ phoneNumber: repeatNum, consentRef: repRef, purposeCode: "FRAUD_PREVENTION" }) })).status); await sleep(20); }
check("API4-resource-consumption", "repeated lookups of one subject are limited (429 appears, no 5xx)", repeatCodes.includes(429) && repeatCodes.every((c) => c < 500), repeatCodes.join(","));
await sleep(1300);
const sweep = new Set<string>();
for (let i = 0; i < 25; i++) { const x = await send(b, "POST", ROUTES[0]!, { raw: JSON.stringify({ phoneNumber: `+6099900990${String(i).padStart(2, "0")}`, consentRef: "DAST-PROBE-0001", purposeCode: "FRAUD_PREVENTION" }) }); sweep.add(`${x.status}:${(JSON.parse(x.text) as { code?: string }).code}`); await sleep(25); }
check("API9-enumeration", "sequential range probing without consent: uniform generic answers (no existence oracle), no 5xx", sweep.size === 1 && [...sweep][0] === "403:CONSENT_REQUIRED", [...sweep].join(","));
await sleep(1300);
const stl = await send(a, "GET", "/v1/statements", {});
check("API1-BOLA", "statements list is scoped to the caller", stl.status === 200 && Array.isArray((JSON.parse(stl.text) as { statements?: unknown[] }).statements));
const stx = await send(b, "GET", "/v1/statements/00000000-0000-4000-8000-000000000000", {});
check("API1-BOLA", "unknown/foreign statement id is a generic 404", stx.status === 404 && safeBody(stx));

const failed = results.filter((r) => !r.ok);
writeFileSync(process.env["DAST_REPORT"] ?? "dast-report.json", JSON.stringify({ target, finished: new Date().toISOString(), total: results.length, failed: failed.length, results }, null, 1));
console.log(`DAST: ${results.length - failed.length}/${results.length} checks passed`);
process.exit(failed.length ? 1 : 0);
