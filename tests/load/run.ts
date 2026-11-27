// Open-loop load test against a RUNNING sandbox (own sandbox only; synthetic numbers). All security controls stay on: mTLS, token
// verification, signed requests, replay store, consent, entitlement, quotas, abuse detection, circuit breakers, metering, audit, request log.
// Open loop = requests are issued on a schedule regardless of how fast earlier ones complete, and latency is measured from the SCHEDULED
// send time, so a slow platform cannot hide its queueing (no coordinated omission).
// Usage: npx tsx tests/load/run.ts <sandboxDir> <baseUrl> <rps> <seconds> <outFile>  (env: LOAD_SUBJECTS, DB_URL for server-side timings)
import { readFileSync, writeFileSync } from "node:fs";
import { createHash, randomBytes } from "node:crypto";
import { CompactSign, SignJWT, importJWK, type JWK } from "jose";
import { Agent, request } from "undici";
import pg from "pg";

const [dir = ".sandbox", target = "https://localhost:8443", rpsS = "200", secS = "60", outFile = "load-report.json"] = process.argv.slice(2);
const RPS = Number(rpsS), SECONDS = Number(secS), SUBJECTS = Number(process.env["LOAD_SUBJECTS"] ?? 6000);
const FAULT_PCT = Number(process.env["LOAD_FAULT_PCT"] ?? 0);      // % of requests aimed at numbers whose last digit makes the mock telco hang (2), fail (3) or send garbage (4)
const part = JSON.parse(readFileSync(`${dir}/participants.json`, "utf8")) as { caFile: string; participants: Array<{ clientId: string; kid: string; certFile: string; keyFile: string; privateJwk: string }> };
const ca = readFileSync(part.caFile, "utf8");
const b64 = (n: number) => randomBytes(n).toString("base64url");
interface P { id: string; kid: string; agent: Agent; key: CryptoKey | Uint8Array; token?: { t: string; at: number } }
const ps: P[] = [];
for (const p of part.participants) ps.push({ id: p.clientId, kid: p.kid, agent: new Agent({ connections: 64, pipelining: 1, connect: { ca, cert: readFileSync(p.certFile, "utf8"), key: readFileSync(p.keyFile, "utf8") } }), key: await importJWK(JSON.parse(p.privateJwk) as JWK, "ES256") });
async function tok(p: P): Promise<string> {
  if (p.token && Date.now() - p.token.at < 120_000) return p.token.t;
  const now = Math.floor(Date.now() / 1000);
  const a = await new SignJWT({}).setProtectedHeader({ alg: "ES256", kid: p.kid }).setIssuer(p.id).setSubject(p.id).setAudience(`${target}/oauth/token`).setIssuedAt(now).setExpirationTime(now + 30).setJti(b64(18)).sign(p.key as never);
  const r = await request(`${target}/oauth/token`, { method: "POST", dispatcher: p.agent, headers: { "content-type": "application/x-www-form-urlencoded" }, body: new URLSearchParams({ grant_type: "client_credentials", client_id: p.id, client_assertion_type: "urn:ietf:params:oauth:client-assertion-type:jwt-bearer", client_assertion: a }).toString() });
  const j = (await r.body.json()) as { access_token?: string }; if (!j.access_token) throw new Error(`token ${r.statusCode}`);
  p.token = { t: j.access_token, at: Date.now() }; return j.access_token;
}
async function post(p: P, path: string, body: unknown): Promise<{ status: number; json: Record<string, unknown> }> {
  const raw = JSON.stringify(body);
  const sig = await new CompactSign(new TextEncoder().encode(JSON.stringify({ htm: "POST", htu: path, dig: createHash("sha256").update(raw).digest("base64url"), iat: Math.floor(Date.now() / 1000), jti: b64(18) }))).setProtectedHeader({ alg: "ES256", kid: p.kid }).sign(p.key as never);
  const r = await request(`${target}${path}`, { method: "POST", dispatcher: p.agent, headers: { authorization: `Bearer ${await tok(p)}`, "content-type": "application/json", "x-request-signature": sig }, body: raw });
  const text = await r.body.text(); let json: Record<string, unknown> = {}; try { json = JSON.parse(text) as Record<string, unknown>; } catch { /* keep empty */ }
  return { status: r.statusCode, json };
}

// ---- subjects: synthetic numbers per telco, each with one consent covering all signals. Last digit 0/1 = normal negative/positive answer in the mocks. ----
const PREFIX = ["+6099900", "+6099901", "+6099902"] as const;
const SUPPORTED: Record<string, string[]> = { "+6099900": ["sim-swap", "device-swap", "call-forwarding", "kyc-match"], "+6099901": ["sim-swap", "call-forwarding"], "+6099902": ["sim-swap", "device-swap", "kyc-match"] };
const KYC = { name: "Synthetic Person", idDocument: "S0000000A", address: "1 Test Lane", email: "p@example.invalid", birthdate: "1990-01-01" };
interface Subj { n: string; ref: string; prefix: string }
const subjects: Subj[] = [];
console.error(`registering ${SUBJECTS} consents ...`);
const t0reg = Date.now();
for (let i = 0; i < SUBJECTS; i++) {
  const prefix = PREFIX[i % 3]!; const idx = Math.floor(i / 3);
  const n = `${prefix}${String(Math.floor(idx / 2) % 10000).padStart(4, "0")}${idx % 2}`;       // last digit 0 or 1; mid 0000-9999 -> up to 20000 numbers per telco, scattered below
  const s = { n, ref: `LOAD-${b64(9)}`, prefix };
  const p = ps[i % ps.length]!;
  const r = await post(p, "/v1/consents", { phoneNumber: n, consentRef: s.ref, purposeCode: "FRAUD_PREVENTION", signals: ["SIM_SWAP", "DEVICE_SWAP", "CALL_FORWARDING", "KYC_MATCH"], expiresAt: new Date(Date.now() + 36e5).toISOString() });
  if (r.status === 429) { i--; await new Promise((x) => setTimeout(x, 250)); continue; }
  if (r.status !== 201) throw new Error(`consent registration failed: ${r.status}`);
  subjects.push({ ...s, n });
}
console.error(`registered in ${Math.round((Date.now() - t0reg) / 1000)} s`);
// A consent belongs to the organisation that registered it, so remember the owner participant for each subject.
const owner = new Map<string, P>(); subjects.forEach((s, i) => owner.set(s.ref, ps[i % ps.length]!));
// Fault subjects: the mock telco misbehaves for these numbers (hang until the platform's timeout, HTTP 500, malformed JSON). Telco A only.
const faulty: Subj[] = [];
if (FAULT_PCT > 0) for (let i = 0; i < Math.ceil((RPS * SECONDS * FAULT_PCT) / 100); i++) {
  const n = `+6099900${String(5000 + Math.floor(i / 3)).padStart(4, "0")}${["2", "3", "4"][i % 3]}`, ref = `LOAD-${b64(9)}`, p = ps[i % ps.length]!;
  const r = await post(p, "/v1/consents", { phoneNumber: n, consentRef: ref, purposeCode: "FRAUD_PREVENTION", signals: ["SIM_SWAP"], expiresAt: new Date(Date.now() + 36e5).toISOString() });
  if (r.status === 429) { i--; await new Promise((x) => setTimeout(x, 250)); continue; }
  if (r.status !== 201) throw new Error(`fault consent registration failed: ${r.status}`);
  faulty.push({ n, ref, prefix: "+6099900" }); owner.set(ref, p);
}
// Shuffle so the traffic is not a sequential range scan (which the abuse detector is meant to catch).
for (let i = subjects.length - 1; i > 0; i--) { const j = Math.floor(Math.random() * (i + 1)); [subjects[i], subjects[j]] = [subjects[j]!, subjects[i]!]; }

// ---- open-loop run ----
interface Rec { lat: number; status: number; result: string; signal: string }
const recs: Rec[] = []; let inflight = 0, maxInflight = 0;
const total = RPS * SECONDS, start = performance.now() + 500; const runStartedAt = new Date().toISOString();
await Promise.all(ps.map(tok));
const sleepUntil = (t: number) => new Promise<void>((r) => { const d = t - performance.now(); if (d > 0) setTimeout(r, d); else setImmediate(r); });
const jobs: Promise<void>[] = [];
for (let i = 0; i < total; i++) {
  await sleepUntil(start + (i * 1000) / RPS);
  const sched = start + (i * 1000) / RPS;
  const useFault = faulty.length > 0 && Math.random() * 100 < FAULT_PCT;
  const s = useFault ? faulty[Math.floor(Math.random() * faulty.length)]! : subjects[i % subjects.length]!, sig = useFault ? "sim-swap" : SUPPORTED[s.prefix]![i % SUPPORTED[s.prefix]!.length]!;
  const p = owner.get(s.ref)!;
  const body: Record<string, unknown> = { phoneNumber: s.n, consentRef: s.ref, purposeCode: "FRAUD_PREVENTION", ...(sig === "kyc-match" ? KYC : {}), ...(sig === "sim-swap" || sig === "device-swap" ? { maxAge: 240 } : {}) };
  inflight++; maxInflight = Math.max(maxInflight, inflight);
  jobs.push(post(p, `/v1/signals/${sig}/check`, body).then((r) => { recs.push({ lat: performance.now() - sched, status: r.status, result: String(r.json["result"] ?? r.json["code"] ?? "?"), signal: sig }); }).catch(() => { recs.push({ lat: performance.now() - sched, status: 0, result: "CLIENT_ERROR", signal: sig }); }).finally(() => { inflight--; }));
}
await Promise.all(jobs);
const wall = (performance.now() - start) / 1000;
const pct = (a: number[], q: number) => { const s = [...a].sort((x, y) => x - y); return s.length ? Math.round(s[Math.min(s.length - 1, Math.ceil(q * s.length) - 1)]! * 10) / 10 : 0; };
const lat = recs.map((r) => r.lat);
const count = (f: (r: Rec) => string) => recs.reduce<Record<string, number>>((m, r) => { const k = f(r); m[k] = (m[k] ?? 0) + 1; return m; }, {});
const report: Record<string, unknown> = {
  generated_at: new Date().toISOString(), target, synthetic: true, offered_rps: RPS, seconds: SECONDS, sent: total, completed: recs.length, achieved_rps: Math.round((recs.length / wall) * 10) / 10, max_inflight: maxInflight,
  status: count((r) => String(r.status)), result: count((r) => r.result),
  client_latency_ms: { p50: pct(lat, 0.5), p95: pct(lat, 0.95), p99: pct(lat, 0.99), max: Math.round(Math.max(...lat)) },
  fault_pct: FAULT_PCT, success_rate: Math.round((recs.filter((r) => r.status === 200).length / recs.length) * 10000) / 100,
};
// ---- server-side timings (platform's own measurements): overhead = total - telco time, from the request log ----
if (process.env["DB_URL"]) {
  await new Promise((r) => setTimeout(r, 1500));          // request-log writes are asynchronous
  const c = new pg.Client({ connectionString: process.env["DB_URL"] }); await c.connect();
  const q = await c.query(`SELECT count(*)::int n,
      percentile_cont(0.5)  WITHIN GROUP (ORDER BY total_ms - telco_ms)::float p50, percentile_cont(0.95) WITHIN GROUP (ORDER BY total_ms - telco_ms)::float p95,
      percentile_cont(0.99) WITHIN GROUP (ORDER BY total_ms - telco_ms)::float p99, max(total_ms - telco_ms)::int max,
      percentile_cont(0.95) WITHIN GROUP (ORDER BY total_ms)::float total_p95, percentile_cont(0.95) WITHIN GROUP (ORDER BY telco_ms)::float telco_p95
    FROM request_log WHERE route LIKE '/v1/signals/%' AND ts >= $1::timestamptz AND http_status = 200`, [runStartedAt]);
  report["server_request_log_rows"] = q.rows[0].n; report["server_overhead_ms"] = { p50: q.rows[0].p50, p95: q.rows[0].p95, p99: q.rows[0].p99, max: q.rows[0].max, note: "total minus time waiting for the telco; request-log rows are written after the response" };
  report["server_total_p95_ms"] = q.rows[0].total_p95; report["server_telco_p95_ms"] = q.rows[0].telco_p95;
  const steps = await c.query(`SELECT s->>'s' step, percentile_cont(0.95) WITHIN GROUP (ORDER BY (s->>'ms')::float)::float p95 FROM request_log, jsonb_array_elements(steps) s WHERE route LIKE '/v1/signals/%' AND ts >= $1::timestamptz AND http_status = 200 GROUP BY 1 ORDER BY 2 DESC`, [runStartedAt]);
  report["server_step_p95_ms"] = Object.fromEntries(steps.rows.map((r) => [r.step, Math.round(r.p95 * 10) / 10]));
  const am = await c.query(`SELECT (SELECT count(*) FROM audit_log)::int audit_rows, (SELECT count(*) FROM usage_record)::int usage_rows`); report["audit_rows_total"] = am.rows[0].audit_rows; report["usage_rows_total"] = am.rows[0].usage_rows;
  await c.end();
}
writeFileSync(outFile, JSON.stringify(report, null, 1)); console.log(JSON.stringify(report, null, 1));
for (const p of ps) await p.agent.close();
