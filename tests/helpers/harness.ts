import { execFileSync } from "node:child_process";
import { mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { Writable } from "node:stream";
import { randomBytes, createPublicKey, X509Certificate } from "node:crypto";
import { CompactSign, SignJWT, exportJWK, generateKeyPair, type JWK } from "jose";
import { Agent, request } from "undici";
import pg from "pg";
import type { Redis } from "ioredis";
import type { FastifyInstance } from "fastify";
import { migrate } from "../../src/db/migrate.js";
import { makePool, type Pool } from "../../src/db/pool.js";
import { RedisStore, type EphemeralStore } from "../../src/common/store.js";
import { LocalKms } from "../../src/kms/local.js";
import { Audit } from "../../src/audit/audit.js";
import { makeLogger } from "../../src/common/log.js";
import type { Config } from "../../src/common/config.js";
import { buildParticipantServer } from "../../src/participant-api/server.js";
import { TelcoAAdapter } from "../../src/adapters/telcoA.js";
import type { TelcoAdapter as TelcoAdapterT } from "../../src/adapters/types.js";
import { certThumbprint } from "../../src/identity/tokens.js";
import { startMockTelcoA, type MockTelco } from "../../mock/telco-a.js";
import { startMockTelcoB } from "../../mock/telco-b.js";
import { startMockAggregator } from "../../mock/aggregator.js";
import { TelcoBAdapter } from "../../src/adapters/telcoB.js";
import { AdapterRegistry } from "../../src/adapters/registry.js";
import { Limiter, DEFAULT_LIMITS as DEFAULT_LIMITS_T, type LimitConfig } from "../../src/ratelimit/limits.js";
import { AbuseDetector, DEFAULT_ABUSE as DEFAULT_ABUSE_T, type AbuseConfig } from "../../src/abuse/enumeration.js";
import { ResilientAdapter, type ResilienceConfig, DEFAULT_RESILIENCE } from "../../src/resilience/breaker.js";
import { TelcoCAdapter } from "../../src/adapters/telcoC.js";
import { TestPki, type Pem } from "./pki.js";

const ADMIN_URL = process.env["TS_TEST_ADMIN_URL"] ?? "";
process.env["TS_ROLE_PW_SEED"] ??= randomBytes(24).toString("hex");
const REDIS_URL = process.env["TS_TEST_REDIS_URL"] ?? "redis://127.0.0.1:6379/15";

// Test-only loose JSON shape for response assertions.
// eslint-disable-next-line @typescript-eslint/no-explicit-any
export type Json = any;
export interface TestClient { name: string; orgId: string; pem: Pem; key: CryptoKey | Awaited<ReturnType<typeof generateKeyPair>>["privateKey"]; kid: string; thumb: string; agent: Agent }
export interface ReqOpts { body?: unknown; rawBody?: string; token?: string | null; sign?: boolean; signAs?: TestClient; iat?: number; jti?: string; headers?: Record<string, string>; agentOf?: TestClient; contentType?: string; tamperAfterSign?: string }
export interface Harness {
  cfg: Config; app: FastifyInstance & { drainLogs(): Promise<void>; routeTable: Array<{ method: string; url: string }> }; port: number; pool: Pool; migrator: Pool; reporting: Pool; billing: Pool; worker: Pool; store: EphemeralStore; kms: LocalKms; audit: Audit;
  pki: TestPki; registry: AdapterRegistry; platformOut: Pem; breakers: Map<string, ResilientAdapter>; telco: MockTelco; telcoB: MockTelco; aggregator: MockTelco; logs: string[]; auditSink: string; kmsDir: string; urls: { migrator: string; app: string; reporting: string; billing: string; admin: string; worker: string };
  orgA: string; orgB: string; orgC: string; bankA: TestClient; bankB: TestClient; bankC: TestClient; adminUrl: string; dbName: string;
  newClient(name: string, orgId: string, scopes: string[], o?: { pem?: Pem; registerCert?: string }): Promise<TestClient>;
  assertion(c: TestClient, o?: { aud?: string; exp?: number; iat?: number; jti?: string; alg?: string; iss?: string }): Promise<string>;
  token(c: TestClient, scope?: string): Promise<string>;
  call(c: TestClient, method: string, path: string, o?: ReqOpts): Promise<{ status: number; json: Json; headers: Record<string, unknown> }>;
  consent(c: TestClient, number: string, o?: { ref?: string; purpose?: string; signals?: string[]; expiresInMs?: number }): Promise<{ ref: string; id: string }>;
  stop(): Promise<void>;
}
export const num = (last: string, mid = "0001") => `+6099900${mid}${last}`;    // synthetic: Telco A range
export const numB = (last: string, mid = "0001") => `+6099901${mid}${last}`;   // Telco B range
export const numC = (last: string, mid = "0001") => `+6099902${mid}${last}`;   // Telco C range (via aggregator)
const b64 = (n: number) => randomBytes(n).toString("base64url");

export async function startHarness(opts: { store?: EphemeralStore; telcoTimeoutMs?: number; rps?: number; tokenRps?: number; rateLimitRedis?: Redis; limits?: Partial<LimitConfig>; abuse?: Partial<AbuseConfig>; resilience?: Partial<ResilienceConfig>; useRegistry?: boolean } = {}): Promise<Harness> {
  if (!ADMIN_URL) throw new Error("TS_TEST_ADMIN_URL must point to a Postgres superuser URL for the test run");
  const work = mkdtempSync(join(tmpdir(), "ts-h-"));
  const dbName = `ts_t_${randomBytes(5).toString("hex")}`;
  execFileSync("node", ["scripts/db-setup.mjs", ADMIN_URL, dbName, join(work, "db.env")], { stdio: "pipe" });
  const env = Object.fromEntries(readFileSync(join(work, "db.env"), "utf8").trim().split("\n").map((l) => [l.slice(0, l.indexOf("=")), l.slice(l.indexOf("=") + 1)]));
  const urls = { migrator: env["TS_MIGRATOR_URL"]!, app: env["TS_DATABASE_URL"]!, reporting: env["TS_REPORTING_URL"]!, billing: env["TS_BILLING_URL"]!, admin: env["TS_ADMIN_DB_URL"]!, worker: env["TS_WORKER_URL"]! };
  await migrate(urls.migrator, "migrations");
  const pool = makePool(urls.app), migrator = makePool(urls.migrator), reporting = makePool(urls.reporting), billing = makePool(urls.billing), worker = makePool(urls.worker);

  const pki = new TestPki();
  const server = pki.issue("platform-server", { server: true });
  const platformOut = pki.issue("platform-out");
  const telcoSrv = pki.issue("telco-a-server", { server: true });
  const telco = await startMockTelcoA({ cert: telcoSrv.cert, key: telcoSrv.key, clientCa: pki.caCert });
  const telcoB = await startMockTelcoB({ cert: telcoSrv.cert, key: telcoSrv.key, clientCa: pki.caCert });
  const aggregator = await startMockAggregator({ cert: telcoSrv.cert, key: telcoSrv.key, clientCa: pki.caCert });

  const kmsDir = join(work, "kms"), auditSink = join(work, "audit.jsonl");
  writeFileSync(auditSink, "", { mode: 0o600 });
  const kms = new LocalKms(kmsDir);
  const store = opts.store ?? new RedisStore(REDIS_URL);
  if (!opts.store) { const { Redis } = await import("ioredis"); const r = new Redis(REDIS_URL); await r.flushdb(); r.disconnect(); }
  const audit = new Audit(pool, auditSink);
  const logs: string[] = [];
  const sink = new Writable({ write(c, _e, cb) { logs.push(String(c)); cb(); } });
  const log = makeLogger("debug", sink);

  const telcoOrigin = `https://localhost:${telco.port}`;
  const cfg: Config = {
    databaseUrl: urls.app, redisUrl: REDIS_URL, participantPort: 0,
    tls: { cert: server.cert, key: server.key, participantCa: pki.caCert }, telcoMtls: { ca: pki.caCert, cert: platformOut.cert, key: platformOut.key },
    issuer: "https://platform.test", audience: "telco-signal-api", tokenEndpoint: "https://localhost:0/oauth/token",
    kmsDir, auditSinkPath: auditSink, telcoAllowList: [telcoOrigin, `https://localhost:${telcoB.port}`, `https://localhost:${aggregator.port}`], telcoTimeoutMs: opts.telcoTimeoutMs ?? 700, requestSkewSeconds: 60,
    rateLimitPerSecond: opts.rps ?? 5000, tokenRateLimitPerSecond: opts.tokenRps ?? 5000,   // high by default so functional tests are not throttled
    limits: DEFAULT_LIMITS_T, abuse: DEFAULT_ABUSE_T, resilience: DEFAULT_RESILIENCE,   // replaced just below with test values
  };
  const mtls = { ca: pki.caCert, cert: platformOut.cert, key: platformOut.key };
  const bOrigin = `https://localhost:${telcoB.port}`, cOrigin = `https://localhost:${aggregator.port}`;
  const adapters = new Map<string, TelcoAdapterT>([
    ["telco-a", new TelcoAAdapter("telco-a", telcoOrigin, cfg.telcoAllowList, mtls, cfg.telcoTimeoutMs)],
    ["telco-b", new TelcoBAdapter("telco-b", bOrigin, cfg.telcoAllowList, mtls, cfg.telcoTimeoutMs)],
    ["telco-c", new TelcoCAdapter("telco-c", "telco-c", cOrigin, cfg.telcoAllowList, mtls, cfg.telcoTimeoutMs)],
  ]);
  const rlRedis = opts.rateLimitRedis ?? (store instanceof RedisStore ? store.redis : undefined);
  // Functional tests run with effectively-unlimited quotas / no breaker unless a test opts in, so they exercise one control at a time.
  const HUGE = 1_000_000;
  cfg.limits = { perParticipantSignalPerMinute: HUGE, perTelcoPerSecond: HUGE, perSubjectPerHour: HUGE, ...opts.limits };
  cfg.abuse = { windowSeconds: 600, distinctSubjects: HUGE, sameRangeSubjects: HUGE, consentFailures: HUGE, autoSuspend: false, ...opts.abuse };
  cfg.resilience = { ...DEFAULT_RESILIENCE, minRequests: HUGE, ...opts.resilience };
  const limiter = new Limiter(store, pool, cfg.limits);
  const abuse = new AbuseDetector(store, pool, kms, audit, log, cfg.abuse);
  const breakers = new Map<string, ResilientAdapter>([...adapters].map(([id, a]) => [id, new ResilientAdapter(a, cfg.resilience)]));
  const registry = new AdapterRegistry(pool, { mtls, timeoutMs: cfg.telcoTimeoutMs, resilience: cfg.resilience, envAllowList: cfg.telcoAllowList, ttlMs: 50, allowLoopback: true });
  const app = await buildParticipantServer({ cfg, pool, store, kms, audit, adapters: opts.useRegistry ? registry : breakers, log, limiter, abuse, ...(rlRedis ? { rateLimitRedis: rlRedis } : {}) });
  await app.listen({ port: 0, host: "127.0.0.1" });
  const port = (app.server.address() as { port: number }).port;
  cfg.tokenEndpoint = `https://localhost:${port}/oauth/token`;

  // ---- seed (as migrator; synthetic only) ----
  const org = async (name: string) => (await migrator.query("INSERT INTO organisations(name, kind, state) VALUES ($1,'bank','active') RETURNING id", [name])).rows[0].id as string;
  const [orgA, orgB, orgC] = [await org("Synthetic Bank A"), await org("Synthetic Bank B"), await org("Synthetic Bank C")];
  await migrator.query("INSERT INTO telcos(id, adapter, base_url) VALUES ('telco-a','camara',$1), ('telco-b','proprietary',$2), ('telco-c','aggregator',$3)", [telcoOrigin, bOrigin, cOrigin]);
  await migrator.query("INSERT INTO route_prefix(prefix, telco_id) VALUES ('+6099900','telco-a'), ('+6099901','telco-b'), ('+6099902','telco-c')");
  await migrator.query(`INSERT INTO telco_signal_coverage(telco_id, signal) VALUES
    ('telco-a','SIM_SWAP'),('telco-a','DEVICE_SWAP'),('telco-a','CALL_FORWARDING'),('telco-a','KYC_MATCH'),
    ('telco-b','SIM_SWAP'),('telco-b','CALL_FORWARDING'),
    ('telco-c','SIM_SWAP'),('telco-c','DEVICE_SWAP'),('telco-c','KYC_MATCH')`);

  await migrator.query("INSERT INTO org_entitlement(org_id, signal, purposes) SELECT o, s.id, '{FRAUD_PREVENTION,ACCOUNT_TAKEOVER_CHECK,TRANSACTION_RISK}' FROM unnest($1::uuid[]) o CROSS JOIN signals s", [[orgA, orgB, orgC]]);
  const h = {} as Harness;
  const agents: Agent[] = [];
  h.newClient = async (name, orgId, scopes, o = {}) => {
    const pem = o.pem ?? pki.issue(name);
    const { publicKey, privateKey } = await generateKeyPair("ES256", { extractable: true });
    const kid = `${name}-k1`;
    const jwk = { ...(await exportJWK(publicKey)), kid, alg: "ES256", use: "sig" } as JWK;
    const thumb = certThumbprint(new X509Certificate(pem.cert).raw);
    await migrator.query("INSERT INTO clients(client_id, org_id, scopes) VALUES ($1,$2,$3)", [name, orgId, scopes]);
    await migrator.query("INSERT INTO client_keys(client_id, kid, jwk, cert_sha256, expires_at) VALUES ($1,$2,$3,$4, now() + interval '1 day')", [name, kid, JSON.stringify(jwk), o.registerCert ?? thumb]);
    const agent = new Agent({ connect: { ca: pki.caCert, cert: pem.cert, key: pem.key, rejectUnauthorized: true } });
    agents.push(agent);
    return { name, orgId, pem, key: privateKey, kid, thumb, agent };
  };
  const ALL = ["sim-swap:check", "device-swap:check", "call-forwarding:check", "kyc-match:check", "consent:write", "consent:read", "statements:read"];
  const bankA = await h.newClient("bank-a", orgA, ALL), bankB = await h.newClient("bank-b", orgB, ALL), bankC = await h.newClient("bank-c", orgC, ["consent:read"]);

  h.assertion = (c, o = {}) => {
    const now = Math.floor(Date.now() / 1000);
    const iat = o.iat ?? now;
    return new SignJWT({}).setProtectedHeader({ alg: (o.alg ?? "ES256") as "ES256", kid: c.kid }).setIssuer(o.iss ?? c.name).setSubject(c.name)
      .setAudience(o.aud ?? cfg.tokenEndpoint).setIssuedAt(iat).setExpirationTime(o.exp ?? iat + 30).setJti(o.jti ?? b64(18)).sign(c.key as never);
  };
  h.token = async (c, scope) => {
    const form = new URLSearchParams({ grant_type: "client_credentials", client_id: c.name, client_assertion_type: "urn:ietf:params:oauth:client-assertion-type:jwt-bearer", client_assertion: await h.assertion(c) });
    if (scope) form.set("scope", scope);
    const r = await request(cfg.tokenEndpoint, { method: "POST", dispatcher: c.agent, headers: { "content-type": "application/x-www-form-urlencoded" }, body: form.toString() });
    const j = (await r.body.json()) as { access_token?: string };
    if (r.statusCode !== 200 || !j.access_token) throw new Error(`token failed ${r.statusCode}`);
    return j.access_token;
  };
  h.call = async (c, method, path, o = {}) => {
    const raw = o.rawBody ?? (o.body === undefined ? "" : JSON.stringify(o.body));
    const token = o.token === null ? undefined : (o.token ?? (await h.token(c)));
    const headers: Record<string, string> = { ...(o.headers ?? {}) };
    if (token) headers["authorization"] = `Bearer ${token}`;
    if (raw) headers["content-type"] = o.contentType ?? "application/json";
    if (o.sign !== false && method === "POST") {
      const s = o.signAs ?? c;
      const { createHash } = await import("node:crypto");
      const payload = JSON.stringify({ htm: method, htu: path, dig: createHash("sha256").update(raw).digest("base64url"), iat: o.iat ?? Math.floor(Date.now() / 1000), jti: o.jti ?? b64(18) });
      headers["x-request-signature"] = await new CompactSign(new TextEncoder().encode(payload)).setProtectedHeader({ alg: "ES256", kid: s.kid }).sign(s.key as never);
    }
    const dispatcher = (o.agentOf ?? c).agent;
    const r = await request(`https://localhost:${port}${path}`, { method: method as "POST", dispatcher, headers, body: (o.tamperAfterSign ?? raw) || null });
    const text = await r.body.text();
    let json: unknown = null; try { json = JSON.parse(text); } catch { /* not json */ }
    return { status: r.statusCode, json: json as Json, headers: r.headers };
  };
  h.consent = async (c, number, o = {}) => {
    const ref = o.ref ?? `CONSENT-${b64(8)}`;
    const r = await h.call(c, "POST", "/v1/consents", { body: { phoneNumber: number, consentRef: ref, purposeCode: o.purpose ?? "FRAUD_PREVENTION", signals: o.signals ?? ["SIM_SWAP", "DEVICE_SWAP", "CALL_FORWARDING", "KYC_MATCH"], expiresAt: new Date(Date.now() + (o.expiresInMs ?? 3_600_000)).toISOString() } });
    if (r.status !== 201) throw new Error(`consent create failed ${r.status}`);
    return { ref, id: r.json.id as string };
  };
  Object.assign(h, { registry, platformOut, breakers, cfg, app, port, pool, migrator, reporting, billing, worker, store, kms, audit, pki, telco, telcoB, aggregator, logs, auditSink, kmsDir, urls, orgA, orgB, orgC, bankA, bankB, bankC, adminUrl: ADMIN_URL, dbName });
  h.stop = async () => {
    await app.close(); await telco.close(); await telcoB.close(); await aggregator.close(); for (const a of agents) await a.close();
    for (const ad of breakers.values()) await ad.close(); await registry.close();
    await pool.end(); await migrator.end(); await reporting.end(); await billing.end(); await worker.end(); await store.close();
    const adm = new pg.Client({ connectionString: ADMIN_URL }); await adm.connect(); await adm.query(`DROP DATABASE IF EXISTS "${dbName}" WITH (FORCE)`); await adm.end();
    rmSync(work, { recursive: true, force: true }); rmSync(pki.dir, { recursive: true, force: true });
    void createPublicKey;
  };
  return h;
}
