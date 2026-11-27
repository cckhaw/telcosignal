import { execFileSync } from "node:child_process";
import { mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { Writable } from "node:stream";
import { randomBytes, createPublicKey, X509Certificate } from "node:crypto";
import { CompactSign, SignJWT, exportJWK, generateKeyPair, type JWK } from "jose";
import { Agent, request } from "undici";
import pg from "pg";
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
import { certThumbprint } from "../../src/identity/tokens.js";
import { startMockTelcoA, type MockTelco } from "../../mock/telco-a.js";
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
  cfg: Config; app: FastifyInstance; port: number; pool: Pool; migrator: Pool; reporting: Pool; store: EphemeralStore; kms: LocalKms; audit: Audit;
  pki: TestPki; telco: MockTelco; logs: string[]; auditSink: string; kmsDir: string; urls: { migrator: string; app: string; reporting: string };
  orgA: string; orgB: string; orgC: string; bankA: TestClient; bankB: TestClient; bankC: TestClient; adminUrl: string; dbName: string;
  newClient(name: string, orgId: string, scopes: string[], o?: { pem?: Pem; registerCert?: string }): Promise<TestClient>;
  assertion(c: TestClient, o?: { aud?: string; exp?: number; iat?: number; jti?: string; alg?: string; iss?: string }): Promise<string>;
  token(c: TestClient, scope?: string): Promise<string>;
  call(c: TestClient, method: string, path: string, o?: ReqOpts): Promise<{ status: number; json: Json; headers: Record<string, unknown> }>;
  consent(c: TestClient, number: string, o?: { ref?: string; purpose?: string; signals?: string[]; expiresInMs?: number }): Promise<{ ref: string; id: string }>;
  stop(): Promise<void>;
}
export const num = (last: string, mid = "0001") => `+6099900${mid}${last}`;   // synthetic, reserved-looking range
const b64 = (n: number) => randomBytes(n).toString("base64url");

export async function startHarness(opts: { store?: EphemeralStore; telcoTimeoutMs?: number } = {}): Promise<Harness> {
  if (!ADMIN_URL) throw new Error("TS_TEST_ADMIN_URL must point to a Postgres superuser URL for the test run");
  const work = mkdtempSync(join(tmpdir(), "ts-h-"));
  const dbName = `ts_t_${randomBytes(5).toString("hex")}`;
  execFileSync("node", ["scripts/db-setup.mjs", ADMIN_URL, dbName, join(work, "db.env")], { stdio: "pipe" });
  const env = Object.fromEntries(readFileSync(join(work, "db.env"), "utf8").trim().split("\n").map((l) => [l.slice(0, l.indexOf("=")), l.slice(l.indexOf("=") + 1)]));
  const urls = { migrator: env["TS_MIGRATOR_URL"]!, app: env["TS_DATABASE_URL"]!, reporting: env["TS_REPORTING_URL"]! };
  await migrate(urls.migrator, "migrations");
  const pool = makePool(urls.app), migrator = makePool(urls.migrator), reporting = makePool(urls.reporting);

  const pki = new TestPki();
  const server = pki.issue("platform-server", { server: true });
  const platformOut = pki.issue("platform-out");
  const telcoSrv = pki.issue("telco-a-server", { server: true });
  const telco = await startMockTelcoA({ cert: telcoSrv.cert, key: telcoSrv.key, clientCa: pki.caCert });

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
    tls: { cert: server.cert, key: server.key, participantCa: pki.caCert },
    issuer: "https://platform.test", audience: "telco-signal-api", tokenEndpoint: "https://localhost:0/oauth/token",
    kmsDir, auditSinkPath: auditSink, telcoAllowList: [telcoOrigin], telcoTimeoutMs: opts.telcoTimeoutMs ?? 700, requestSkewSeconds: 60,
  };
  const adapters = new Map([["telco-a", new TelcoAAdapter("telco-a", telcoOrigin, cfg.telcoAllowList, { ca: pki.caCert, cert: platformOut.cert, key: platformOut.key }, cfg.telcoTimeoutMs)]]);
  const app = await buildParticipantServer({ cfg, pool, store, kms, audit, adapters, log });
  await app.listen({ port: 0, host: "127.0.0.1" });
  const port = (app.server.address() as { port: number }).port;
  cfg.tokenEndpoint = `https://localhost:${port}/oauth/token`;

  // ---- seed (as migrator; synthetic only) ----
  const org = async (name: string) => (await migrator.query("INSERT INTO organisations(name, kind, state) VALUES ($1,'bank','active') RETURNING id", [name])).rows[0].id as string;
  const [orgA, orgB, orgC] = [await org("Synthetic Bank A"), await org("Synthetic Bank B"), await org("Synthetic Bank C")];
  await migrator.query("INSERT INTO telcos(id, adapter, base_url) VALUES ('telco-a','camara',$1)", [telcoOrigin]);
  await migrator.query("INSERT INTO route_prefix(prefix, telco_id) VALUES ('+6099900','telco-a')");

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
  const ALL = ["sim-swap:check", "consent:write", "consent:read"];
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
    const r = await h.call(c, "POST", "/v1/consents", { body: { phoneNumber: number, consentRef: ref, purposeCode: o.purpose ?? "FRAUD_PREVENTION", signals: o.signals ?? ["SIM_SWAP"], expiresAt: new Date(Date.now() + (o.expiresInMs ?? 3_600_000)).toISOString() } });
    if (r.status !== 201) throw new Error(`consent create failed ${r.status}`);
    return { ref, id: r.json.id as string };
  };
  Object.assign(h, { cfg, app, port, pool, migrator, reporting, store, kms, audit, pki, telco, logs, auditSink, kmsDir, urls, orgA, orgB, orgC, bankA, bankB, bankC, adminUrl: ADMIN_URL, dbName });
  h.stop = async () => {
    await app.close(); await telco.close(); for (const a of agents) await a.close();
    for (const ad of adapters.values()) await ad.close();
    await pool.end(); await migrator.end(); await reporting.end(); await store.close();
    const adm = new pg.Client({ connectionString: ADMIN_URL }); await adm.connect(); await adm.query(`DROP DATABASE IF EXISTS "${dbName}" WITH (FORCE)`); await adm.end();
    rmSync(work, { recursive: true, force: true }); rmSync(pki.dir, { recursive: true, force: true });
    void createPublicKey;
  };
  return h;
}
