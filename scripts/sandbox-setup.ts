// Generates a LOCAL SANDBOX (synthetic data only): database, roles, certificates, keys, KMS dir, config env file.
// Everything secret is generated here at setup time into <outdir> (gitignored). Nothing is committed or baked into images.
// Usage: TS_ADMIN_URL=postgres://postgres:...@127.0.0.1:5432/postgres npx tsx scripts/sandbox-setup.ts .sandbox
import { execFileSync } from "node:child_process";
import { chmodSync, mkdirSync, readFileSync, writeFileSync } from "node:fs";
import { join, resolve } from "node:path";
import { X509Certificate, randomBytes } from "node:crypto";
import { exportJWK, generateKeyPair } from "jose";
import pg from "pg";
import { TestPki } from "../tests/helpers/pki.js";
import { migrate } from "../src/db/migrate.js";

const out = resolve(process.argv[2] ?? ".sandbox");
const adminUrl = process.env["TS_ADMIN_URL"];
if (!adminUrl) throw new Error("TS_ADMIN_URL required (Postgres superuser URL for creating roles/database)");
const redisUrl = process.env["TS_REDIS_URL"] ?? "redis://127.0.0.1:6379/0";
const port = Number(process.env["TS_PARTICIPANT_PORT"] ?? 8443);
mkdirSync(join(out, "pki"), { recursive: true, mode: 0o700 }); mkdirSync(join(out, "kms"), { recursive: true, mode: 0o700 });
chmodSync(out, 0o700);
const w = (rel: string, data: string) => { writeFileSync(join(out, rel), data, { mode: 0o600 }); return join(out, rel); };

// ---- database + roles (passwords generated now) ----
execFileSync("node", ["scripts/db-setup.mjs", adminUrl, "ts_sandbox", join(out, "db.env")], { stdio: "pipe" });
const dbEnv = Object.fromEntries(readFileSync(join(out, "db.env"), "utf8").trim().split("\n").map((l) => [l.slice(0, l.indexOf("=")), l.slice(l.indexOf("=") + 1)])) as Record<string, string>;
await migrate(dbEnv["TS_MIGRATOR_URL"]!, "migrations");

// ---- PKI ----
const pki = new TestPki(30);
const ca = w("pki/ca.crt", pki.caCert);
const srv = pki.issue("platform-server", { server: true }), telcoSrv = pki.issue("telco-server", { server: true }), platformOut = pki.issue("platform-out");
const files = { srvCert: w("pki/server.crt", srv.cert), srvKey: w("pki/server.key", srv.key), telcoCert: w("pki/telco.crt", telcoSrv.cert), telcoKey: w("pki/telco.key", telcoSrv.key), outCert: w("pki/platform-out.crt", platformOut.cert), outKey: w("pki/platform-out.key", platformOut.key) };

// ---- synthetic data ----
const m = new pg.Client({ connectionString: dbEnv["TS_MIGRATOR_URL"] }); await m.connect();
const ports = { a: 9101, b: 9102, c: 9103 };
const o = (n: string) => `https://localhost:${n}`;
await m.query("INSERT INTO telcos(id, adapter, base_url) VALUES ('telco-a','camara',$1),('telco-b','proprietary',$2),('telco-c','aggregator',$3)", [o(String(ports.a)), o(String(ports.b)), o(String(ports.c))]);
await m.query("INSERT INTO route_prefix(prefix, telco_id) VALUES ('+6099900','telco-a'),('+6099901','telco-b'),('+6099902','telco-c')");
await m.query(`INSERT INTO telco_signal_coverage(telco_id, signal) VALUES ('telco-a','SIM_SWAP'),('telco-a','DEVICE_SWAP'),('telco-a','CALL_FORWARDING'),('telco-a','KYC_MATCH'),('telco-b','SIM_SWAP'),('telco-b','CALL_FORWARDING'),('telco-c','SIM_SWAP'),('telco-c','DEVICE_SWAP'),('telco-c','KYC_MATCH')`);
const SCOPES = ["sim-swap:check", "device-swap:check", "call-forwarding:check", "kyc-match:check", "consent:write", "consent:read"];
const participants: Array<Record<string, string>> = [];
for (const name of ["sandbox-bank-a", "sandbox-bank-b"]) {
  const org = (await m.query("INSERT INTO organisations(name, kind, state) VALUES ($1,'bank','testing') RETURNING id", [`Synthetic ${name}`])).rows[0].id as string;
  const pem = pki.issue(name);
  const { publicKey, privateKey } = await generateKeyPair("ES256", { extractable: true });
  const kid = `${name}-k1`;
  const pub = { ...(await exportJWK(publicKey)), kid, alg: "ES256", use: "sig" };
  await m.query("INSERT INTO clients(client_id, org_id, scopes) VALUES ($1,$2,$3)", [name, org, SCOPES]);
  await m.query("INSERT INTO client_keys(client_id, kid, jwk, cert_sha256, expires_at) VALUES ($1,$2,$3,$4, now() + interval '30 days')", [name, kid, JSON.stringify(pub), (await import("../src/identity/tokens.js")).certThumbprint(new X509Certificate(pem.cert).raw)]);
  participants.push({ clientId: name, kid, certFile: w(`pki/${name}.crt`, pem.cert), keyFile: w(`pki/${name}.key`, pem.key), privateJwk: JSON.stringify(await exportJWK(privateKey)) });
}
await m.end();
writeFileSync(join(out, "participants.json"), JSON.stringify({ caFile: ca, participants }, null, 1), { mode: 0o600 });

const env: Record<string, string> = {
  TS_DATABASE_URL: dbEnv["TS_DATABASE_URL"]!, TS_REPORTING_URL: dbEnv["TS_REPORTING_URL"]!, TS_REDIS_URL: redisUrl, TS_PARTICIPANT_PORT: String(port),
  TS_TLS_CERT_FILE: files.srvCert, TS_TLS_KEY_FILE: files.srvKey, TS_PARTICIPANT_CA_FILE: ca,
  TS_TELCO_CA_FILE: ca, TS_TELCO_CLIENT_CERT_FILE: files.outCert, TS_TELCO_CLIENT_KEY_FILE: files.outKey,
  TS_ISSUER: "https://platform.sandbox.invalid", TS_TOKEN_ENDPOINT: `https://localhost:${port}/oauth/token`, TS_KMS_DIR: join(out, "kms"),
  TS_AUDIT_SINK: w("audit-sink.jsonl", ""), TS_TELCO_ALLOWLIST: [ports.a, ports.b, ports.c].map((p) => o(String(p))).join(","),
  TS_RATE_LIMIT_RPS: process.env["TS_RATE_LIMIT_RPS"] ?? "100", TS_TOKEN_RATE_LIMIT_RPS: process.env["TS_TOKEN_RATE_LIMIT_RPS"] ?? "10",
  MOCK_CERT_FILE: files.telcoCert, MOCK_KEY_FILE: files.telcoKey, MOCK_CLIENT_CA_FILE: ca, MOCK_A_PORT: String(ports.a), MOCK_B_PORT: String(ports.b), MOCK_C_PORT: String(ports.c),
};
w("env", Object.entries(env).map(([k, v]) => `${k}=${v}`).join("\n") + "\n");
// Variant for the Docker Compose network: service host names, and secrets mounted read-only at /run/sandbox.
const inC = (v: string) => v.replace(out, "/run/sandbox").replace("127.0.0.1:5432", "postgres:5432").replace("127.0.0.1:6379", "redis:6379").replace(/https:\/\/localhost:(910\d)/g, "https://mocks:$1");
w("env.compose", Object.entries(env).map(([k, v]) => `${k}=${inC(v)}`).join("\n") + "\n");
console.log(JSON.stringify({ ok: true, out, participants: participants.map((p) => p["clientId"]), note: "synthetic data only; secrets generated at setup in a 0700 directory" }));
void randomBytes;
