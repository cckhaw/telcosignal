// Superuser-run setup for LOCAL/CI/sandbox databases. Generates role passwords at setup time (never committed).
// Usage: node scripts/db-setup.mjs <admin-url> <dbname> <out-env-file>
import pg from "pg";
import { randomBytes, createHmac } from "node:crypto";
import { writeFileSync } from "node:fs";
const [adminUrl, dbname, outFile] = process.argv.slice(2);
if (!adminUrl || !/^[a-z0-9_]{1,40}$/.test(dbname ?? "")) throw new Error("usage: db-setup <admin-url> <dbname> [out]");
// Role passwords are generated at setup. Roles are cluster-wide, so several databases created in ONE test run share
// per-run derived passwords (TS_ROLE_PW_SEED, random per run); production-like setups leave it unset => fresh random passwords.
const seed = process.env.TS_ROLE_PW_SEED;
const pw = (r) => (seed ? createHmac("sha256", seed).update(r).digest("base64url") : randomBytes(24).toString("base64url"));
const roles = { ts_migrator: pw("ts_migrator"), ts_app: pw("ts_app"), ts_reporting: pw("ts_reporting"), ts_billing: pw("ts_billing"), ts_admin: pw("ts_admin"), ts_worker: pw("ts_worker") };
const admin = new pg.Client({ connectionString: adminUrl });
await admin.connect();
const q = (s) => admin.query(s);
const ident = (s) => `"${s.replace(/"/g, '""')}"`;
for (const [r, p] of Object.entries(roles)) {
  const exists = (await admin.query("select 1 from pg_roles where rolname=$1", [r])).rowCount;
  const attrs = r === "ts_migrator" ? "LOGIN NOBYPASSRLS NOSUPERUSER NOCREATEDB NOCREATEROLE" : "LOGIN NOBYPASSRLS NOSUPERUSER NOCREATEDB NOCREATEROLE";
  await q(`${exists ? "ALTER" : "CREATE"} ROLE ${ident(r)} ${attrs} PASSWORD '${p}'`);
}
for (const [r, attrs] of [["ts_lookup", "NOLOGIN BYPASSRLS"], ["ts_audit", "NOLOGIN NOBYPASSRLS"], ["ts_switch", "NOLOGIN NOBYPASSRLS"], ["ts_config", "NOLOGIN NOBYPASSRLS"]]) {
  const exists = (await admin.query("select 1 from pg_roles where rolname=$1", [r])).rowCount;
  if (!exists) await q(`CREATE ROLE ${r} ${attrs}`);
}
await q("GRANT ts_lookup, ts_audit, ts_switch, ts_config TO ts_migrator"); // lets the migrator hand ownership of definer functions to them
await q(`DROP DATABASE IF EXISTS ${ident(dbname)} WITH (FORCE)`);
await q(`CREATE DATABASE ${ident(dbname)} OWNER ts_migrator`);
await q(`REVOKE ALL ON DATABASE ${ident(dbname)} FROM PUBLIC`);
await q(`GRANT CONNECT ON DATABASE ${ident(dbname)} TO ts_app, ts_reporting, ts_migrator, ts_billing, ts_admin, ts_worker`);
await admin.end();
const u = new URL(adminUrl);
const url = (r) => { const x = new URL(adminUrl); x.username = r; x.password = roles[r]; x.pathname = `/${dbname}`; return x.toString(); };
const env = { TS_MIGRATOR_URL: url("ts_migrator"), TS_DATABASE_URL: url("ts_app"), TS_REPORTING_URL: url("ts_reporting"), TS_BILLING_URL: url("ts_billing"), TS_ADMIN_DB_URL: url("ts_admin"), TS_WORKER_URL: url("ts_worker") };
if (outFile) writeFileSync(outFile, Object.entries(env).map(([k, v]) => `${k}=${v}`).join("\n") + "\n", { mode: 0o600 });
void u;
console.log(JSON.stringify({ ok: true, db: dbname, envFile: outFile ?? null }));
