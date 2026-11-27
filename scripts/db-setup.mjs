// Superuser-run setup for LOCAL/CI/sandbox databases. Generates role passwords at setup time (never committed).
// Usage: node scripts/db-setup.mjs <admin-url|-> <dbname> <out-env-file>
// The admin URL contains a password. Pass "-" and put the URL in TS_DB_SETUP_ADMIN_URL so it never appears on a command line (error messages
// and process listings include argv, which once carried a connection string into a CI artifact).
import pg from "pg";
import { randomBytes, createHmac } from "node:crypto";
import { writeFileSync } from "node:fs";
const [adminArg, dbname, outFile] = process.argv.slice(2);
const adminUrl = adminArg === "-" ? process.env.TS_DB_SETUP_ADMIN_URL : adminArg;
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
  // Attributes are stated only when the role is CREATED. Re-stating them with ALTER ROLE needs superuser even for NOSUPERUSER/NOBYPASSRLS
  // (managed Postgres such as Neon refuses it), so an existing role only gets a new password, and its attributes are VERIFIED below.
  await q(exists ? `ALTER ROLE ${ident(r)} PASSWORD '${p}'` : `CREATE ROLE ${ident(r)} LOGIN NOBYPASSRLS NOSUPERUSER NOCREATEDB NOCREATEROLE PASSWORD '${p}'`);
}
const bad = (await admin.query("select rolname, rolsuper, rolbypassrls, rolcreatedb, rolcreaterole, rolcanlogin from pg_roles where rolname = any($1) and (rolsuper or rolbypassrls or rolcreatedb or rolcreaterole or not rolcanlogin)", [Object.keys(roles)])).rows;
if (bad.length) throw new Error(`refusing to continue: platform roles with unexpected attributes: ${bad.map((b) => b.rolname).join(", ")}`);
for (const [r, attrs] of [["ts_lookup", "NOLOGIN BYPASSRLS"], ["ts_audit", "NOLOGIN NOBYPASSRLS"], ["ts_switch", "NOLOGIN NOBYPASSRLS"], ["ts_config", "NOLOGIN NOBYPASSRLS"]]) {
  const exists = (await admin.query("select 1 from pg_roles where rolname=$1", [r])).rowCount;
  if (!exists) await q(`CREATE ROLE ${r} ${attrs}`);
}
const defs = (await admin.query("select rolname, rolsuper, rolbypassrls, rolcanlogin from pg_roles where rolname = any($1)", [["ts_lookup", "ts_audit", "ts_switch", "ts_config"]])).rows;
const wrong = defs.filter((d) => d.rolsuper || d.rolcanlogin || d.rolbypassrls !== (d.rolname === "ts_lookup"));
if (wrong.length || defs.length !== 4) throw new Error(`refusing to continue: definer roles with unexpected attributes: ${wrong.map((d) => d.rolname).join(", ") || "missing"}`);
await q("GRANT ts_lookup, ts_audit, ts_switch, ts_config TO ts_migrator"); // lets the migrator hand ownership of definer functions to them
// CREATE DATABASE ... OWNER <role> needs the creating role to be able to SET ROLE to it. A superuser always can; on managed Postgres (Neon) the
// creator of a role holds ADMIN but not SET by default, so grant it explicitly (the creator can only do this for roles it created).
await q(`GRANT ts_migrator TO CURRENT_USER WITH SET TRUE`);
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
