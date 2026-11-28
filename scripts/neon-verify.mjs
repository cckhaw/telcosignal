// Runs the platform's database layer and test suite against the Neon project the owner connected (SYNTHETIC DATA ONLY).
// Manual (workflow_dispatch) only. Never prints the connection string, host or password. Creates only objects whose names start with ts_.
// Usage (CI): node scripts/neon-verify.mjs <out-json>   env: NEON_CANDIDATES = newline-separated list of candidate connection strings (secrets)
import pg from "pg";
import { spawnSync } from "node:child_process";
import { writeFileSync } from "node:fs";

const out = process.argv[2] ?? "neon-verify.json";
// NEON_CANDIDATES: lines of NAME=value (value = a secret). Only NAMES and non-secret URL shape facts are ever printed.
const cands = (process.env.NEON_CANDIDATES ?? "").split("\n").map((l) => l.trim()).filter(Boolean).map((l) => { const i = l.indexOf("="); return { name: l.slice(0, i), value: l.slice(i + 1) }; }).filter((c) => c.value);
const report = { synthetic: true, started: new Date().toISOString(), steps: [] };
const step = (name, ok, detail) => { report.steps.push({ name, ok, ...(detail ? { detail } : {}) }); console.log(`${ok ? "PASS" : "FAIL"} ${name}${detail ? ` - ${detail}` : ""}`); };
const finish = (code) => { report.finished = new Date().toISOString(); writeFileSync(out, JSON.stringify(report, null, 1)); process.exit(code); };

// 1. pick a Neon connection string; refuse anything that is not a Neon host (never run this against another database by accident).
//    A pooled host (-pooler) is converted to the direct host (Neon convention) because the platform needs session features (roles, DDL, advisory locks).
const shape = (c) => { try { const u = new URL(c.value); return { name: c.name, scheme: u.protocol, neonHost: u.hostname.endsWith(".neon.tech"), pooled: u.hostname.includes("-pooler"), port: u.port || "default", sslmode: u.searchParams.get("sslmode") ?? "none" }; } catch { return { name: c.name, parsable: false }; } };
report.candidates = cands.map(shape); console.log("candidate shapes (no secrets):", JSON.stringify(report.candidates));
const toDirect = (v) => { const u = new URL(v); u.hostname = u.hostname.replace("-pooler", ""); u.searchParams.delete("pgbouncer"); u.searchParams.delete("channel_binding"); return u.toString(); };
const found = cands.find((c) => { try { const u = new URL(c.value); return u.protocol.startsWith("postgres") && u.hostname.endsWith(".neon.tech"); } catch { return false; } });
if (!found) { step("find a Neon connection string among the configured secrets", false, `${cands.length} candidate(s) present; none is a postgres URL on a *.neon.tech host`); finish(1); }
const pick = toDirect(found.value); report.secret_used = found.name;
const u = new URL(pick);
report.region_hint = u.hostname.split(".").slice(-4, -3)[0];
step(`found a Neon connection string (secret ${found.name}${shape(found).pooled ? ", pooled host converted to direct" : ""})`, true);

const admin = new pg.Client({ connectionString: pick, ssl: { rejectUnauthorized: true } });
try { await admin.connect(); } catch (e) { step("connect (TLS verified)", false, String(e.message).replace(/postgres:\/\/\S+/g, "[url]")); finish(1); }
const ver = (await admin.query("select version() v, current_user u, (select rolcreaterole from pg_roles where rolname=current_user) cr, (select rolbypassrls from pg_roles where rolname=current_user) bypass")).rows[0];
report.server = ver.v.split(" on ")[0]; report.can_create_role = ver.cr; step("connect (TLS verified) and read server version", true, report.server);

// 2. can the connecting role create the roles the platform needs (incl. a BYPASSRLS definer role)?
const t = "ts_probe_" + Math.random().toString(36).slice(2, 8);
try { await admin.query(`CREATE ROLE ${t} NOLOGIN BYPASSRLS`); await admin.query(`DROP ROLE ${t}`); step("can create a BYPASSRLS definer role", true); }
catch (e) { step("can create a BYPASSRLS definer role", false, String(e.message)); await admin.end(); finish(1); }
await admin.end();

const redact = (t) => String(t).replace(/[a-z][a-z0-9+.-]*:\/\/[^\s'"]+/gi, "[url]").replace(new RegExp(u.password.replace(/[.*+?^${}()|[\]\\]/g, "\\$&"), "g"), "[secret]").slice(0, 600);
// 2b. run the database setup once, directly, and show a REDACTED error if it fails (the test harness hides the cause)
const probe = spawnSync("node", ["scripts/db-setup.mjs", "-", "ts_t_probe_neon", "neon-probe.env"], { env: { ...process.env, TS_DB_SETUP_ADMIN_URL: pick }, encoding: "utf8" });
step("database setup (roles + database) on Neon", probe.status === 0, probe.status === 0 ? undefined : redact(probe.stderr.split("\n").filter((l) => /error|permission|must|cannot|denied|exist/i.test(l)).slice(0, 3).join(" | ")));
if (probe.status !== 0) finish(1);
if (probe.status === 0) { const d = new pg.Client({ connectionString: pick }); await d.connect(); await d.query('DROP DATABASE IF EXISTS ts_t_probe_neon WITH (FORCE)'); await d.end(); }

// 3. run a representative subset of the suite against Neon (the database layer: roles, forced row-level security, audit chain, metering, tenant isolation).
//    The full suite (21 files, each creating its own database over the WAN) did not finish inside 45 minutes, so the subset is time-boxed and progress is visible.
const files = (process.env.NEON_TEST_FILES ?? "tests/security/m1-controls.test.ts tests/security/m3-metering.test.ts").split(/\s+/).filter(Boolean);
const dropLeftovers = async () => { const d = new pg.Client({ connectionString: pick }); await d.connect(); const dbs = (await d.query("select datname from pg_database where datname like 'ts\\_t\\_%'")).rows; for (const x of dbs) await d.query(`DROP DATABASE IF EXISTS "${x.datname}" WITH (FORCE)`).catch(() => undefined); await d.end(); return dbs.length; };
step("removed leftover ts_t_* databases from earlier runs", true, String(await dropLeftovers()));
const env = { ...process.env, TS_TEST_ADMIN_URL: pick, TS_TEST_REDIS_URL: process.env.TS_TEST_REDIS_URL ?? "redis://127.0.0.1:6379/15", NEON_CANDIDATES: "" };
const started = Date.now();
const r = spawnSync("npx", ["vitest", "run", ...files, "--testTimeout=300000", "--hookTimeout=300000", "--reporter=default", "--reporter=json", "--outputFile.json=/tmp/neon-vitest.json"], { env, stdio: ["ignore", "inherit", "inherit"], timeout: 20 * 60 * 1000, killSignal: "SIGTERM" });   // raw JSON stays on the runner (it can echo connection details)
report.test_seconds = Math.round((Date.now() - started) / 1000);
let summary = null;
try { const j = JSON.parse((await import("node:fs")).readFileSync("/tmp/neon-vitest.json", "utf8")); summary = { files, tests: j.numTotalTests, passed: j.numPassedTests, failed: j.numFailedTests, failedNames: j.testResults.flatMap((f) => f.assertionResults.filter((a) => a.status === "failed").map((a) => redact(`${f.name.split("/").slice(-1)[0]}: ${a.title} => ${String((a.failureMessages ?? [""])[0]).split("\n")[0]}`))) }; } catch { /* leave null */ }
report.vitest = summary;
step("cleanup: removed ts_t_* databases created by this run", true, String(await dropLeftovers()));
step(`database-layer tests against Neon (${files.length} files, ${report.test_seconds}s${r.error ? ", " + r.error.code : ""})`, r.status === 0, summary ? `${summary.passed}/${summary.tests} passed` : `exit ${r.status}`);
finish(r.status === 0 ? 0 : 1);
