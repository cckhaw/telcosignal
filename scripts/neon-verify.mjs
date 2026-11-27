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

// 3. run the full test suite against Neon: each test file creates its own ts_t_* database and drops it afterwards
const env = { ...process.env, TS_TEST_ADMIN_URL: pick, TS_TEST_REDIS_URL: process.env.TS_TEST_REDIS_URL ?? "redis://127.0.0.1:6379/15", NEON_CANDIDATES: "" };
const r = spawnSync("npx", ["vitest", "run", "--reporter=json", "--outputFile=neon-vitest.json"], { env, stdio: ["ignore", "inherit", "inherit"] });
let summary = null;
try { const j = JSON.parse((await import("node:fs")).readFileSync("neon-vitest.json", "utf8")); summary = { files: j.numTotalTestSuites, tests: j.numTotalTests, passed: j.numPassedTests, failed: j.numFailedTests, failedNames: j.testResults.flatMap((f) => f.assertionResults.filter((a) => a.status === "failed").map((a) => `${f.name.split("/").slice(-1)[0]}: ${a.title}`.slice(0, 200))) }; } catch { /* leave null */ }
report.vitest = summary; step("full test suite against Neon", r.status === 0, summary ? `${summary.passed}/${summary.tests} passed` : `exit ${r.status}`);
finish(r.status === 0 ? 0 : 1);
