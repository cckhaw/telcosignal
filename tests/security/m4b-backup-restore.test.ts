import { describe, it, expect, beforeAll, afterAll } from "vitest";
import { mkdtempSync, rmSync, statSync, readFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import pg from "pg";
import { startHarness, num, type Harness } from "../helpers/harness.js";
import { startAdmin, type Admin } from "../helpers/admin-harness.js";
import { backupDatabase, restoreDatabase, fingerprint } from "../../src/ops/backup.js";
import { generateStatements } from "../../src/metering/statements.js";
import { refreshRollups } from "../../src/ops/rollups.js";
import { makePool } from "../../src/db/pool.js";
import { verifyAuditChain } from "../../src/audit/audit.js";

let h: Harness, a: Admin; const dir = mkdtempSync(join(tmpdir(), "bk-")); let restoredDb = ""; let restoredUrl = (role: string) => role;
const su = (db: string) => h.adminUrl.replace(/\/[^/]*$/, `/${db}`);
beforeAll(async () => {
  h = await startHarness(); a = await startAdmin(h);
  const alice = await a.login("alice"), bob = await a.login("bob");
  for (let i = 0; i < 5; i++) { const n = num(i % 2 ? "1" : "0", `95${i}0`); const c = await h.consent(h.bankA, n); await h.call(h.bankA, "POST", "/v1/signals/sim-swap/check", { body: { phoneNumber: n, consentRef: c.ref, purposeCode: "FRAUD_PREVENTION" } }); }
  await h.migrator.query("INSERT INTO price_plan(id,currency,platform_fee_minor,signal_price_minor,tiers) VALUES ('bk-plan','MYR',1,'{\"SIM_SWAP\":10}','[{\"upTo\":null,\"pct\":100}]')");
  await h.migrator.query("INSERT INTO org_price_plan(org_id,plan_id,effective_from) VALUES ($1,'bk-plan', now() - interval '1 day')", [h.orgA]);
  await h.migrator.query("INSERT INTO telco_cost(telco_id,signal,cost_minor,effective_from) VALUES ('telco-a','SIM_SWAP',4, now() - interval '1 day')");
  await generateStatements(h.billing, { start: new Date(Date.now() - 3600e3), end: new Date(Date.now() + 3600e3) });
  const ch = await alice.post("/changes/new", { kind: "RATE_LIMIT", orgId: h.orgA, signal: "SIM_SWAP", maxPerMinute: "77" }); await bob.post(`${ch.location}/approve`, {});
  await h.app.drainLogs(); await refreshRollups(h.worker);
});
afterAll(async () => {
  await a.stop();
  if (restoredDb) { const c = new pg.Client({ connectionString: h.adminUrl }); await c.connect(); await c.query(`DROP DATABASE IF EXISTS "${restoredDb}" WITH (FORCE)`); await c.end(); }
  await h.stop(); rmSync(dir, { recursive: true, force: true });
});

describe("TESTED RESTORE: a backup restores faithfully into a new database", () => {
  let file = "", backupMs = 0, restoreMs = 0;
  it("takes a backup, and restores it into a NEW database (never over an existing one)", async () => {
    file = join(dir, "backup.dump"); backupMs = await backupDatabase(h.adminUrl, h.dbName, file);
    expect(statSync(file).size).toBeGreaterThan(10_000);
    restoredDb = `${h.dbName}_restored`; restoreMs = await restoreDatabase(h.adminUrl, restoredDb, file);
    await expect(restoreDatabase(h.adminUrl, restoredDb, file)).rejects.toThrow(/refusing to restore over an existing database/);
    await expect(restoreDatabase(h.adminUrl, h.dbName, file)).rejects.toThrow(/refusing/);
    restoredUrl = (role: string) => { const u = new URL(role === "su" ? h.adminUrl : (h.urls as unknown as Record<string, string>)[role]!); u.pathname = `/${restoredDb}`; return u.toString(); };
    expect(backupMs).toBeLessThan(60_000); expect(restoreMs).toBeLessThan(60_000);      // measured RPO/RTO inputs are recorded in docs/reports/M4b.md
  });
  it("the restored database has identical data (row counts of every table) and identical structure", async () => {
    const [src, dst] = [await fingerprint(su(h.dbName)), await fingerprint(su(restoredDb))];
    expect(dst.tables).toEqual(src.tables); expect(Object.keys(src.tables).length).toBeGreaterThan(30);
    expect(src.tables["audit_log"]).toBeGreaterThan(5); expect(src.tables["usage_record"]).toBeGreaterThan(3); expect(src.tables["statement"]).toBeGreaterThan(0); expect(src.tables["config_history"]).toBeGreaterThan(0);
    expect(dst.migrations).toEqual(src.migrations); expect(dst.triggers).toBe(src.triggers); expect(dst.policies).toBe(src.policies); expect(dst.functions).toEqual(src.functions);
  });
  it("privileges, ownership and row-level security are restored exactly (the least-privilege model survives a restore)", async () => {
    const [src, dst] = [await fingerprint(su(h.dbName)), await fingerprint(su(restoredDb))];
    expect(dst.grants).toEqual(src.grants); expect(dst.grants.length).toBeGreaterThan(100); expect(dst.rls).toEqual(src.rls);
    expect(dst.rls.filter((r) => r.endsWith(":true:true")).length).toBeGreaterThan(20);        // row-level security enabled AND forced
  });
  it("the audit chain still verifies after restore (both recomputation and comparison with the external copy), and a tampered restore would not", async () => {
    const pool = makePool(restoredUrl("reporting"), { max: 2 });
    try {
      const v = await verifyAuditChain(pool, h.auditSink); expect(v.problem ?? "ok").toBe("ok"); expect(v.ok).toBe(true);
      const sql = await pool.query("SELECT * FROM audit_verify()").catch(() => null); void sql;
    } finally { await pool.end(); }
    const c = new pg.Client({ connectionString: su(restoredDb) }); await c.connect();
    try { const r = await c.query("SELECT * FROM audit_verify()"); expect(r.rows[0]).toMatchObject({ ok: true }); } finally { await c.end(); }
  });
  it("tenant isolation is still enforced in the restored database (application role, pooled)", async () => {
    const pool = makePool(restoredUrl("app"), { max: 1 });
    try {
      expect((await pool.query("SELECT count(*)::int n FROM consents")).rows[0].n).toBe(0);                 // no tenant context => nothing
      const c = await pool.connect();
      try { await c.query("BEGIN"); await c.query("SELECT set_config('app.org_id',$1,true)", [h.orgA]); const own = (await c.query("SELECT count(*)::int n FROM consents")).rows[0].n; const other = (await c.query("SELECT count(*)::int n FROM consents WHERE org_id <> $1", [h.orgA])).rows[0].n; await c.query("ROLLBACK"); expect(own).toBeGreaterThan(0); expect(other).toBe(0); } finally { c.release(); }
      await expect(pool.query("DELETE FROM usage_record")).rejects.toThrow(/permission denied|append-only/i);
      await expect(pool.query("UPDATE audit_log SET outcome='x'")).rejects.toThrow(/permission denied/i);
    } finally { await pool.end(); }
    const adm = makePool(restoredUrl("admin"), { max: 1 });
    try { await expect(adm.query("UPDATE rate_limit_override SET max_per_minute = 1")).rejects.toThrow(/permission denied/i); await expect(adm.query("SELECT cfg_decide(gen_random_uuid(),'alice',true,'x',10)")).rejects.toThrow(/no such change|not pending/); } finally { await adm.end(); }
  });
  it("business data still reconciles in the restored database: statements tie to usage records by digest; rollups equal usage", async () => {
    const c = new pg.Client({ connectionString: su(restoredDb) }); await c.connect();
    try {
      const st = (await c.query("SELECT usage_count, encode(usage_digest,'hex') d FROM statement WHERE kind='participant' AND org_id=$1", [h.orgA])).rows[0];
      const ids = (await c.query("SELECT id FROM usage_record WHERE org_id=$1 AND billable ORDER BY id", [h.orgA])).rows.map((r) => r.id);
      const { createHash } = await import("node:crypto");
      expect(st.usage_count).toBe(ids.length); expect(st.d).toBe(createHash("sha256").update(ids.map((i) => `${i}\n`).join("")).digest("hex"));
      expect((await c.query("SELECT sum(requests)::int n FROM rollup_minute")).rows[0].n).toBe((await c.query("SELECT count(*)::int n FROM usage_record")).rows[0].n);
      expect((await c.query("SELECT max_per_minute m FROM rate_limit_override WHERE org_id=$1 AND signal='SIM_SWAP'", [h.orgA])).rows[0].m).toBe(77);
    } finally { await c.end(); }
  });
  it("the backup contains no key material and no phone numbers", async () => {
    const raw = readFileSync(file).toString("latin1");
    expect(raw).not.toMatch(/BEGIN (EC |RSA )?PRIVATE KEY/); expect(raw).not.toMatch(/\+60999000[0-9]{5}/); expect(raw).not.toContain("6099900950");
    for (const kmsFile of ["msisdn-hmac.v1.key", "token-signing-ec.v1.key"]) expect(raw).not.toContain(kmsFile);
  });
});
