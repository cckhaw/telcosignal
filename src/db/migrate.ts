import { createHash } from "node:crypto";
import { readdirSync, readFileSync } from "node:fs";
import { join } from "node:path";
import pg from "pg";

/** Versioned, checksummed migrations. A changed already-applied file is refused (reviewed history is immutable). */
export async function migrate(migratorUrl: string, dir: string): Promise<string[]> {
  const c = new pg.Client({ connectionString: migratorUrl });
  await c.connect();
  const applied: string[] = [];
  try {
    await c.query("CREATE TABLE IF NOT EXISTS schema_migrations (id text PRIMARY KEY, sha256 text NOT NULL, applied_at timestamptz NOT NULL DEFAULT now())");
    for (const f of readdirSync(dir).filter((x) => /^\d{3}_[a-z0-9_]+\.sql$/.test(x)).sort()) {
      const sql = readFileSync(join(dir, f), "utf8");
      const sum = createHash("sha256").update(sql).digest("hex");
      const done = await c.query("SELECT sha256 FROM schema_migrations WHERE id=$1", [f]);
      if (done.rowCount) {
        if (done.rows[0].sha256 !== sum) throw new Error(`migration ${f} was modified after being applied`);
        continue;
      }
      await c.query("BEGIN");
      try {
        await c.query(sql);
        await c.query("INSERT INTO schema_migrations(id, sha256) VALUES ($1,$2)", [f, sum]);
        await c.query("COMMIT");
        applied.push(f);
      } catch (e) { await c.query("ROLLBACK"); throw e; }
    }
  } finally { await c.end(); }
  return applied;
}
