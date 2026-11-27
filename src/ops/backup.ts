// Logical backup and restore (pg_dump / pg_restore). Backups hold DATA and SCHEMA but never keys: KMS keys are backed up separately
// (see docs/runbooks/backup-restore.md). On Neon, point-in-time restore is the primary mechanism (blocked on D-002); this is the portable fallback.
import { execFile } from "node:child_process";
import { promisify } from "node:util";
import pg from "pg";
const run = promisify(execFile);
const env = (url: string) => { const u = new URL(url); return { ...process.env, PGPASSWORD: decodeURIComponent(u.password), PGHOST: u.hostname, PGPORT: u.port || "5432", PGUSER: decodeURIComponent(u.username) }; };
const validName = (s: string) => { if (!/^[a-z0-9_]{1,63}$/.test(s)) throw new Error("bad database name"); return s; };
/** Identifiers cannot be bound parameters. Instead of interpolating them into SQL text, let Postgres quote them (format('%I', ...)) from a BOUND parameter. */
async function withIdentifier(c: pg.Client, template: string, id: string) {
  const sql = (await c.query("SELECT format($1, $2::text) AS s", [template, id])).rows[0].s as string;
  return c.query(sql);
}

export async function backupDatabase(superUrl: string, db: string, file: string): Promise<number> {
  const t0 = Date.now();
  await run("pg_dump", ["--format=custom", "--no-password", "--file", file, db], { env: env(superUrl), timeout: 120_000 });
  return Date.now() - t0;
}
/** Restore into a NEW database (never over a live one). Ownership, grants, row-level security, triggers and policies are restored as dumped. */
export async function restoreDatabase(superUrl: string, newDb: string, file: string): Promise<number> {
  validName(newDb);
  const t0 = Date.now();
  const admin = new pg.Client({ connectionString: superUrl }); await admin.connect();
  try {
    const exists = await admin.query("SELECT 1 FROM pg_database WHERE datname=$1", [newDb]);
    if (exists.rowCount) throw new Error("refusing to restore over an existing database");
    await withIdentifier(admin, "CREATE DATABASE %I", validName(newDb));
  } finally { await admin.end(); }
  await run("pg_restore", ["--no-password", "--exit-on-error", "--dbname", newDb, file], { env: env(superUrl), timeout: 120_000 });
  return Date.now() - t0;
}
export interface Fingerprint { tables: Record<string, number>; grants: string[]; rls: string[]; policies: number; triggers: number; functions: string[]; migrations: string[] }
/** A structural + data fingerprint used to prove a restore is faithful. */
export async function fingerprint(url: string): Promise<Fingerprint> {
  const c = new pg.Client({ connectionString: url }); await c.connect();
  try {
    const tn = (await c.query("SELECT tablename FROM pg_tables WHERE schemaname='public' ORDER BY 1")).rows.map((r) => r.tablename as string);
    const tables: Record<string, number> = {};
    for (const t of tn) tables[t] = Number((await withIdentifier(c, "SELECT count(*) AS n FROM public.%I", t)).rows[0].n);
    return {
      tables,
      grants: (await c.query("SELECT grantee || ':' || table_name || ':' || privilege_type AS g FROM information_schema.role_table_grants WHERE table_schema='public' AND grantee LIKE 'ts\\_%' ORDER BY 1")).rows.map((r) => r.g as string),
      rls: (await c.query("SELECT relname || ':' || relrowsecurity || ':' || relforcerowsecurity AS r FROM pg_class WHERE relnamespace='public'::regnamespace AND relkind='r' ORDER BY 1")).rows.map((r) => r.r as string),
      policies: Number((await c.query("SELECT count(*) n FROM pg_policies WHERE schemaname='public'")).rows[0].n),
      triggers: Number((await c.query("SELECT count(*) n FROM pg_trigger WHERE NOT tgisinternal")).rows[0].n),
      functions: (await c.query("SELECT p.proname || ':' || pg_get_userbyid(p.proowner) || ':' || p.prosecdef AS f FROM pg_proc p WHERE pronamespace='public'::regnamespace ORDER BY 1")).rows.map((r) => r.f as string),
      migrations: (await c.query("SELECT id || ':' || sha256 AS m FROM schema_migrations ORDER BY 1")).rows.map((r) => r.m as string),
    };
  } finally { await c.end(); }
}
