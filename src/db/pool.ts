import pg from "pg";
export type Pool = pg.Pool;
export type Tx = pg.PoolClient;

export function makePool(connectionString: string, opts: { max?: number } = {}): Pool {
  const ssl = process.env["TS_DB_SSLMODE"] === "verify-full"
    ? { rejectUnauthorized: true, ...(process.env["TS_DB_CA"] ? { ca: process.env["TS_DB_CA"] } : {}) }
    : undefined; // local/CI only; non-local environments must set TS_DB_SSLMODE=verify-full
  const pool = new pg.Pool({ connectionString, max: opts.max ?? 10, statement_timeout: 5000, idle_in_transaction_session_timeout: 10000, ...(ssl ? { ssl } : {}) });
  pool.on("error", () => { /* idle client errors must not crash or leak details */ });
  return pool;
}

/** Run fn in a transaction scoped to one organisation. org id is set with SET LOCAL semantics
 *  (set_config(..., true)), so it can never leak to the next user of a pooled connection. */
export async function withOrgTx<T>(pool: Pool, orgId: string, fn: (tx: Tx) => Promise<T>): Promise<T> {
  if (!/^[0-9a-f-]{36}$/.test(orgId)) throw new Error("bad org id");
  const tx = await pool.connect();
  try {
    await tx.query("BEGIN");
    await tx.query("SELECT set_config('app.org_id', $1, true)", [orgId]);
    const r = await fn(tx);
    await tx.query("COMMIT");
    return r;
  } catch (e) {
    await tx.query("ROLLBACK").catch(() => undefined);
    throw e;
  } finally {
    tx.release();
  }
}

/** Transaction with NO tenant context: tenant tables return zero rows. Used for auth lookups/audit/config reads. */
export async function withSystemTx<T>(pool: Pool, fn: (tx: Tx) => Promise<T>): Promise<T> {
  const tx = await pool.connect();
  try {
    await tx.query("BEGIN");
    const r = await fn(tx);
    await tx.query("COMMIT");
    return r;
  } catch (e) {
    await tx.query("ROLLBACK").catch(() => undefined);
    throw e;
  } finally {
    tx.release();
  }
}
