// Time-bucketed rollups for dashboards. Built from the append-only usage records and the request log by the WORKER role,
// so dashboards never touch the request path. Rebuilding a bucket range is deterministic and idempotent.
import type { Pool } from "../db/pool.js";

/** Latency histogram bucket upper bounds in ms; the last bucket is open-ended (>= 2000 ms). */
export const BOUNDS = [5, 10, 25, 50, 100, 250, 500, 1000, 2000] as const;
const hist = (col: string): string => {
  const parts = BOUNDS.map((b, i) => `count(*) FILTER (WHERE ${col} < ${b}${i ? ` AND ${col} >= ${BOUNDS[i - 1]}` : ""})`);
  parts.push(`count(*) FILTER (WHERE ${col} >= ${BOUNDS[BOUNDS.length - 1]})`);
  return `ARRAY[${parts.join(", ")}]::int[]`;
};
/** Percentile from a merged histogram: the UPPER BOUND of the bucket containing the percentile (conservative). null = no data; Infinity = beyond the last bound. */
export function percentile(counts: number[], q: number): number | null {
  const total = counts.reduce((a, b) => a + b, 0);
  if (total === 0) return null;
  let cum = 0;
  for (let i = 0; i < counts.length; i++) { cum += counts[i] ?? 0; if (cum >= Math.ceil(q * total)) return i < BOUNDS.length ? BOUNDS[i]! : Infinity; }
  return Infinity;
}
export interface RefreshResult { from: Date; to: Date; usageRows: number; securityRows: number }

export async function refreshRollups(worker: Pool, o: { from?: Date; to?: Date; now?: Date } = {}): Promise<RefreshResult> {
  const c = await worker.connect();
  try {
    await c.query("BEGIN ISOLATION LEVEL REPEATABLE READ READ WRITE");
    const now = o.now ?? new Date();
    const to = o.to ?? new Date(Math.floor(now.getTime() / 60_000) * 60_000 + 60_000);          // include the current (partial) minute
    let from = o.from;
    if (!from) {
      const w = (await c.query("SELECT watermark FROM rollup_state WHERE name='main'")).rows[0]?.watermark as Date | undefined;
      const first = (await c.query("SELECT min(ts) AS t FROM usage_record")).rows[0]?.t as Date | null;
      from = w ? new Date(w.getTime() - 5 * 60_000) : first ? new Date(Math.floor(first.getTime() / 60_000) * 60_000) : to;     // 5-minute overlap absorbs late writes
    }
    await c.query("DELETE FROM rollup_minute WHERE bucket >= $1 AND bucket < $2", [from, to]);
    await c.query("DELETE FROM rollup_security_minute WHERE bucket >= $1 AND bucket < $2", [from, to]);
    const u = await c.query(
      `INSERT INTO rollup_minute(bucket, org_id, signal, telco_id, api_version, outcome, reason_class, requests, billable, total_ms_sum, telco_ms_sum, h_total, h_over, h_telco)
       SELECT date_trunc('minute', ts), org_id, signal, coalesce(telco_id, ''), api_version, outcome, reason_class, count(*), count(*) FILTER (WHERE billable), sum(total_ms), sum(telco_ms),
              ${hist("total_ms")}, ${hist("greatest(total_ms - telco_ms, 0)")}, ${hist("telco_ms")}
       FROM usage_record WHERE ts >= $1 AND ts < $2 GROUP BY 1,2,3,4,5,6,7`, [from, to]);
    const s = await c.query(
      `INSERT INTO rollup_security_minute(bucket, org_key, org_id, error_code, events)
       SELECT date_trunc('minute', ts), coalesce(org_id::text, ''), org_id, error_code, count(*) FROM request_log WHERE error_code IS NOT NULL AND ts >= $1 AND ts < $2 GROUP BY 1,2,3,4`, [from, to]);
    await c.query("INSERT INTO rollup_state(name, watermark, updated_at) VALUES ('main', $1, now()) ON CONFLICT (name) DO UPDATE SET watermark = EXCLUDED.watermark, updated_at = now()", [to]);
    await c.query("COMMIT");
    return { from, to, usageRows: u.rowCount ?? 0, securityRows: s.rowCount ?? 0 };
  } catch (e) { await c.query("ROLLBACK").catch(() => undefined); throw e; } finally { c.release(); }
}
