// Retention and deletion jobs (worker role). Usage records (billing evidence) and the audit log are never deleted here.
import type { Pool } from "../db/pool.js";
export interface RetentionResult { requestLog: number; consents: number; sessions: number; abuseFlags: number }
export async function runRetention(w: Pool): Promise<RetentionResult> {
  const set = async (k: string, d: number) => Number(((await w.query("SELECT value #>> '{}' v FROM platform_setting WHERE key=$1", [k])).rows[0]?.v) ?? d);
  const logDays = Math.max(await set("logs.retention_days", 90), 7), consentDays = Math.max(await set("consent.retention_days", 180), 30);
  const a = await w.query("DELETE FROM request_log WHERE ts < now() - make_interval(days => $1)", [logDays]);
  const b = await w.query("DELETE FROM consents WHERE greatest(expires_at, coalesce(revoked_at, expires_at)) < now() - make_interval(days => $1)", [consentDays]);   // expired or revoked long ago: delete the subject link
  const c = await w.query("DELETE FROM admin_session WHERE coalesce(ended_at, expires_at) < now() - interval '30 days'");
  const d = await w.query("DELETE FROM abuse_flag WHERE ts < now() - interval '365 days'");
  return { requestLog: a.rowCount ?? 0, consents: b.rowCount ?? 0, sessions: c.rowCount ?? 0, abuseFlags: d.rowCount ?? 0 };
}
