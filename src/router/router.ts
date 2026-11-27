import type { Pool } from "../db/pool.js";
import type { Kms } from "../kms/types.js";
import { subjectHash, type Signal } from "../consent/consent.js";

export type Route = { kind: "route"; telcoId: string } | { kind: "unsupported"; telcoId: string } | { kind: "none" };
/** Routing: number porting overlay (keyed hash, effective-dated) takes precedence over longest-prefix routing.
 *  Unknown prefixes => "none" (the caller answers UNAVAILABLE, identical to any other failure: no existence oracle). */
export async function routeNumber(pool: Pool, kms: Kms, msisdn: string, signal: Signal): Promise<Route> {
  const hash = await subjectHash(kms, msisdn);
  const ported = await pool.query("SELECT telco_id FROM porting WHERE subject_hash = $1 AND effective_from <= now() ORDER BY effective_from DESC LIMIT 1", [hash]);
  let telcoId: string | undefined = ported.rows[0]?.telco_id;
  if (!telcoId) {
    const r = await pool.query("SELECT telco_id FROM route_prefix WHERE $1 LIKE prefix || '%' ORDER BY length(prefix) DESC LIMIT 1", [msisdn]);
    telcoId = r.rows[0]?.telco_id;
  }
  if (!telcoId) return { kind: "none" };
  const t = await pool.query(
    "SELECT EXISTS (SELECT 1 FROM telcos WHERE id=$1 AND state='active') AS active, EXISTS (SELECT 1 FROM telco_signal_coverage WHERE telco_id=$1 AND signal=$2) AS covered", [telcoId, signal]);
  if (!t.rows[0]?.active) return { kind: "none" };
  return t.rows[0].covered ? { kind: "route", telcoId } : { kind: "unsupported", telcoId };
}
