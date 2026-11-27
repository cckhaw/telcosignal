import type { Pool } from "../db/pool.js";
/** Longest-prefix routing. M2 adds the number-porting overlay. Unknown prefixes return null (-> UNAVAILABLE, same as any failure). */
export async function routeNumber(pool: Pool, msisdn: string): Promise<string | null> {
  const r = await pool.query(
    `SELECT r.telco_id FROM route_prefix r JOIN telcos t ON t.id = r.telco_id
      WHERE $1 LIKE r.prefix || '%' AND t.state = 'active' ORDER BY length(r.prefix) DESC LIMIT 1`, [msisdn]);
  return r.rows[0]?.telco_id ?? null;
}
