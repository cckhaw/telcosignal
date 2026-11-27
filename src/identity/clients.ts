import type { Pool } from "../db/pool.js";
export interface ClientRec { clientId: string; orgId: string; state: string; scopes: string[]; orgState: string; orgKind: string }
export interface KeyRec { kid: string; jwk: Record<string, unknown>; certSha256: string; expiresAt: Date; revokedAt: Date | null }

export async function lookupClient(pool: Pool, clientId: string): Promise<ClientRec | null> {
  if (!/^[a-z0-9][a-z0-9_-]{2,62}$/.test(clientId)) return null;
  const r = await pool.query("SELECT * FROM authn_lookup_client($1)", [clientId]);
  const x = r.rows[0];
  return x ? { clientId: x.client_id, orgId: x.org_id, state: x.state, scopes: x.scopes, orgState: x.org_state, orgKind: x.org_kind } : null;
}
export async function clientKeys(pool: Pool, clientId: string): Promise<KeyRec[]> {
  const r = await pool.query("SELECT * FROM authn_client_keys($1)", [clientId]);
  return r.rows.map((x) => ({ kid: x.kid, jwk: x.jwk, certSha256: x.cert_sha256, expiresAt: x.expires_at, revokedAt: x.revoked_at }));
}
/** Sandbox policy: organisations in 'testing' or 'active' state may call the API; everything else fails closed. */
export function clientUsable(c: ClientRec): boolean {
  return c.state === "active" && (c.orgState === "active" || c.orgState === "testing");
}
