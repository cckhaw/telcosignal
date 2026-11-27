import type { Tx } from "../db/pool.js";
import type { Kms } from "../kms/types.js";

export const PURPOSES = ["FRAUD_PREVENTION", "ACCOUNT_TAKEOVER_CHECK", "TRANSACTION_RISK"] as const;
export const SIGNALS = ["SIM_SWAP", "DEVICE_SWAP", "CALL_FORWARDING", "KYC_MATCH"] as const;
export type Signal = (typeof SIGNALS)[number];

export async function subjectHash(kms: Kms, msisdn: string): Promise<Buffer> {
  return kms.hmac("msisdn-hmac", msisdn);   // keyed hash: the number itself is never stored or logged
}

/** Consent must exist for THIS organisation (enforced by RLS), subject, purpose and signal, and be unexpired and unrevoked.
 *  Any failure is the same answer (no reason leaks which part failed). */
export async function consentValid(tx: Tx, q: { consentRef: string; subjectHash: Buffer; purpose: string; signal: Signal }): Promise<boolean> {
  const r = await tx.query(
    `SELECT 1 FROM consents WHERE consent_ref = $1 AND subject_hash = $2 AND purpose_code = $3
       AND $4 = ANY(signals) AND revoked_at IS NULL AND expires_at > now()`,
    [q.consentRef, q.subjectHash, q.purpose, q.signal],
  );
  return (r.rowCount ?? 0) > 0;
}

export async function createConsent(tx: Tx, orgId: string, c: { consentRef: string; subjectHash: Buffer; purpose: string; signals: string[]; expiresAt: Date }): Promise<string | null> {
  const r = await tx.query(
    `INSERT INTO consents(org_id, consent_ref, subject_hash, purpose_code, signals, expires_at)
     VALUES ($1,$2,$3,$4,$5,$6) ON CONFLICT (org_id, consent_ref) DO NOTHING RETURNING id`,
    [orgId, c.consentRef, c.subjectHash, c.purpose, c.signals, c.expiresAt],
  );
  return r.rows[0]?.id ?? null;
}
export async function revokeConsent(tx: Tx, id: string): Promise<boolean> {
  const r = await tx.query("UPDATE consents SET revoked_at = now() WHERE id = $1 AND revoked_at IS NULL", [id]);
  return (r.rowCount ?? 0) > 0;     // RLS: another organisation's consent is simply not visible -> false
}
export async function getConsent(tx: Tx, id: string) {
  const r = await tx.query("SELECT id, consent_ref, purpose_code, signals, granted_at, expires_at, revoked_at FROM consents WHERE id = $1", [id]);
  return r.rows[0] ?? null;
}
