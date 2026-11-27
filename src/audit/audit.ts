import { appendFileSync, readFileSync, existsSync } from "node:fs";
import { createHash } from "node:crypto";
import type { Pool } from "../db/pool.js";

export interface AuditEntry {
  correlationId: string; actor: string; action: string; orgId?: string; outcome: string;
  detail?: Record<string, string | number | boolean | null>;
}
const ZERO = Buffer.alloc(32);

function canonicalDetail(d: AuditEntry["detail"]): string {
  const o = d ?? {};
  return JSON.stringify(Object.fromEntries(Object.keys(o).sort().map((k) => [k, o[k]])));
}
export function canonicalLine(r: { seq: bigint | number | string; ts_us: bigint | number | string; correlation_id: string; actor: string; action: string; org_id: string; outcome: string; detail_text: string }) {
  return `${r.seq}|${r.ts_us}|${r.correlation_id}|${r.actor}|${r.action}|${r.org_id}|${r.outcome}|${r.detail_text}`;
}

export class Audit {
  constructor(private readonly pool: Pool, private readonly sinkPath: string) {}

  /** Throws on failure: callers fail closed (no un-audited successful access). */
  async record(e: AuditEntry): Promise<void> {
    const detail = canonicalDetail(e.detail);
    // Guard: audit records must never carry phone numbers.
    if (/\+[1-9][0-9]{4,14}/.test(detail) || /\+[1-9][0-9]{4,14}/.test(e.action)) throw new Error("audit record contains an E.164 number");
    const r = await this.pool.query(
      "SELECT seq::text, ts_us::text, prev_hash, hash FROM audit_append($1,$2,$3,$4,$5,$6)",
      [e.correlationId, e.actor, e.action, e.orgId ?? "", e.outcome, detail],
    );
    const row = r.rows[0];
    // External copy (mock WORM sink): append-only file outside the database. Only database-computed values (sequence and
    // hashes) are written: no request-derived text ever reaches the file, and the verifier needs nothing more.
    appendFileSync(this.sinkPath, JSON.stringify({ seq: String(row.seq), hash: Buffer.from(row.hash).toString("hex"), prev: Buffer.from(row.prev_hash).toString("hex") }) + "\n", { flag: "a", mode: 0o600 });
  }
}

export interface VerifyResult { ok: boolean; rows: number; problem?: string }
/** Recompute the chain from the database and compare against the external copy. */
export async function verifyAuditChain(reader: Pool, sinkPath: string): Promise<VerifyResult> {
  const { rows } = await reader.query("SELECT seq::text, ts_us::text, correlation_id, actor, action, org_id, outcome, detail_text, prev_hash, hash FROM audit_log ORDER BY audit_log.seq");
  let prev = ZERO;
  let expectSeq = 1n;
  for (const r of rows) {
    if (BigInt(r.seq) !== expectSeq) return { ok: false, rows: rows.length, problem: `gap at ${expectSeq}` };
    if (!Buffer.from(r.prev_hash).equals(prev)) return { ok: false, rows: rows.length, problem: `prev_hash mismatch at ${r.seq}` };
    const h = createHash("sha256").update(Buffer.concat([prev, Buffer.from(canonicalLine(r), "utf8")])).digest();
    if (!h.equals(Buffer.from(r.hash))) return { ok: false, rows: rows.length, problem: `hash mismatch at ${r.seq}` };
    prev = h; expectSeq += 1n;
  }
  const ext = existsSync(sinkPath) ? readFileSync(sinkPath, "utf8").split("\n").filter(Boolean).map((l) => JSON.parse(l) as { seq: string; hash: string }) : [];
  if (ext.length !== rows.length) return { ok: false, rows: rows.length, problem: `external copy has ${ext.length} rows, database has ${rows.length}` };
  for (let i = 0; i < rows.length; i++) {
    if (ext[i]?.hash !== Buffer.from(rows[i].hash).toString("hex")) return { ok: false, rows: rows.length, problem: `external copy differs at ${rows[i].seq}` };
  }
  return { ok: true, rows: rows.length };
}
