import { createHash } from "node:crypto";
import type { Pool } from "../db/pool.js";
import { tieredAmount, validateTiers } from "./pricing.js";

export interface GenerateResult { created: string[]; skipped: number; problems: string[] }
type Counts = Map<string, Map<string, number>>;     // signal -> telco -> count

/** Generates immutable statements for one period [start, end). Runs under the billing role (the only non-owner that may read usage across
 *  organisations) in a REPEATABLE READ snapshot, so every statement in a run sees the same usage. Idempotent: existing statements are never changed.
 *  Only billable usage is charged (TRUE/FALSE outcomes). Missing prices are reported, never guessed. */
export async function generateStatements(billing: Pool, period: { start: Date; end: Date }): Promise<GenerateResult> {
  const out: GenerateResult = { created: [], skipped: 0, problems: [] };
  const c = await billing.connect();
  try {
    await c.query("BEGIN ISOLATION LEVEL REPEATABLE READ READ WRITE");
    const orgs = await c.query("SELECT DISTINCT org_id FROM usage_record WHERE billable AND ts >= $1 AND ts < $2 ORDER BY org_id", [period.start, period.end]);
    for (const { org_id } of orgs.rows as Array<{ org_id: string }>) {
      const plan = (await c.query("SELECT p.* FROM org_price_plan o JOIN price_plan p ON p.id=o.plan_id WHERE o.org_id=$1 AND o.effective_from <= $2 ORDER BY o.effective_from DESC LIMIT 1", [org_id, period.start])).rows[0];
      if (!plan) { out.problems.push(`org ${org_id}: no price plan effective at period start`); continue; }
      const tiers = validateTiers(plan.tiers);
      const rows = (await c.query("SELECT id, signal, telco_id FROM usage_record WHERE org_id=$1 AND billable AND ts >= $2 AND ts < $3 ORDER BY id", [org_id, period.start, period.end])).rows as Array<{ id: string; signal: string; telco_id: string | null }>;
      const counts: Counts = new Map();
      const digest = createHash("sha256");
      for (const r of rows) { digest.update(`${r.id}\n`); const m = counts.get(r.signal) ?? new Map(); m.set(r.telco_id ?? "none", (m.get(r.telco_id ?? "none") ?? 0) + 1); counts.set(r.signal, m); }
      let total = 0; const lines = [];
      for (const [signal, byTelco] of [...counts].sort()) {
        const unit = plan.signal_price_minor[signal];
        if (!Number.isInteger(unit)) { out.problems.push(`org ${org_id}: no price for ${signal}`); total = -1; break; }
        const n = [...byTelco.values()].reduce((a, b) => a + b, 0);
        const tierAmount = tieredAmount(n, unit, tiers), fee = n * plan.platform_fee_minor;
        lines.push({ signal, count: n, unitPriceMinor: unit, tierAmountMinor: tierAmount, platformFeeMinor: fee, amountMinor: tierAmount + fee, byTelco: Object.fromEntries([...byTelco].sort()) });
        total += tierAmount + fee;
      }
      if (total < 0) continue;
      const ins = await c.query(
        `INSERT INTO statement(kind, org_id, period_start, period_end, currency, lines, usage_count, total_minor, usage_digest) VALUES ('participant',$1,$2,$3,$4,$5,$6,$7,$8)
         ON CONFLICT DO NOTHING RETURNING id`, [org_id, period.start, period.end, plan.currency, JSON.stringify(lines), rows.length, total, digest.digest()]);
      if (ins.rowCount) out.created.push(ins.rows[0].id);
      else if ((await c.query("SELECT 1 FROM statement WHERE kind='participant' AND org_id=$1 AND period_start=$2 AND period_end=$3", [org_id, period.start, period.end])).rowCount) out.skipped++;
      else out.problems.push(`org ${org_id}: period overlaps an existing statement (not generated, to avoid double billing)`);
    }
    const telcos = await c.query("SELECT DISTINCT telco_id FROM usage_record WHERE billable AND telco_id IS NOT NULL AND ts >= $1 AND ts < $2 ORDER BY telco_id", [period.start, period.end]);
    for (const { telco_id } of telcos.rows as Array<{ telco_id: string }>) {
      const rows = (await c.query("SELECT id, signal FROM usage_record WHERE telco_id=$1 AND billable AND ts >= $2 AND ts < $3 ORDER BY id", [telco_id, period.start, period.end])).rows as Array<{ id: string; signal: string }>;
      const bySignal = new Map<string, number>(); const digest = createHash("sha256");
      for (const r of rows) { digest.update(`${r.id}\n`); bySignal.set(r.signal, (bySignal.get(r.signal) ?? 0) + 1); }
      let total = 0, ok = true; const lines = []; let currency = "MYR";
      for (const [signal, n] of [...bySignal].sort()) {
        const cost = (await c.query("SELECT cost_minor FROM telco_cost WHERE telco_id=$1 AND signal=$2 AND effective_from <= $3 ORDER BY effective_from DESC LIMIT 1", [telco_id, signal, period.start])).rows[0]?.cost_minor as number | undefined;
        if (cost === undefined) { out.problems.push(`telco ${telco_id}: no cost for ${signal}`); ok = false; break; }
        lines.push({ signal, count: n, unitCostMinor: cost, amountMinor: n * cost }); total += n * cost;
      }
      if (!ok) continue;
      void currency; currency = "MYR";
      const ins = await c.query(
        `INSERT INTO statement(kind, telco_id, period_start, period_end, currency, lines, usage_count, total_minor, usage_digest) VALUES ('telco',$1,$2,$3,$4,$5,$6,$7,$8)
         ON CONFLICT DO NOTHING RETURNING id`, [telco_id, period.start, period.end, currency, JSON.stringify(lines), rows.length, total, digest.digest()]);
      if (ins.rowCount) out.created.push(ins.rows[0].id);
      else if ((await c.query("SELECT 1 FROM statement WHERE kind='telco' AND telco_id=$1 AND period_start=$2 AND period_end=$3", [telco_id, period.start, period.end])).rowCount) out.skipped++;
      else out.problems.push(`telco ${telco_id}: period overlaps an existing statement (not generated, to avoid double billing)`);
    }
    await c.query("COMMIT");
  } catch (e) { await c.query("ROLLBACK").catch(() => undefined); throw e; }
  finally { c.release(); }
  return out;
}
