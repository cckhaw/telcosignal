// Pricing placeholders. ALL money is integer minor units; no floating point anywhere.
export interface Tier { upTo: number | null; pct: number }
export function validateTiers(t: unknown): Tier[] {
  if (!Array.isArray(t) || t.length === 0) throw new Error("tiers must be a non-empty array");
  let prev = 0;
  t.forEach((x, i) => {
    const o = x as { upTo: number | null; pct: number };
    if (!Number.isInteger(o.pct) || o.pct < 0 || o.pct > 100) throw new Error("tier pct must be an integer 0..100");
    const last = i === t.length - 1;
    if (last ? o.upTo !== null : !(Number.isInteger(o.upTo) && (o.upTo as number) > prev)) throw new Error("tiers must ascend and the last must be open-ended (upTo: null)");
    if (!last) prev = o.upTo as number;
  });
  return t as Tier[];
}
/** Marginal volume tiers: each unit is priced at its own tier's percentage of the unit price. Half-up rounding once, on the total. */
export function tieredAmount(count: number, unitPriceMinor: number, tiers: Tier[]): number {
  if (!Number.isInteger(count) || count < 0 || !Number.isInteger(unitPriceMinor) || unitPriceMinor < 0) throw new Error("integers required");
  let remaining = BigInt(count), prev = 0n, weighted = 0n;
  for (const t of tiers) {
    if (remaining === 0n) break;
    const cap = t.upTo === null ? remaining : BigInt(t.upTo) - prev;
    const units = remaining < cap ? remaining : cap;
    weighted += units * BigInt(t.pct);
    remaining -= units; prev += units;
  }
  return Number((BigInt(unitPriceMinor) * weighted + 50n) / 100n);
}
