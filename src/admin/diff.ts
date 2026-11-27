export interface DiffRow { path: string; from: string; to: string }
const flat = (v: unknown, p = "", out: Record<string, string> = {}): Record<string, string> => {
  if (v !== null && typeof v === "object") { const e = Object.entries(v as Record<string, unknown>); if (e.length === 0) out[p || "(root)"] = Array.isArray(v) ? "[]" : "{}"; for (const [k, x] of e) flat(x, p ? `${p}.${k}` : k, out); }
  else out[p || "(root)"] = JSON.stringify(v ?? null);
  return out;
};
/** Path-level diff of two JSON documents (before -> after). */
export function jsonDiff(before: unknown, after: unknown): DiffRow[] {
  const a = flat(before), b = flat(after), rows: DiffRow[] = [];
  for (const k of [...new Set([...Object.keys(a), ...Object.keys(b)])].sort()) if (a[k] !== b[k]) rows.push({ path: k, from: a[k] ?? "(none)", to: b[k] ?? "(none)" });
  return rows;
}
