// DB-driven adapter registry: telcos onboarded/changed through the admin portal take effect without a restart.
/** Anything that can run a parameterised query (the participant pool, or the admin portal's scoped wrapper). */
export interface QueryPool { query(sql: string, params?: unknown[]): Promise<{ rows: Array<Record<string, unknown>> }> }
import type { TelcoAdapter } from "./types.js";
import { TelcoAAdapter } from "./telcoA.js";
import { TelcoBAdapter } from "./telcoB.js";
import { TelcoCAdapter } from "./telcoC.js";
import type { MtlsOptions } from "./outbound.js";
import { ResilientAdapter, type ResilienceConfig } from "../resilience/breaker.js";
import { validateTelcoEndpoint } from "../common/ssrf.js";

export interface AdapterSource { get(telcoId: string): Promise<TelcoAdapter | undefined> | TelcoAdapter | undefined }
interface Entry { fingerprint: string; adapter: ResilientAdapter; at: number }

export class AdapterRegistry implements AdapterSource {
  private cache = new Map<string, Entry>();
  constructor(private pool: QueryPool, private o: { mtls: MtlsOptions; timeoutMs: number; resilience: ResilienceConfig; envAllowList: string[]; ttlMs?: number; allowLoopback?: boolean }) {}

  /** Active telcos only (this is what participant traffic uses). */
  async get(telcoId: string) { return this.load(telcoId, true); }
  /** Any non-retired telco, for onboarding conformance tests and the synthetic test console. */
  async getForTest(telcoId: string) { return this.load(telcoId, false); }
  breakerStates() { return [...this.cache].map(([id, e]) => ({ telcoId: id, ...e.adapter.getState() })); }

  private async load(telcoId: string, activeOnly: boolean): Promise<TelcoAdapter | undefined> {
    const hit = this.cache.get(telcoId);
    const ttl = this.o.ttlMs ?? 3000;
    const r = !hit || Date.now() - hit.at > ttl
      ? await this.pool.query("SELECT adapter, base_url, state FROM telcos WHERE id = $1", [telcoId]) : null;
    if (r) {
      const row = r.rows[0] as unknown as { adapter: string; base_url: string; state: string } | undefined;
      if (!row || row.state === "retired" || (activeOnly && row.state !== "active")) { return undefined; }
      const fp = `${row.adapter}|${row.base_url}`;
      if (hit && hit.fingerprint === fp) { hit.at = Date.now(); return hit.adapter; }
      const al = await this.pool.query("SELECT origin FROM endpoint_allowlist");
      const allow = [...this.o.envAllowList, ...al.rows.map((x) => String(x['origin']))];
      const check = validateTelcoEndpoint(row.base_url, { allowLoopback: this.o.allowLoopback ?? false });
      if (!check.ok || !allow.includes(check.origin!)) return undefined;      // defence in depth: never build an adapter for an unvetted endpoint
      const inner: TelcoAdapter = row.adapter === "camara" ? new TelcoAAdapter(telcoId, row.base_url, allow, this.o.mtls, this.o.timeoutMs)
        : row.adapter === "proprietary" ? new TelcoBAdapter(telcoId, row.base_url, allow, this.o.mtls, this.o.timeoutMs)
        : new TelcoCAdapter(telcoId, telcoId, row.base_url, allow, this.o.mtls, this.o.timeoutMs);
      const a = new ResilientAdapter(inner, this.o.resilience);
      if (hit) void hit.adapter.close();
      this.cache.set(telcoId, { fingerprint: fp, adapter: a, at: Date.now() });
      return a;
    }
    return hit?.adapter;
  }
  async close() { for (const e of this.cache.values()) await e.adapter.close(); }
}
