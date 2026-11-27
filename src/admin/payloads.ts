// Builds and validates change-request payloads from form input. Server-side validation happens BEFORE a request exists; the database re-checks.
import { SIGNALS, PURPOSES } from "../consent/consent.js";
import { validateTiers } from "../metering/pricing.js";
import { validateTelcoEndpoint } from "../common/ssrf.js";

export class InputError extends Error {}
export interface Built { kind: string; target: string; payload: Record<string, unknown>; orgId: string | null }
const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/;
const need = (f: Record<string, string>, k: string, re?: RegExp): string => { const v = (f[k] ?? "").trim(); if (!v || (re && !re.test(v))) throw new InputError(`invalid ${k}`); return v; };
const int = (f: Record<string, string>, k: string, min: number, max: number): number => { const v = Number(need(f, k, /^-?\d{1,12}$/)); if (v < min || v > max) throw new InputError(`invalid ${k}`); return v; };
const uuid = (f: Record<string, string>, k: string) => need(f, k, UUID);
const json = (f: Record<string, string>, k: string): unknown => { try { return JSON.parse(need(f, k)); } catch { throw new InputError(`${k} must be valid JSON`); } };
const tiersOf = (v: unknown) => { try { return validateTiers(v); } catch (e) { throw new InputError((e as Error).message); } };
const signal = (f: Record<string, string>, k = "signal") => { const v = need(f, k); if (!(SIGNALS as readonly string[]).includes(v)) throw new InputError(`invalid ${k}`); return v; };

export interface BuildCtx { allowLoopback: boolean; syntheticPrefixes: string[]; hashNumber: (n: string) => Promise<string> }
export async function buildChange(kind: string, f: Record<string, string>, ctx: BuildCtx): Promise<Built> {
  const action = f["action"] ?? "";
  switch (kind) {
    case "PRICE_PLAN":
      if (action === "create_plan") {
        const sp = json(f, "signalPrices") as Record<string, unknown>;
        for (const [s, v] of Object.entries(sp)) if (!(SIGNALS as readonly string[]).includes(s) || !Number.isInteger(v) || (v as number) < 0) throw new InputError("signalPrices must map signals to non-negative integers (minor units)");
        const id = need(f, "planId", /^[a-z0-9-]{3,40}$/);
        return { kind, target: `plan:${id}`, orgId: null, payload: { action, plan: { id, currency: need(f, "currency", /^[A-Z]{3}$/), platformFeeMinor: int(f, "platformFeeMinor", 0, 1_000_000), signalPriceMinor: sp, tiers: tiersOf(json(f, "tiers")) } } };
      }
      if (action === "assign") { const o = uuid(f, "orgId"); return { kind, target: `org:${o}`, orgId: o, payload: { action, orgId: o, planId: need(f, "planId", /^[a-z0-9-]{3,40}$/) } }; }
      break;
    case "RATE_LIMIT": { const o = uuid(f, "orgId"), s = signal(f); const m = (f["maxPerMinute"] ?? "").trim(); return { kind, target: `org:${o}:${s}`, orgId: o, payload: { orgId: o, signal: s, maxPerMinute: m === "" ? null : int(f, "maxPerMinute", 1, 100000) } }; }
    case "SETTING": {
      const key = need(f, "key"); const v = json(f, "value");
      if (key === "consent.max_days" && !(Number.isInteger(v) && (v as number) >= 1 && (v as number) <= 400)) throw new InputError("consent.max_days must be an integer 1..400");
      if (key === "sandbox.allow_loopback" && typeof v !== "boolean") throw new InputError("sandbox.allow_loopback must be true or false");
      if (key === "logs.retention_days" && !(Number.isInteger(v) && (v as number) >= 7 && (v as number) <= 3650)) throw new InputError("logs.retention_days must be an integer 7..3650");
      if (key === "consent.retention_days" && !(Number.isInteger(v) && (v as number) >= 30 && (v as number) <= 3650)) throw new InputError("consent.retention_days must be an integer 30..3650");
      if (!["consent.max_days", "sandbox.allow_loopback", "logs.retention_days", "consent.retention_days"].includes(key)) throw new InputError("unknown setting");
      return { kind, target: `setting:${key}`, orgId: null, payload: { key, value: v } };
    }
    case "ROUTING":
      if (action === "set_prefix") { const p = need(f, "prefix", /^\+[1-9][0-9]{1,14}$/); return { kind, target: `prefix:${p}`, orgId: null, payload: { action, prefix: p, telcoId: need(f, "telcoId", /^[a-z0-9-]{1,30}$/) } }; }
      if (action === "remove_prefix") { const p = need(f, "prefix", /^\+[1-9][0-9]{1,14}$/); return { kind, target: `prefix:${p}`, orgId: null, payload: { action, prefix: p } }; }
      if (action === "allow_origin" || action === "remove_origin") {
        const c = validateTelcoEndpoint(need(f, "origin"), { allowLoopback: ctx.allowLoopback }); if (!c.ok) throw new InputError(`endpoint refused: ${c.reason}`);
        return { kind, target: `origin:${c.origin}`, orgId: null, payload: { action, origin: c.origin } };
      }
      if (action === "create_telco" || action === "telco_endpoint") {
        const c = validateTelcoEndpoint(need(f, "baseUrl"), { allowLoopback: ctx.allowLoopback }); if (!c.ok) throw new InputError(`endpoint refused: ${c.reason}`);
        const id = need(f, "telcoId", /^[a-z0-9-]{1,30}$/);
        if (action === "telco_endpoint") return { kind, target: `telco:${id}`, orgId: null, payload: { action, telcoId: id, baseUrl: need(f, "baseUrl") } };
        const adapter = need(f, "adapter"); if (!["camara", "proprietary", "aggregator"].includes(adapter)) throw new InputError("invalid adapter type");
        const o = uuid(f, "orgId"); return { kind, target: `telco:${id}`, orgId: o, payload: { action, telcoId: id, adapter, baseUrl: need(f, "baseUrl"), orgId: o } };
      }
      if (action === "telco_state") { const s = need(f, "state"); if (!["draft", "testing", "active", "suspended", "retired"].includes(s)) throw new InputError("invalid state"); const id = need(f, "telcoId", /^[a-z0-9-]{1,30}$/); return { kind, target: `telco:${id}`, orgId: null, payload: { action, telcoId: id, state: s } }; }
      if (action === "coverage_set") { const id = need(f, "telcoId", /^[a-z0-9-]{1,30}$/); const sg = need(f, "signals").split(/[ ,]+/).filter(Boolean); sg.forEach((s) => { if (!(SIGNALS as readonly string[]).includes(s)) throw new InputError("invalid signal"); }); return { kind, target: `coverage:${id}`, orgId: null, payload: { action, telcoId: id, signals: sg } }; }
      break;
    case "PORTING": {
      const n = need(f, "msisdn", /^\+[1-9][0-9]{4,14}$/);
      if (!ctx.syntheticPrefixes.some((p) => n.startsWith(p))) throw new InputError("only synthetic numbers may be used in this sandbox");
      const t = need(f, "telcoId", /^[a-z0-9-]{1,30}$/); const hash = await ctx.hashNumber(n);       // the number is hashed here and never stored
      return { kind, target: `porting:${hash.slice(0, 16)}`, orgId: null, payload: { subjectHash: hash, telcoId: t, ...(f["effectiveFrom"] ? { effectiveFrom: new Date(need(f, "effectiveFrom")).toISOString() } : {}) } };
    }
    case "KILL_SWITCH_LIFT": { const s = need(f, "scope"); if (!["participant", "telco", "signal"].includes(s)) throw new InputError("invalid scope"); const k = need(f, "key", /^[A-Za-z0-9_-]{1,64}$/); return { kind, target: `${s}:${k}`, orgId: null, payload: { scope: s, key: k } }; }
    case "ORG_STATE": { const o = uuid(f, "orgId"); const t = need(f, "toState"); if (!["active", "retired"].includes(t)) throw new InputError("invalid target state"); return { kind, target: `org:${o}`, orgId: o, payload: { orgId: o, toState: t } }; }
    case "ENTITLEMENT": {
      const o = uuid(f, "orgId"), s = signal(f);
      if (f["remove"] === "on") return { kind, target: `org:${o}:${s}`, orgId: o, payload: { orgId: o, signal: s, purposes: null } };
      const ps = need(f, "purposes").split(/[ ,]+/).filter(Boolean); ps.forEach((p) => { if (!(PURPOSES as readonly string[]).includes(p)) throw new InputError("invalid purpose"); });
      return { kind, target: `org:${o}:${s}`, orgId: o, payload: { orgId: o, signal: s, purposes: ps } };
    }
    case "ADMIN_USER": {
      const role = need(f, "role"); const org = (f["orgId"] ?? "").trim();
      if (!["platform_admin", "operations", "integration_engineer", "security_auditor", "finance", "telco_user", "bank_user"].includes(role)) throw new InputError("invalid role");
      return { kind, target: `user:${need(f, "sub", /^[A-Za-z0-9._:@-]{3,128}$/)}`, orgId: org ? uuid(f, "orgId") : null, payload: { sub: need(f, "sub", /^[A-Za-z0-9._:@-]{3,128}$/), displayName: need(f, "displayName"), role, ...(org ? { orgId: uuid(f, "orgId") } : {}), state: f["state"] === "disabled" ? "disabled" : "active" } };
    }
  }
  throw new InputError("unsupported change");
}
