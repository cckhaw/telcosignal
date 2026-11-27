// Telco A: CAMARA-style. Paths and payloads follow the vendored, pinned definitions in openapi/camara (see PINS.md):
//   sim-swap r4.3 (/sim-swap/v2/check), device-swap r4.3 (/device-swap/v1/check),
//   call-forwarding-signal r4.3 (/call-forwarding-signal/v0.5/check-unconditional-forwarding), KYC match r2.2 (/kyc-match/v0.3/match).
import { Ajv } from "ajv";
import type { AdapterRequest, AdapterResult, FieldMatch, TelcoAdapter } from "./types.js";
import type { Signal } from "../consent/consent.js";
import { OutboundClient, type MtlsOptions } from "./outbound.js";

const ajv = new Ajv({ strict: true, allErrors: false });
const bool = (k: string) => ajv.compile({ type: "object", properties: { [k]: { type: "boolean" } }, required: [k], additionalProperties: false });
const vSwap = bool("swapped"), vFwd = bool("active");
const MR = { enum: ["true", "false", "not_available"] };
const vKyc = ajv.compile({ type: "object", additionalProperties: false, properties: {
  idDocumentMatch: MR, nameMatch: MR, givenNameMatch: MR, familyNameMatch: MR, addressMatch: MR, birthdateMatch: MR, emailMatch: MR, postalCodeMatch: MR, countryMatch: MR,
  nameMatchScore: { type: "integer", minimum: 0, maximum: 100 }, givenNameMatchScore: { type: "integer", minimum: 0, maximum: 100 }, familyNameMatchScore: { type: "integer", minimum: 0, maximum: 100 },
  addressMatchScore: { type: "integer", minimum: 0, maximum: 100 },
}, minProperties: 1 });
export const CAMARA_PATHS = { SIM_SWAP: "/sim-swap/v2/check", DEVICE_SWAP: "/device-swap/v1/check", CALL_FORWARDING: "/call-forwarding-signal/v0.5/check-unconditional-forwarding", KYC_MATCH: "/kyc-match/v0.3/match" } as const;
const JSON_CT = /^application\/json/;

export class TelcoAAdapter implements TelcoAdapter {
  readonly supports = new Set<Signal>(["SIM_SWAP", "DEVICE_SWAP", "CALL_FORWARDING", "KYC_MATCH"]);
  private out: OutboundClient;
  constructor(readonly telcoId: string, baseUrl: string, allowList: string[], mtls: MtlsOptions, private timeoutMs = 2000) {
    this.out = new OutboundClient(baseUrl, allowList, mtls, timeoutMs);
  }
  async call(r: AdapterRequest): Promise<AdapterResult> {
    const t0 = performance.now();
    const done = (status: AdapterResult["status"], reason: string, fields?: Record<string, FieldMatch>): AdapterResult => ({ status, reason, telcoMs: Math.round(performance.now() - t0), ...(fields ? { fields } : {}) });
    if (!this.supports.has(r.signal)) return done("NOT_SUPPORTED", "signal not covered");
    const body = r.signal === "KYC_MATCH" ? { phoneNumber: r.msisdn, ...(r.kyc ?? {}) }
      : r.signal === "CALL_FORWARDING" ? { phoneNumber: r.msisdn } : { phoneNumber: r.msisdn, maxAge: r.maxAgeHours ?? 240 };
    const f = await this.out.post(CAMARA_PATHS[r.signal], JSON.stringify(body), { "content-type": "application/json", "x-correlator": r.correlationId, accept: "application/json" }, JSON_CT);
    if (!f.ok) return done("UNAVAILABLE", f.reason);
    let parsed: unknown;
    try { parsed = JSON.parse(f.text); } catch { return done("UNAVAILABLE", "malformed json"); }
    if (r.signal === "SIM_SWAP" || r.signal === "DEVICE_SWAP") return vSwap(parsed) ? done((parsed as { swapped: boolean }).swapped ? "TRUE" : "FALSE", "ok") : done("UNAVAILABLE", "response failed schema validation");
    if (r.signal === "CALL_FORWARDING") return vFwd(parsed) ? done((parsed as { active: boolean }).active ? "TRUE" : "FALSE", "ok") : done("UNAVAILABLE", "response failed schema validation");
    if (!vKyc(parsed)) return done("UNAVAILABLE", "response failed schema validation");
    return kycResult(parsed as Record<string, unknown>, done);
  }
  async close() { await this.out.close(); }
}

/** Overall: TRUE only if every returned match field is "true"; FALSE if any is "false"; otherwise UNAVAILABLE (never a false "match"). */
export function kycResult(p: Record<string, unknown>, done: (s: AdapterResult["status"], r: string, f?: Record<string, FieldMatch>) => AdapterResult): AdapterResult {
  const fields: Record<string, FieldMatch> = {};
  for (const [k, v] of Object.entries(p)) if (k.endsWith("Match")) fields[k.slice(0, -5)] = v === "true" ? "MATCH" : v === "false" ? "NO_MATCH" : "NOT_AVAILABLE";
  const vals = Object.values(fields);
  if (vals.length === 0) return done("UNAVAILABLE", "no match fields");
  if (vals.includes("NO_MATCH")) return done("FALSE", "ok", fields);
  if (vals.every((x) => x === "MATCH")) return done("TRUE", "ok", fields);
  return done("UNAVAILABLE", "some fields not available", fields);
}
