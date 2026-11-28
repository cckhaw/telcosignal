// Telco A: CAMARA-style. Paths and payloads follow the vendored, pinned definitions in openapi/camara (see PINS.md):
//   sim-swap r4.3 (/sim-swap/v2/check), device-swap r4.3 (/device-swap/v1/check),
//   call-forwarding-signal r4.3 (/call-forwarding-signal/v0.5/check-unconditional-forwarding), KYC match r2.2 (/kyc-match/v0.3/match),
//   number-recycling r3.3 (/number-recycling/v0.3/check), kyc-tenure r3.4 (/kyc-tenure/v0.3/check-tenure),
//   location-verification r4.3 (/location-verification/v3/verify), device-roaming-status r2.2 (/device-roaming-status/v1/retrieve).
import { Ajv } from "ajv";
import type { AdapterRequest, AdapterResult, FieldMatch, TelcoAdapter } from "./types.js";
import type { Signal } from "../consent/consent.js";
import { OutboundClient, type MtlsOptions } from "./outbound.js";
import { dateDaysAgo } from "./params.js";

const ajv = new Ajv({ strict: true, allErrors: false });
const bool = (k: string) => ajv.compile({ type: "object", properties: { [k]: { type: "boolean" } }, required: [k], additionalProperties: false });
const vSwap = bool("swapped"), vFwd = bool("active");
const MR = { enum: ["true", "false", "not_available"] };
const vKyc = ajv.compile({ type: "object", additionalProperties: false, properties: {
  idDocumentMatch: MR, nameMatch: MR, givenNameMatch: MR, familyNameMatch: MR, addressMatch: MR, birthdateMatch: MR, emailMatch: MR, postalCodeMatch: MR, countryMatch: MR,
  nameMatchScore: { type: "integer", minimum: 0, maximum: 100 }, givenNameMatchScore: { type: "integer", minimum: 0, maximum: 100 }, familyNameMatchScore: { type: "integer", minimum: 0, maximum: 100 },
  addressMatchScore: { type: "integer", minimum: 0, maximum: 100 },
}, minProperties: 1 });
// Second-wave responses. Unknown properties are rejected; fields we deliberately do not use (country, timestamps, match rate) are tolerated but discarded.
const vRecycled = bool("phoneNumberRecycled"), vTenure = ajv.compile({ type: "object", required: ["tenureDateCheck"], properties: { tenureDateCheck: { type: "boolean" }, contractType: { type: "string", maxLength: 32 } }, additionalProperties: false });
const vLocation = ajv.compile({ type: "object", required: ["verificationResult"], additionalProperties: false, properties: {
  verificationResult: { enum: ["TRUE", "FALSE", "PARTIAL"] }, lastLocationTime: { type: "string", maxLength: 64 }, matchRate: { type: "integer", minimum: 1, maximum: 99 }, device: { type: "object", maxProperties: 4 } } });
const vRoaming = ajv.compile({ type: "object", required: ["roaming"], additionalProperties: false, properties: {
  roaming: { type: "boolean" }, lastStatusTime: { type: "string", maxLength: 64 }, countryCode: { type: "integer", minimum: 1, maximum: 999 }, countryName: { type: "array", maxItems: 8, items: { type: "string", maxLength: 64 } } } });
export const CAMARA_PATHS = { SIM_SWAP: "/sim-swap/v2/check", DEVICE_SWAP: "/device-swap/v1/check", CALL_FORWARDING: "/call-forwarding-signal/v0.5/check-unconditional-forwarding", KYC_MATCH: "/kyc-match/v0.3/match",
  NUMBER_RECYCLING: "/number-recycling/v0.3/check", KYC_TENURE: "/kyc-tenure/v0.3/check-tenure", DEVICE_LOCATION: "/location-verification/v3/verify", DEVICE_ROAMING: "/device-roaming-status/v1/retrieve" } as const;
const JSON_CT = /^application\/json/;

export class TelcoAAdapter implements TelcoAdapter {
  readonly supports = new Set<Signal>(["SIM_SWAP", "DEVICE_SWAP", "CALL_FORWARDING", "KYC_MATCH", "NUMBER_RECYCLING", "KYC_TENURE", "DEVICE_LOCATION", "DEVICE_ROAMING"]);
  private out: OutboundClient;
  constructor(readonly telcoId: string, baseUrl: string, allowList: string[], mtls: MtlsOptions, private timeoutMs = 2000) {
    this.out = new OutboundClient(baseUrl, allowList, mtls, timeoutMs);
  }
  async call(r: AdapterRequest): Promise<AdapterResult> {
    const t0 = performance.now();
    const done = (status: AdapterResult["status"], reason: string, fields?: Record<string, FieldMatch>): AdapterResult => ({ status, reason, telcoMs: Math.round(performance.now() - t0), ...(fields ? { fields } : {}) });
    if (!this.supports.has(r.signal)) return done("NOT_SUPPORTED", "signal not covered");
    const body = requestBody(r);
    if (!body) return done("UNAVAILABLE", "missing parameters");
    const f = await this.out.post(CAMARA_PATHS[r.signal], JSON.stringify(body), { "content-type": "application/json", "x-correlator": r.correlationId, accept: "application/json" }, JSON_CT);
    if (!f.ok) return done("UNAVAILABLE", f.reason);
    let parsed: unknown;
    try { parsed = JSON.parse(f.text); } catch { return done("UNAVAILABLE", "malformed json"); }
    if (r.signal === "SIM_SWAP" || r.signal === "DEVICE_SWAP") return vSwap(parsed) ? done((parsed as { swapped: boolean }).swapped ? "TRUE" : "FALSE", "ok") : done("UNAVAILABLE", "response failed schema validation");
    if (r.signal === "CALL_FORWARDING") return vFwd(parsed) ? done((parsed as { active: boolean }).active ? "TRUE" : "FALSE", "ok") : done("UNAVAILABLE", "response failed schema validation");
    if (r.signal === "NUMBER_RECYCLING") return vRecycled(parsed) ? done((parsed as { phoneNumberRecycled: boolean }).phoneNumberRecycled ? "TRUE" : "FALSE", "ok") : done("UNAVAILABLE", "response failed schema validation");
    if (r.signal === "KYC_TENURE") return vTenure(parsed) ? done((parsed as { tenureDateCheck: boolean }).tenureDateCheck ? "TRUE" : "FALSE", "ok") : done("UNAVAILABLE", "response failed schema validation");
    if (r.signal === "DEVICE_ROAMING") return vRoaming(parsed) ? done((parsed as { roaming: boolean }).roaming ? "TRUE" : "FALSE", "ok") : done("UNAVAILABLE", "response failed schema validation");   // country is discarded on purpose
    if (r.signal === "DEVICE_LOCATION") {
      if (!vLocation(parsed)) return done("UNAVAILABLE", "response failed schema validation");
      const v = (parsed as { verificationResult: string }).verificationResult;
      return v === "TRUE" ? done("TRUE", "ok") : v === "FALSE" ? done("FALSE", "ok") : done("UNAVAILABLE", "partial location match");     // PARTIAL is neither inside nor outside: never FALSE
    }
    if (!vKyc(parsed)) return done("UNAVAILABLE", "response failed schema validation");
    return kycResult(parsed as Record<string, unknown>, done);
  }
  async close() { await this.out.close(); }
}

/** Request body per signal, following the pinned CAMARA definitions. Returns null if a required parameter is missing (a platform bug, never sent). */
function requestBody(r: AdapterRequest): Record<string, unknown> | null {
  const p = r.params;
  switch (r.signal) {
    case "KYC_MATCH": return { phoneNumber: r.msisdn, ...(r.kyc ?? {}) };
    case "CALL_FORWARDING": return { phoneNumber: r.msisdn };
    case "NUMBER_RECYCLING": return p?.specifiedDate ? { phoneNumber: r.msisdn, specifiedDate: p.specifiedDate } : null;
    case "KYC_TENURE": return p?.minTenureDays ? { phoneNumber: r.msisdn, tenureDate: dateDaysAgo(p.minTenureDays) } : null;
    case "DEVICE_LOCATION": return p?.area ? { device: { phoneNumber: r.msisdn }, area: { areaType: "CIRCLE", center: { latitude: p.area.latitude, longitude: p.area.longitude }, radius: p.area.radiusMeters }, ...(p.maxAgeSeconds !== undefined ? { maxAge: p.maxAgeSeconds } : {}) } : null;
    case "DEVICE_ROAMING": return { device: { phoneNumber: r.msisdn } };
    default: return { phoneNumber: r.msisdn, maxAge: r.maxAgeHours ?? 240 };
  }
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
