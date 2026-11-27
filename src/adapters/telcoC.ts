// Telco C via a (mock) aggregator. The aggregator is NOT trusted: the response must echo our requestId and the carrier we
// asked for, otherwise it is discarded (prevents answers for another request/carrier being accepted).
import { randomUUID } from "node:crypto";
import { Ajv } from "ajv";
import type { AdapterRequest, AdapterResult, FieldMatch, TelcoAdapter } from "./types.js";
import type { Signal } from "../consent/consent.js";
import { OutboundClient, type MtlsOptions } from "./outbound.js";
import { kycResult } from "./telcoA.js";

const ajv = new Ajv({ strict: true, allErrors: false });
const MR = { enum: ["true", "false", "not_available"] };
const vResp = ajv.compile({
  type: "object", additionalProperties: false, required: ["requestId", "carrier", "status"],
  properties: {
    requestId: { type: "string", maxLength: 64 }, carrier: { type: "string", maxLength: 32 }, status: { enum: ["OK", "ERROR"] },
    result: { type: "object", additionalProperties: false, properties: { value: { type: "boolean" }, fields: { type: "object", additionalProperties: MR, maxProperties: 12 } } },
  },
});
const SIGNAL_NAME: Partial<Record<Signal, string>> = { SIM_SWAP: "SIM_SWAP", DEVICE_SWAP: "DEVICE_SWAP", KYC_MATCH: "KYC_MATCH" };
export class TelcoCAdapter implements TelcoAdapter {
  readonly supports = new Set<Signal>(["SIM_SWAP", "DEVICE_SWAP", "KYC_MATCH"]);
  private out: OutboundClient;
  constructor(readonly telcoId: string, private readonly carrier: string, aggregatorUrl: string, allowList: string[], mtls: MtlsOptions, timeoutMs = 2000) {
    this.out = new OutboundClient(aggregatorUrl, allowList, mtls, timeoutMs, 2048);
  }
  async call(r: AdapterRequest): Promise<AdapterResult> {
    const t0 = performance.now();
    const done = (status: AdapterResult["status"], reason: string, fields?: Record<string, FieldMatch>): AdapterResult => ({ status, reason, telcoMs: Math.round(performance.now() - t0), ...(fields ? { fields } : {}) });
    const sig = SIGNAL_NAME[r.signal];
    if (!sig) return done("NOT_SUPPORTED", "signal not covered");
    const requestId = randomUUID();
    const f = await this.out.post("/agg/v1/query", JSON.stringify({ requestId, carrier: this.carrier, signal: sig, msisdn: r.msisdn, params: { maxAge: r.maxAgeHours ?? 240, ...(r.kyc ?? {}) } }),
      { "content-type": "application/json", accept: "application/json" }, /^application\/json/);
    if (!f.ok) return done("UNAVAILABLE", f.reason);
    let p: unknown;
    try { p = JSON.parse(f.text); } catch { return done("UNAVAILABLE", "malformed json"); }
    if (!vResp(p)) return done("UNAVAILABLE", "response failed schema validation");
    const x = p as { requestId: string; carrier: string; status: string; result?: { value?: boolean; fields?: Record<string, string> } };
    if (x.requestId !== requestId || x.carrier !== this.carrier) return done("UNAVAILABLE", "aggregator response not bound to this request");
    if (x.status !== "OK" || !x.result) return done("UNAVAILABLE", "aggregator error");
    if (sig === "KYC_MATCH") return x.result.fields ? kycResult(Object.fromEntries(Object.entries(x.result.fields).map(([k, v]) => [`${k}Match`, v])), done) : done("UNAVAILABLE", "no fields");
    return typeof x.result.value === "boolean" ? done(x.result.value ? "TRUE" : "FALSE", "ok") : done("UNAVAILABLE", "no value");
  }
  async close() { await this.out.close(); }
}
