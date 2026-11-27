// Telco B: proprietary format. Request: text/plain "MSISDN=<digits>;Q=<SIMCHG|CFWD>;W=<hours>".
// Response: text/plain "RC=<2 digits>[;FLAG=<Y|N>]". Parsed with one strict anchored pattern; everything else is UNAVAILABLE.
import type { AdapterRequest, AdapterResult, TelcoAdapter } from "./types.js";
import type { Signal } from "../consent/consent.js";
import { OutboundClient, type MtlsOptions } from "./outbound.js";

const QUERY: Partial<Record<Signal, string>> = { SIM_SWAP: "SIMCHG", CALL_FORWARDING: "CFWD" };
const RESPONSE = /^RC=(\d{2})(?:;FLAG=([YN]))?$/;
export function parseTelcoB(text: string): { rc: string; flag?: "Y" | "N" } | null {
  const m = RESPONSE.exec(text.trim());      // no multiline flag: CR/LF injection cannot smuggle extra fields
  if (!m || text.trim().length > 32) return null;
  return { rc: m[1] as string, ...(m[2] ? { flag: m[2] as "Y" | "N" } : {}) };
}
export class TelcoBAdapter implements TelcoAdapter {
  readonly supports = new Set<Signal>(["SIM_SWAP", "CALL_FORWARDING"]);
  private out: OutboundClient;
  constructor(readonly telcoId: string, baseUrl: string, allowList: string[], mtls: MtlsOptions, timeoutMs = 2000) {
    this.out = new OutboundClient(baseUrl, allowList, mtls, timeoutMs, 256);
  }
  async call(r: AdapterRequest): Promise<AdapterResult> {
    const t0 = performance.now();
    const done = (status: AdapterResult["status"], reason: string): AdapterResult => ({ status, reason, telcoMs: Math.round(performance.now() - t0) });
    const q = QUERY[r.signal];
    if (!q) return done("NOT_SUPPORTED", "signal not covered");
    const digits = r.msisdn.replace(/^\+/, "");
    if (!/^[1-9][0-9]{4,14}$/.test(digits)) return done("UNAVAILABLE", "bad number");
    const f = await this.out.post("/api/v2/subscriber/status", `MSISDN=${digits};Q=${q};W=${r.maxAgeHours ?? 240}`, { "content-type": "text/plain", accept: "text/plain" }, /^text\/plain/);
    if (!f.ok) return done("UNAVAILABLE", f.reason);
    const p = parseTelcoB(f.text);
    if (!p) return done("UNAVAILABLE", "unparseable response");
    if (p.rc !== "00" || !p.flag) return done("UNAVAILABLE", `telco rc ${p.rc}`);       // rc 14 (unknown subscriber) etc. are indistinguishable from failures
    return done(p.flag === "Y" ? "TRUE" : "FALSE", "ok");
  }
  async close() { await this.out.close(); }
}
