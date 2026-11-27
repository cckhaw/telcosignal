// Telco A: CAMARA-style (SIM Swap r4.3 `check`). Telco responses are UNTRUSTED input.
import { Agent, request } from "undici";
import { Ajv } from "ajv";
import type { AdapterRequest, AdapterResult, TelcoAdapter } from "./types.js";
import type { Signal } from "../consent/consent.js";

const MAX_BODY = 1024;
const ajv = new Ajv({ strict: true, allErrors: false });
const validateCheck = ajv.compile({ type: "object", properties: { swapped: { type: "boolean" } }, required: ["swapped"], additionalProperties: false });

export interface MtlsOptions { ca: string; cert: string; key: string }
export class TelcoAAdapter implements TelcoAdapter {
  readonly supports = new Set<Signal>(["SIM_SWAP"]);
  private agent: Agent;
  private origin: string;
  constructor(readonly telcoId: string, baseUrl: string, allowList: string[], mtls: MtlsOptions, private timeoutMs = 2000) {
    const u = new URL(baseUrl);
    if (u.protocol !== "https:") throw new Error("telco endpoint must be https");
    if (!allowList.includes(u.origin)) throw new Error("telco endpoint not on the outbound allow-list");  // SSRF control
    this.origin = u.origin;
    // TLS verification is always on: server cert verified against the pinned CA; client cert presented (mTLS).
    this.agent = new Agent({ connect: { ca: mtls.ca, cert: mtls.cert, key: mtls.key, rejectUnauthorized: true, minVersion: "TLSv1.2" }, maxRedirections: 0 } as never);
  }
  async call(r: AdapterRequest): Promise<AdapterResult> {
    const t0 = performance.now();
    const done = (status: AdapterResult["status"], reason: string): AdapterResult => ({ status, reason, telcoMs: Math.round(performance.now() - t0) });
    if (!this.supports.has(r.signal)) return done("NOT_SUPPORTED", "signal not covered");
    try {
      const res = await request(`${this.origin}/sim-swap/v1/check`, {
        method: "POST", dispatcher: this.agent, signal: AbortSignal.timeout(this.timeoutMs),
        headers: { "content-type": "application/json", "x-correlator": r.correlationId, accept: "application/json" },
        body: JSON.stringify({ phoneNumber: r.msisdn, maxAge: r.maxAgeHours ?? 240 }),
        headersTimeout: this.timeoutMs, bodyTimeout: this.timeoutMs,
      });
      // Early exits destroy the stream; undici then emits an abort error event. Sink it so a hostile/slow telco cannot raise an unhandled error.
      res.body.on("error", () => undefined);
      if (res.statusCode !== 200) { res.body.destroy(); return done("UNAVAILABLE", `telco status ${res.statusCode}`); }   // 404/422 included: no existence signal
      if (!String(res.headers["content-type"] ?? "").toLowerCase().startsWith("application/json")) { res.body.destroy(); return done("UNAVAILABLE", "bad content type"); }
      const chunks: Buffer[] = []; let size = 0;
      for await (const c of res.body) {
        size += (c as Buffer).length;
        if (size > MAX_BODY) { res.body.destroy(); return done("UNAVAILABLE", "response too large"); }
        chunks.push(c as Buffer);
      }
      let parsed: unknown;
      try { parsed = JSON.parse(Buffer.concat(chunks).toString("utf8")); } catch { return done("UNAVAILABLE", "malformed json"); }
      if (!validateCheck(parsed)) return done("UNAVAILABLE", "response failed schema validation");
      return done((parsed as { swapped: boolean }).swapped ? "TRUE" : "FALSE", "ok");
    } catch (e) {
      const name = (e as Error).name;
      return done("UNAVAILABLE", name === "TimeoutError" || name === "AbortError" ? "timeout" : "transport error");
    }
  }
  async close() { await this.agent.close(); }
}
