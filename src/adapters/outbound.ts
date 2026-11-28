// Shared hardened outbound client for every telco/aggregator adapter. All telco responses are UNTRUSTED input.
import { Agent, request } from "undici";
import { lookup as dnsLookup } from "node:dns";
import { isIP } from "node:net";
import { isBlockedAddress } from "../common/ssrf.js";

export interface MtlsOptions { ca: string; cert: string; key: string; allowPrivateAddresses?: boolean }   // allowPrivateAddresses: sandbox only (the mock telcos are on loopback)
export type Fetched = { ok: true; status: number; text: string } | { ok: false; reason: string };

export class OutboundClient {
  private agent: Agent;
  readonly origin: string;
  constructor(baseUrl: string, allowList: readonly string[], mtls: MtlsOptions, private readonly timeoutMs: number, private readonly maxBody = 2048) {
    const u = new URL(baseUrl);
    if (u.protocol !== "https:") throw new Error("telco endpoint must be https");
    if (!allowList.includes(u.origin)) throw new Error("telco endpoint not on the outbound allow-list");   // SSRF control
    this.origin = u.origin;
    const allowPrivate = mtls.allowPrivateAddresses === true;
    const host = u.hostname.replace(/^\[|\]$/g, "");
    if (isIP(host) && isBlockedAddress(host, allowPrivate)) throw new Error("telco endpoint address is private, loopback or link-local");
    // The address the socket really connects to is checked AFTER name resolution, every time (internal addresses, DNS rebinding).
    // If ANY resolved address is blocked the whole name is refused (a mixed answer is a rebinding signal).
    const lookup = (hostname: string, opts: { all?: boolean; family?: number }, cb: (...a: unknown[]) => void): void => {
      dnsLookup(hostname, { ...(opts as object), all: true, verbatim: true } as never, ((err: Error | null, addrs: Array<{ address: string; family: number }>) => {
        if (err) return cb(err, "", 0);
        if (!addrs.length || addrs.some((x) => isBlockedAddress(x.address, allowPrivate))) return cb(new Error("telco host resolves to a blocked address"), "", 0);
        return opts.all ? cb(null, addrs) : cb(null, addrs[0]!.address, addrs[0]!.family);
      }) as never);
    };
    // TLS verification is always on: server cert verified against the pinned CA; client cert presented (mTLS). Redirects are never followed.
    this.agent = new Agent({ connect: { ca: mtls.ca, cert: mtls.cert, key: mtls.key, rejectUnauthorized: true, minVersion: "TLSv1.2", lookup }, maxRedirections: 0 } as never);
  }
  /** POST with hard time and size limits. Never throws. Non-200, wrong content-type, oversized or slow responses => ok:false. */
  async post(path: string, body: string, headers: Record<string, string>, accept: RegExp): Promise<Fetched> {
    if (!/^\/[A-Za-z0-9._/-]+$/.test(path)) return { ok: false, reason: "bad path" };
    try {
      const res = await request(`${this.origin}${path}`, {
        method: "POST", dispatcher: this.agent, signal: AbortSignal.timeout(this.timeoutMs), headers, body,
        headersTimeout: this.timeoutMs, bodyTimeout: this.timeoutMs,
      });
      res.body.on("error", () => undefined);      // early destroy emits an abort event; sink it (no unhandled errors from a hostile peer)
      if (res.statusCode !== 200) { res.body.destroy(); return { ok: false, reason: `telco status ${res.statusCode}` }; }   // 404/422 included: no existence signal
      if (!accept.test(String(res.headers["content-type"] ?? "").toLowerCase())) { res.body.destroy(); return { ok: false, reason: "bad content type" }; }
      const chunks: Buffer[] = []; let size = 0;
      for await (const c of res.body) {
        size += (c as Buffer).length;
        if (size > this.maxBody) { res.body.destroy(); return { ok: false, reason: "response too large" }; }
        chunks.push(c as Buffer);
      }
      return { ok: true, status: 200, text: Buffer.concat(chunks).toString("utf8") };
    } catch (e) {
      const n = (e as Error).name;
      return { ok: false, reason: n === "TimeoutError" || n === "AbortError" ? "timeout" : "transport error" };
    }
  }
  async close() { await this.agent.close(); }
}
