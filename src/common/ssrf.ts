// Outbound-endpoint validation for admin-supplied telco/aggregator URLs (SSRF control). Used by the portal AND again when adapters are built.
import { isIP } from "node:net";

const BLOCKED_HOSTS = new Set(["metadata.google.internal", "metadata", "instance-data"]);
function ipv4Blocked(ip: string): boolean {
  const [a = 0, b = 0] = ip.split(".").map(Number);
  return a === 0 || a === 10 || a === 127 || (a === 100 && b >= 64 && b <= 127) || (a === 169 && b === 254) || (a === 172 && b >= 16 && b <= 31)
    || (a === 192 && b === 168) || (a === 192 && b === 0) || (a === 198 && (b === 18 || b === 19)) || a >= 224;
}
/** Connect-time check on a RESOLVED address (defeats DNS names that point at internal addresses and DNS rebinding, because it runs on the
 *  address the socket will actually use). IPv4-mapped/compatible IPv6, NAT64, 6to4 and Teredo forms are judged by the IPv4 address they carry. */
export function isBlockedAddress(addr: string, allowPrivate = false): boolean {
  const a = addr.toLowerCase().replace(/^\[|\]$/g, "");
  const v = isIP(a);
  if (v === 4) return allowPrivate ? false : ipv4Blocked(a);
  if (v !== 6) return true;                                          // not an IP at all: refuse
  if (allowPrivate) return false;
  const mapped = /^(?:0{0,4}:){0,5}(?:ffff:)?(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})$/.exec(a)?.[1];
  if (mapped) return ipv4Blocked(mapped);
  const hex = /^::ffff:([0-9a-f]{1,4}):([0-9a-f]{1,4})$/.exec(a);
  if (hex) { const n = (parseInt(hex[1]!, 16) << 16) | parseInt(hex[2]!, 16); return ipv4Blocked([n >>> 24, (n >>> 16) & 255, (n >>> 8) & 255, n & 255].join(".")); }
  return a === "::" || a === "::1" || /^f[cd]/.test(a) || /^fe[89ab]/.test(a) || a.startsWith("64:ff9b:") || a.startsWith("2002:") || a.startsWith("2001:0:") || a.startsWith("2001::") || a.startsWith("::ffff:") || a.startsWith("ff");
}
export interface EndpointCheck { ok: boolean; origin?: string; reason?: string }
/** https only; no credentials, fragments or odd ports/hosts; private/loopback/link-local/metadata addresses are refused
 *  (loopback hostnames only when the sandbox explicitly allows it). */
export function validateTelcoEndpoint(raw: string, opts: { allowLoopback?: boolean } = {}): EndpointCheck {
  let u: URL;
  try { u = new URL(raw); } catch { return { ok: false, reason: "not a valid URL" }; }
  if (u.protocol !== "https:") return { ok: false, reason: "https is required" };
  if (u.username || u.password) return { ok: false, reason: "credentials in URLs are not allowed" };
  if (u.hash) return { ok: false, reason: "fragments are not allowed" };
  const host = u.hostname.toLowerCase().replace(/^\[|\]$/g, "");
  // WHATWG parsing silently rewrites encoded hosts (2130706433, 0x7f000001, 127.1 -> 127.0.0.1). Compare with what was actually written and refuse any rewrite.
  const rawHost = /^https:\/\/(?:[^@/?#]*@)?(\[[^\]]+\]|[^/:?#]+)/i.exec(raw)?.[1]?.toLowerCase().replace(/^\[|\]$/g, "");
  if (rawHost === undefined || rawHost !== host) return { ok: false, reason: "host encodings are not allowed" };
  if (BLOCKED_HOSTS.has(host) || host.endsWith(".internal") || host.endsWith(".local") || host.endsWith(".localhost")) return { ok: false, reason: "internal host names are not allowed" };
  if (host === "localhost") return opts.allowLoopback ? { ok: true, origin: u.origin } : { ok: false, reason: "loopback is not allowed" };
  const v = isIP(host);
  if (v === 4) { if (host.startsWith("127.") && opts.allowLoopback) return { ok: true, origin: u.origin }; if (ipv4Blocked(host)) return { ok: false, reason: "private, loopback or link-local address" }; }
  if (v === 6) {
    if (host === "::1" && opts.allowLoopback) return { ok: true, origin: u.origin };
    if (host === "::" || host === "::1" || /^f[cd]/.test(host) || /^fe[89ab]/.test(host) || host.startsWith("::ffff:")) return { ok: false, reason: "private, loopback or link-local address" };
  }
  if (/^\d+$/.test(host) || /^0x/i.test(host) || /^[0-9.]+$/.test(host) && v !== 4) return { ok: false, reason: "numeric host encodings are not allowed" };   // 2130706433, 0x7f000001, 127.1
  if (!host.includes(".") && !v) return { ok: false, reason: "a fully qualified host name is required" };
  return { ok: true, origin: u.origin };
}
