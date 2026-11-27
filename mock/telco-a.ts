// Mock Telco A: CAMARA APIs at the pinned paths. Behaviour is driven by the LAST digit of the synthetic number:
// 1 positive, 2 hang, 3 HTTP 500, 4 malformed JSON, 5 HTTP 404, 6 wrong type, 7 oversized/extra fields, 8 KYC not_available, else negative.
import { startTlsMock, type MockTelco, type MockTls } from "./common.js";
export type { MockTelco } from "./common.js";
export const startMockTelcoA = (tls: MockTls, port = 0): Promise<MockTelco> => startTlsMock(tls, (req, raw, res) => {
  let b: Record<string, unknown> = {};
  try { b = JSON.parse(raw) as Record<string, unknown>; } catch { /* handled below */ }
  const d = String(b["phoneNumber"] ?? "").slice(-1);
  const url = req.url ?? "";
  const kind = url === "/sim-swap/v2/check" || url === "/device-swap/v1/check" ? "swap" : url === "/call-forwarding-signal/v0.5/check-unconditional-forwarding" ? "fwd" : url === "/kyc-match/v0.3/match" ? "kyc" : null;
  if (req.method !== "POST" || !kind) { res.writeHead(404).end(); return; }
  if (d === "2") return;
  if (d === "9") { res.writeHead(302, { location: "https://evil.invalid/steal" }).end(); return; }       // redirects must never be followed
  if (d === "3") { res.writeHead(500, { "content-type": "application/json" }).end('{"status":500,"code":"INTERNAL","message":"boom: secret-internal-detail"}'); return; }
  if (d === "5") { res.writeHead(404, { "content-type": "application/json" }).end('{"status":404,"code":"IDENTIFIER_NOT_FOUND"}'); return; }
  res.writeHead(200, { "content-type": "application/json" });
  if (d === "4") return void res.end("{not json");
  if (d === "6") return void res.end(kind === "swap" ? '{"swapped":"false"}' : kind === "fwd" ? '{"active":"no"}' : '{"nameMatch":"maybe"}');
  if (d === "7") return void res.end(JSON.stringify({ swapped: false, active: false, nameMatch: "true", junk: "x".repeat(5000) }));
  if (kind === "swap") return void res.end(JSON.stringify({ swapped: d === "1" }));
  if (kind === "fwd") return void res.end(JSON.stringify({ active: d === "1" }));
  if (d === "8") return void res.end(JSON.stringify({ nameMatch: "not_available" }));
  res.end(JSON.stringify(d === "1" ? { nameMatch: "false", idDocumentMatch: "true" } : { nameMatch: "true", idDocumentMatch: "true", nameMatchScore: 97 }));
}, port);
