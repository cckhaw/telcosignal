// Mock Telco A: CAMARA APIs at the pinned paths. Behaviour is driven by the LAST digit of the synthetic number:
// 1 positive, 2 hang, 3 HTTP 500, 4 malformed JSON, 5 HTTP 404, 6 wrong type, 7 oversized/extra fields, 8 KYC not_available / location PARTIAL, else negative.
// Second-wave signals read the number from phoneNumber (recycling, tenure) or device.phoneNumber (location, roaming).
import { startTlsMock, type MockTelco, type MockTls } from "./common.js";
export type { MockTelco } from "./common.js";
export const startMockTelcoA = (tls: MockTls, port = 0): Promise<MockTelco> => startTlsMock(tls, (req, raw, res) => {
  let b: Record<string, unknown> = {};
  try { b = JSON.parse(raw) as Record<string, unknown>; } catch { /* handled below */ }
  const dev = (b["device"] ?? {}) as Record<string, unknown>;
  const d = String(b["phoneNumber"] ?? dev["phoneNumber"] ?? "").slice(-1);
  const url = req.url ?? "";
  const kind = url === "/sim-swap/v2/check" || url === "/device-swap/v1/check" ? "swap" : url === "/call-forwarding-signal/v0.5/check-unconditional-forwarding" ? "fwd" : url === "/kyc-match/v0.3/match" ? "kyc"
    : url === "/number-recycling/v0.3/check" ? "recycle" : url === "/kyc-tenure/v0.3/check-tenure" ? "tenure" : url === "/location-verification/v3/verify" ? "loc" : url === "/device-roaming-status/v1/retrieve" ? "roam" : null;
  if (req.method !== "POST" || !kind) { res.writeHead(404).end(); return; }
  if (d === "2") return;
  // Request shape is checked against the pinned definitions: a malformed request is a 400, so a wrongly built adapter request can never look like a success.
  const DATE = /^\d{4}-\d{2}-\d{2}$/, area = (b["area"] ?? {}) as Record<string, unknown>, ctr = (area["center"] ?? {}) as Record<string, unknown>;
  const shapeOk = kind === "recycle" ? DATE.test(String(b["specifiedDate"])) && typeof b["phoneNumber"] === "string"
    : kind === "tenure" ? DATE.test(String(b["tenureDate"])) && typeof b["phoneNumber"] === "string"
    : kind === "loc" ? area["areaType"] === "CIRCLE" && typeof ctr["latitude"] === "number" && typeof ctr["longitude"] === "number" && typeof area["radius"] === "number" && typeof dev["phoneNumber"] === "string"
    : kind === "roam" ? typeof dev["phoneNumber"] === "string" : true;
  if (!shapeOk) { res.writeHead(400, { "content-type": "application/json" }).end('{"status":400,"code":"INVALID_ARGUMENT"}'); return; }
  if (d === "9") { res.writeHead(302, { location: "https://evil.invalid/steal" }).end(); return; }       // redirects must never be followed
  if (d === "3") { res.writeHead(500, { "content-type": "application/json" }).end('{"status":500,"code":"INTERNAL","message":"boom: secret-internal-detail"}'); return; }
  if (d === "5") { res.writeHead(404, { "content-type": "application/json" }).end('{"status":404,"code":"IDENTIFIER_NOT_FOUND"}'); return; }
  res.writeHead(200, { "content-type": "application/json" });
  if (d === "4") return void res.end("{not json");
  if (d === "6") return void res.end(kind === "swap" ? '{"swapped":"false"}' : kind === "fwd" ? '{"active":"no"}' : kind === "recycle" ? '{"phoneNumberRecycled":"false"}' : kind === "tenure" ? '{"tenureDateCheck":1}' : kind === "loc" ? '{"verificationResult":"MAYBE"}' : kind === "roam" ? '{"roaming":"no"}' : '{"nameMatch":"maybe"}');
  if (d === "7") return void res.end(JSON.stringify({ swapped: false, active: false, nameMatch: "true", junk: "x".repeat(5000) }));
  if (kind === "swap") return void res.end(JSON.stringify({ swapped: d === "1" }));
  if (kind === "fwd") return void res.end(JSON.stringify({ active: d === "1" }));
  if (kind === "recycle") return void res.end(JSON.stringify({ phoneNumberRecycled: d === "1" }));
  if (kind === "tenure") return void res.end(JSON.stringify({ tenureDateCheck: d === "1" }));
  if (kind === "roam") return void res.end(JSON.stringify({ roaming: d === "1", ...(d === "1" ? { countryCode: 65, countryName: ["SG"] } : {}) }));
  if (kind === "loc") return void res.end(JSON.stringify({ verificationResult: d === "8" ? "PARTIAL" : d === "1" ? "TRUE" : "FALSE", lastLocationTime: "2026-11-28T00:00:00Z" }));
  if (d === "8") return void res.end(JSON.stringify({ nameMatch: "not_available" }));
  res.end(JSON.stringify(d === "1" ? { nameMatch: "false", idDocumentMatch: "true" } : { nameMatch: "true", idDocumentMatch: "true", nameMatchScore: 97 }));
}, port);
