// Mock aggregator in front of Telco C. Last digit: 1 true, 2 hang, 3 HTTP 500, 4 wrong requestId echoed, 5 wrong carrier echoed,
// 6 status ERROR, 7 extra/huge fields, 8 KYC not_available, 9 hostile strings (script/prototype keys), else false.
import { startTlsMock, type MockTelco, type MockTls } from "./common.js";
export const startMockAggregator = (tls: MockTls, port = 0): Promise<MockTelco> => startTlsMock(tls, (req, raw, res) => {
  let b: Record<string, unknown>;
  try { b = JSON.parse(raw) as Record<string, unknown>; } catch { res.writeHead(400).end(); return; }
  if (req.method !== "POST" || req.url !== "/agg/v1/query") { res.writeHead(404).end(); return; }
  const d = String(b["msisdn"] ?? "").slice(-1), signal = b["signal"];
  const base = { requestId: b["requestId"], carrier: b["carrier"], status: "OK" };
  if (d === "2") return;
  if (d === "3") { res.writeHead(500, { "content-type": "application/json" }).end('{"error":"internal secret-internal-detail"}'); return; }
  res.writeHead(200, { "content-type": "application/json" });
  if (d === "4") return void res.end(JSON.stringify({ ...base, requestId: "00000000-0000-4000-8000-000000000000", result: { value: false } }));
  if (d === "5") return void res.end(JSON.stringify({ ...base, carrier: "telco-evil", result: { value: false } }));
  if (d === "6") return void res.end(JSON.stringify({ ...base, status: "ERROR" }));
  if (d === "7") return void res.end(JSON.stringify({ ...base, result: { value: false }, junk: "x".repeat(4000) }));
  if (d === "9") return void res.end(`{"requestId":${JSON.stringify(b["requestId"])},"carrier":${JSON.stringify(b["carrier"])},"status":"OK","result":{"value":false},"__proto__":{"polluted":true},"note":"<script>alert(1)</script>"}`);
  if (signal === "KYC_MATCH") return void res.end(JSON.stringify({ ...base, result: { fields: d === "8" ? { name: "not_available" } : d === "1" ? { name: "false" } : { name: "true", idDocument: "true" } } }));
  const prm = (b["params"] ?? {}) as Record<string, unknown>, DATE = /^\d{4}-\d{2}-\d{2}$/;
  if ((signal === "NUMBER_RECYCLING" && !DATE.test(String(prm["specifiedDate"]))) || (signal === "KYC_TENURE" && !DATE.test(String(prm["tenureDate"])))) return void res.end(JSON.stringify({ ...base, status: "ERROR" }));
  res.end(JSON.stringify({ ...base, result: { value: d === "1" } }));
}, port);
