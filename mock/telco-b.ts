// Mock Telco B: proprietary text protocol. Last digit: 1 Y, 2 hang, 3 HTTP 500, 4 garbage, 5 RC=14 (unknown subscriber),
// 6 header/CRLF injection attempt, 7 oversized, 8 RC=99, else N. Also verifies it received the documented request format.
import { startTlsMock, type MockTelco, type MockTls } from "./common.js";
export const startMockTelcoB = (tls: MockTls, port = 0): Promise<MockTelco> => startTlsMock(tls, (req, raw, res) => {
  const m = /^MSISDN=(\d{5,15});Q=(SIMCHG|CFWD);W=(\d{1,4})$/.exec(raw);
  if (req.method !== "POST" || req.url !== "/api/v2/subscriber/status" || !m) { res.writeHead(400, { "content-type": "text/plain" }).end("RC=01"); return; }
  const d = (m[1] as string).slice(-1);
  if (d === "2") return;
  if (d === "3") { res.writeHead(500, { "content-type": "text/plain" }).end("RC=99;DETAIL=stacktrace secret-internal-detail"); return; }
  res.writeHead(200, { "content-type": "text/plain" });
  if (d === "4") return void res.end("<html>nope</html>");
  if (d === "5") return void res.end("RC=14");
  if (d === "6") return void res.end("RC=00;FLAG=N\r\nRC=00;FLAG=Y");
  if (d === "7") return void res.end("RC=00;FLAG=N" + " ".repeat(2000) + "X");
  if (d === "8") return void res.end("RC=99");
  res.end(`RC=00;FLAG=${d === "1" ? "Y" : "N"}`);
}, port);
