// Mock Telco A: CAMARA SIM Swap `check` (pinned r4.3). SYNTHETIC. Behaviour is driven by the last digit of the synthetic number.
import https from "node:https";
import type { AddressInfo } from "node:net";

export interface MockTelco { port: number; calls: number; lastBody: string | null; close(): Promise<void> }
/** digit -> behaviour: 1 swapped, 2 hang (timeout), 3 HTTP 500, 4 malformed JSON, 5 HTTP 404, 6 wrong-type field, 7 extra field + huge, else not swapped */
export async function startMockTelcoA(tls: { cert: string; key: string; clientCa: string }): Promise<MockTelco> {
  const state = { calls: 0, lastBody: null as string | null };
  const srv = https.createServer({ cert: tls.cert, key: tls.key, ca: tls.clientCa, requestCert: true, rejectUnauthorized: true }, (req, res) => {
    const chunks: Buffer[] = [];
    req.on("data", (c: Buffer) => chunks.push(c));
    req.on("end", () => {
      state.calls++;
      const raw = Buffer.concat(chunks).toString("utf8");
      state.lastBody = raw;
      let n = "";
      try { n = (JSON.parse(raw) as { phoneNumber?: string }).phoneNumber ?? ""; } catch { /* ignore */ }
      const d = n.slice(-1);
      if (req.method !== "POST" || req.url !== "/sim-swap/v1/check") { res.writeHead(404).end(); return; }
      if (d === "2") return;                       // never respond
      if (d === "3") { res.writeHead(500, { "content-type": "application/json" }).end('{"status":500,"code":"INTERNAL","message":"boom: secret-internal-detail"}'); return; }
      if (d === "5") { res.writeHead(404, { "content-type": "application/json" }).end('{"status":404,"code":"IDENTIFIER_NOT_FOUND"}'); return; }
      res.writeHead(200, { "content-type": "application/json" });
      if (d === "4") res.end("{not json");
      else if (d === "6") res.end('{"swapped":"false"}');
      else if (d === "7") res.end(JSON.stringify({ swapped: false, junk: "x".repeat(5000) }));
      else res.end(JSON.stringify({ swapped: d === "1" }));
    });
  });
  await new Promise<void>((r) => srv.listen(0, "127.0.0.1", r));
  return {
    port: (srv.address() as AddressInfo).port,
    get calls() { return state.calls; }, get lastBody() { return state.lastBody; },
    close: () => new Promise<void>((r) => { srv.closeAllConnections(); srv.close(() => r()); }),
  };
}
