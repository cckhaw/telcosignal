// Shared TLS mock-server plumbing. SYNTHETIC. Requires client certificates (mTLS from the platform).
import https from "node:https";
import type { IncomingMessage, ServerResponse } from "node:http";
import type { AddressInfo } from "node:net";
export interface MockTelco { port: number; calls: number; lastBody: string | null; lastPath: string | null; close(): Promise<void> }
export interface MockTls { cert: string; key: string; clientCa: string }
export async function startTlsMock(tls: MockTls, handle: (req: IncomingMessage, raw: string, res: ServerResponse) => void, port = 0): Promise<MockTelco> {
  const st = { calls: 0, lastBody: null as string | null, lastPath: null as string | null };
  const srv = https.createServer({ cert: tls.cert, key: tls.key, ca: tls.clientCa, requestCert: true, rejectUnauthorized: true }, (req, res) => {
    const chunks: Buffer[] = [];
    req.on("data", (c: Buffer) => chunks.push(c));
    req.on("end", () => { st.calls++; const raw = Buffer.concat(chunks).toString("utf8"); st.lastBody = raw; st.lastPath = req.url ?? null; const lat = Number(process.env["MOCK_LATENCY_MS"] ?? 0); if (lat > 0) setTimeout(() => handle(req, raw, res), lat); else handle(req, raw, res); });
  });
  await new Promise<void>((r) => srv.listen(port, process.env["MOCK_BIND"] ?? "127.0.0.1", r));
  return {
    port: (srv.address() as AddressInfo).port,
    get calls() { return st.calls; }, get lastBody() { return st.lastBody; }, get lastPath() { return st.lastPath; },
    close: () => new Promise<void>((r) => { srv.closeAllConnections(); srv.close(() => r()); }),
  };
}
