// Sandbox runner for the three mock telcos (SYNTHETIC). Ports/certs come from the environment.
import { readFileSync } from "node:fs";
import { startMockTelcoA } from "./telco-a.js";
import { startMockTelcoB } from "./telco-b.js";
import { startMockAggregator } from "./aggregator.js";
const f = (n: string) => readFileSync(process.env[n] ?? (() => { throw new Error(`missing ${n}`); })(), "utf8");
const tls = { cert: f("MOCK_CERT_FILE"), key: f("MOCK_KEY_FILE"), clientCa: f("MOCK_CLIENT_CA_FILE") };
await startMockTelcoA(tls, Number(process.env["MOCK_A_PORT"] ?? 9101));
await startMockTelcoB(tls, Number(process.env["MOCK_B_PORT"] ?? 9102));
await startMockAggregator(tls, Number(process.env["MOCK_C_PORT"] ?? 9103));
console.log("mock telcos A/B/aggregator listening (synthetic)");
