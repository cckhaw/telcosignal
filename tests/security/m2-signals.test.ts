import { describe, it, expect, beforeAll, afterAll } from "vitest";
import { createHash } from "node:crypto";
import { readFileSync } from "node:fs";
import { startHarness, num, numB, numC, type Harness, type Json } from "../helpers/harness.js";
import { subjectHash } from "../../src/consent/consent.js";
import { TelcoAAdapter, CAMARA_PATHS } from "../../src/adapters/telcoA.js";
import { TelcoBAdapter, parseTelcoB } from "../../src/adapters/telcoB.js";
import { startMockTelcoA } from "../../mock/telco-a.js";

let h: Harness;
beforeAll(async () => { h = await startHarness(); });
afterAll(async () => { await h.stop(); });

const base = (n: string, ref: string) => ({ phoneNumber: n, consentRef: ref, purposeCode: "FRAUD_PREVENTION" });
const SIG_PATH = { SIM_SWAP: "sim-swap", DEVICE_SWAP: "device-swap", CALL_FORWARDING: "call-forwarding", KYC_MATCH: "kyc-match" } as const;
async function ask(signal: keyof typeof SIG_PATH, n: string, extra: Record<string, unknown> = {}, c = h.bankA): Promise<{ status: number; json: Json }> {
  const consent = await h.consent(c, n);
  return h.call(c, "POST", `/v1/signals/${SIG_PATH[signal]}/check`, { body: { ...base(n, consent.ref), ...extra } });
}
const KYC = { name: "Synthetic Person", idDocument: "SYN-ID-0001" };

describe("every signal works end to end on the telcos that cover it", () => {
  it.each([["SIM_SWAP", num, "A"], ["DEVICE_SWAP", num, "A"], ["CALL_FORWARDING", num, "A"], ["SIM_SWAP", numB, "B"], ["CALL_FORWARDING", numB, "B"], ["SIM_SWAP", numC, "C"], ["DEVICE_SWAP", numC, "C"]] as const)(
    "%s via telco (%#): TRUE for a positive, FALSE for a negative", async (signal, gen, _telco) => {
      void _telco;
      expect((await ask(signal, gen("1", "0200"))).json.result).toBe("TRUE");
      expect((await ask(signal, gen("0", "0200"))).json.result).toBe("FALSE");
    });
  it("KYC match via A and C: TRUE when every field matches, FALSE on a mismatch, per-field detail returned", async () => {
    for (const gen of [num, numC]) {
      const ok = await ask("KYC_MATCH", gen("0", "0201"), KYC);
      expect(ok.json.result).toBe("TRUE"); expect(ok.json.fields).toMatchObject({ idDocument: "MATCH" });
      const bad = await ask("KYC_MATCH", gen("1", "0201"), KYC);
      expect(bad.json.result).toBe("FALSE"); expect(bad.json.fields.name).toBe("NO_MATCH");
    }
  });
  it("KYC: not_available is UNAVAILABLE, never a 'match'", async () => {
    expect((await ask("KYC_MATCH", num("8", "0202"), KYC)).json.result).toBe("UNAVAILABLE");
    expect((await ask("KYC_MATCH", numC("8", "0202"), KYC)).json.result).toBe("UNAVAILABLE");
  });
});

describe("routing, number porting and coverage", () => {
  it("routes by prefix to the right telco using that telco's own protocol", async () => {
    const [a0, b0, c0] = [h.telco.calls, h.telcoB.calls, h.aggregator.calls];
    await ask("SIM_SWAP", num("0", "0210"));
    expect([h.telco.calls - a0, h.telcoB.calls - b0, h.aggregator.calls - c0]).toEqual([1, 0, 0]);
    expect(h.telco.lastPath).toBe("/sim-swap/v2/check");
    await ask("SIM_SWAP", numB("0", "0210"));
    expect([h.telco.calls - a0, h.telcoB.calls - b0, h.aggregator.calls - c0]).toEqual([1, 1, 0]);
    expect(h.telcoB.lastBody).toMatch(/^MSISDN=\d+;Q=SIMCHG;W=240$/);
    await ask("SIM_SWAP", numC("0", "0210"));
    expect([h.telco.calls - a0, h.telcoB.calls - b0, h.aggregator.calls - c0]).toEqual([1, 1, 1]);
    expect(JSON.parse(h.aggregator.lastBody!).signal).toBe("SIM_SWAP");
  });
  it("PORTING: a number ported from A's range to B is routed to B; its neighbour still goes to A", async () => {
    const ported = num("1", "0220"), neighbour = num("1", "0221");
    await h.migrator.query("INSERT INTO porting(subject_hash, telco_id, effective_from) VALUES ($1,'telco-b', now() - interval '1 hour')", [await subjectHash(h.kms, ported)]);
    const [a0, b0] = [h.telco.calls, h.telcoB.calls];
    const r = await ask("SIM_SWAP", ported);
    expect(r.json.result).toBe("TRUE");                             // telco B answers 'Y' for a trailing 1, proving B served it
    expect([h.telco.calls - a0, h.telcoB.calls - b0]).toEqual([0, 1]);
    const r2 = await ask("SIM_SWAP", neighbour);
    expect(r2.json.result).toBe("TRUE"); expect(h.telco.calls - a0).toBe(1);
  });
  it("PORTING: effective-dated (a future port is ignored) and the latest effective port wins", async () => {
    const n = num("0", "0222"); const hash = await subjectHash(h.kms, n);
    await h.migrator.query("INSERT INTO porting(subject_hash, telco_id, effective_from) VALUES ($1,'telco-c', now() + interval '1 day')", [hash]);
    const [a0, c0] = [h.telco.calls, h.aggregator.calls];
    await ask("SIM_SWAP", n);
    expect([h.telco.calls - a0, h.aggregator.calls - c0]).toEqual([1, 0]);               // future port not yet effective
    await h.migrator.query("INSERT INTO porting(subject_hash, telco_id, effective_from) VALUES ($1,'telco-b', now() - interval '2 days'), ($1,'telco-c', now() - interval '1 day')", [hash]);
    const [b1, c1] = [h.telcoB.calls, h.aggregator.calls];
    await ask("SIM_SWAP", n);
    expect([h.telcoB.calls - b1, h.aggregator.calls - c1]).toEqual([0, 1]);              // newest effective port (C) wins over older (B)
  });
  it("porting data holds only keyed hashes, never numbers", async () => {
    const { rows } = await h.migrator.query("SELECT * FROM porting");
    expect(JSON.stringify(rows.map((r) => ({ ...r, subject_hash: "[bytes]" })))).not.toMatch(/\+?60999/);
    await expect(h.pool.query("INSERT INTO porting(subject_hash, telco_id, effective_from) VALUES ($1,'telco-a', now())", [Buffer.alloc(32)])).rejects.toThrow(/permission denied/i);
  });
  it("NOT_SUPPORTED (never FALSE) when the telco does not cover the signal; no telco call; not billed", async () => {
    const [a0, b0, c0] = [h.telco.calls, h.telcoB.calls, h.aggregator.calls];
    expect((await ask("DEVICE_SWAP", numB("0", "0230"))).json.result).toBe("NOT_SUPPORTED");
    expect((await ask("KYC_MATCH", numB("0", "0230"), KYC)).json.result).toBe("NOT_SUPPORTED");
    expect((await ask("CALL_FORWARDING", numC("0", "0230"))).json.result).toBe("NOT_SUPPORTED");
    expect([h.telco.calls - a0, h.telcoB.calls - b0, h.aggregator.calls - c0]).toEqual([0, 0, 0]);
    const { rows } = await h.migrator.query("SELECT billable FROM usage_record WHERE outcome='NOT_SUPPORTED'");
    expect(rows.length).toBeGreaterThanOrEqual(3); expect(rows.every((r) => r.billable === false)).toBe(true);
  });
  it("coverage and registry are enforced at runtime: removing coverage or disabling a signal stops calls", async () => {
    await h.migrator.query("DELETE FROM telco_signal_coverage WHERE telco_id='telco-a' AND signal='CALL_FORWARDING'");
    const a0 = h.telco.calls;
    expect((await ask("CALL_FORWARDING", num("1", "0231"))).json.result).toBe("NOT_SUPPORTED");
    await h.migrator.query("UPDATE signals SET enabled=false WHERE id='DEVICE_SWAP'");
    expect((await ask("DEVICE_SWAP", num("1", "0231"))).json.result).toBe("UNAVAILABLE");
    expect(h.telco.calls).toBe(a0);
    await h.migrator.query("UPDATE signals SET enabled=true WHERE id='DEVICE_SWAP'");
    await h.migrator.query("INSERT INTO telco_signal_coverage VALUES ('telco-a','CALL_FORWARDING')");
  });
  it("a suspended telco is not routed to (UNAVAILABLE)", async () => {
    await h.migrator.query("UPDATE telcos SET state='suspended' WHERE id='telco-b'");
    const b0 = h.telcoB.calls;
    expect((await ask("SIM_SWAP", numB("1", "0232"))).json.result).toBe("UNAVAILABLE");
    expect(h.telcoB.calls).toBe(b0);
    await h.migrator.query("UPDATE telcos SET state='active' WHERE id='telco-b'");
  });
  it("per-signal scopes: a client with only sim-swap scope cannot call kyc-match", async () => {
    const c = await h.newClient("bank-simonly", h.orgA, ["sim-swap:check", "consent:write"]);
    const n = numC("0", "0233"); const consent = await h.consent(c, n);
    const r = await h.call(c, "POST", "/v1/signals/kyc-match/check", { body: { ...base(n, consent.ref), ...KYC } });
    expect(r.status).toBe(403);
  });
});

describe("malicious or broken telco/aggregator responses are rejected (never TRUE/FALSE)", () => {
  const cases: Array<[string, (d: string, m: string) => string, string, string[]]> = [
    ["A", num, "SIM_SWAP", ["2", "3", "4", "5", "6", "7", "9"]],
    ["B", numB, "SIM_SWAP", ["2", "3", "4", "5", "6", "7", "8"]],
    ["C", numC, "SIM_SWAP", ["2", "3", "4", "5", "6", "7", "9"]],
  ];
  for (const [name, gen, signal, digits] of cases)
    it.each(digits)(`telco ${name}: hostile/invalid behaviour %s => UNAVAILABLE`, async (d) => {
      const r = await ask(signal as "SIM_SWAP", gen(d, "0240"));
      expect(r.status).toBe(200); expect(r.json.result).toBe("UNAVAILABLE");
      expect(JSON.stringify(r.json)).not.toMatch(/secret-internal-detail|stack|script|polluted/);
    });
  it("telco A returning a redirect is not followed", async () => {
    expect((await ask("SIM_SWAP", num("9", "0241"))).json.result).toBe("UNAVAILABLE");
  });
  it("Telco B parser is anchored: CRLF-smuggled second line, padding and trailing junk are rejected", () => {
    expect(parseTelcoB("RC=00;FLAG=Y")).toEqual({ rc: "00", flag: "Y" });
    expect(parseTelcoB("RC=00;FLAG=N\r\nRC=00;FLAG=Y")).toBeNull();
    expect(parseTelcoB("RC=00;FLAG=Y;X=1")).toBeNull();
    expect(parseTelcoB("xRC=00;FLAG=Y")).toBeNull();
    expect(parseTelcoB("RC=00;FLAG=Maybe")).toBeNull();
    expect(parseTelcoB("RC=00;FLAG=N" + " ".repeat(40) + "X")).toBeNull();
  });
  it("aggregator answers are bound to the request: wrong requestId or carrier is discarded", async () => {
    expect((await ask("SIM_SWAP", numC("4", "0242"))).json.result).toBe("UNAVAILABLE");
    expect((await ask("SIM_SWAP", numC("5", "0242"))).json.result).toBe("UNAVAILABLE");
  });
  it("prototype pollution via a telco response has no effect", async () => {
    await ask("SIM_SWAP", numC("9", "0243"));
    expect(({} as Record<string, unknown>)["polluted"]).toBeUndefined();
  });
  it("malicious-response outcomes are never billed", async () => {
    const { rows } = await h.migrator.query("SELECT count(*)::int n FROM usage_record WHERE outcome='UNAVAILABLE' AND billable");
    expect(rows[0].n).toBe(0);
  });
});

describe("KYC inputs are never stored or logged; outbound data is minimised", () => {
  it("synthetic KYC values appear nowhere at rest, in logs, or in the audit external copy", async () => {
    const secretName = "Zzyzx Quillfeather-" + Math.random().toString(36).slice(2, 8), secretId = "ID-" + Math.random().toString(36).slice(2, 12);
    const n = num("0", "0250");
    const r = await ask("KYC_MATCH", n, { name: secretName, idDocument: secretId, address: "1 Synthetic Lane" });
    expect(r.json.result).toBe("TRUE");
    const tables = ["consents", "usage_record", "audit_log", "organisations", "clients", "client_keys", "porting", "telcos", "kill_switch"];
    let dump = "";
    for (const t of tables) dump += JSON.stringify((await h.migrator.query(`SELECT * FROM ${t}`)).rows.map((x) => Object.fromEntries(Object.entries(x).map(([k, v]) => [k, Buffer.isBuffer(v) ? "[bytes]" : v]))));
    for (const needle of [secretName, secretId, "1 Synthetic Lane"]) {
      expect(dump).not.toContain(needle);
      expect(h.logs.join("")).not.toContain(needle);
      expect(readFileSync(h.auditSink, "utf8")).not.toContain(needle);
    }
    expect(JSON.parse(h.telco.lastBody!).name).toBe(secretName);        // ...but it did reach the telco (that is the purpose)
  });
  it("KYC requires at least one attribute and rejects unknown ones", async () => {
    const n = num("0", "0251"); const c = await h.consent(h.bankA, n);
    expect((await h.call(h.bankA, "POST", "/v1/signals/kyc-match/check", { body: base(n, c.ref) })).status).toBe(400);
    expect((await h.call(h.bankA, "POST", "/v1/signals/kyc-match/check", { body: { ...base(n, c.ref), name: "x", ssn: "123" } })).status).toBe(400);
  });
  it("the telco receives only what the signal needs: no consent ref, purpose, organisation or client id", async () => {
    await ask("SIM_SWAP", numB("0", "0252")); expect(h.telcoB.lastBody).toMatch(/^MSISDN=\d+;Q=SIMCHG;W=\d+$/);
    await ask("SIM_SWAP", numC("0", "0252"));
    expect(Object.keys(JSON.parse(h.aggregator.lastBody!)).sort()).toEqual(["carrier", "msisdn", "params", "requestId", "signal"]);
    expect(h.aggregator.lastBody).not.toMatch(/bank-a|CONSENT|FRAUD_PREVENTION/);
    await ask("CALL_FORWARDING", num("0", "0252")); expect(Object.keys(JSON.parse(h.telco.lastBody!))).toEqual(["phoneNumber"]);
  });
  it("cross-participant: another organisation cannot use bank-a's KYC consent", async () => {
    const n = num("0", "0253"); const c = await h.consent(h.bankA, n);
    const r = await h.call(h.bankB, "POST", "/v1/signals/kyc-match/check", { body: { ...base(n, c.ref), ...KYC } });
    expect(r.status).toBe(403); expect(r.json.code).toBe("CONSENT_REQUIRED");
  });
});

describe("outbound controls: allow-list, TLS pinning, spec conformance", () => {
  it("adapters refuse endpoints that are not on the allow-list or not https (SSRF)", () => {
    const m = { ca: h.pki.caCert, cert: "x", key: "y" };
    expect(() => new TelcoAAdapter("x", "https://169.254.169.254", ["https://ok.example:8443"], m)).toThrow(/allow-list/);
    expect(() => new TelcoAAdapter("x", "https://localhost:1", ["https://localhost:1"].slice(1), m)).toThrow(/allow-list/);
    expect(() => new TelcoAAdapter("x", "http://localhost:1", ["http://localhost:1"], m)).toThrow(/https/);
    expect(() => new TelcoBAdapter("x", "https://evil.example", ["https://good.example"], m)).toThrow(/allow-list/);
  });
  it("a telco presenting a certificate from an untrusted CA is not trusted (UNAVAILABLE)", async () => {
    const rogueSrv = h.pki.issue("rogue-telco", { server: true, ca: "rogue" });
    const m = await startMockTelcoA({ cert: rogueSrv.cert, key: rogueSrv.key, clientCa: h.pki.caCert });
    const out = h.pki.issue("platform-out2");
    try {
      const ad = new TelcoAAdapter("rogue", `https://localhost:${m.port}`, [`https://localhost:${m.port}`], { ca: h.pki.caCert, cert: out.cert, key: out.key }, 800);
      const r = await ad.call({ signal: "SIM_SWAP", msisdn: num("0", "0260"), correlationId: "c" });
      expect(r.status).toBe("UNAVAILABLE"); expect(m.calls).toBe(0);
      await ad.close();
    } finally { await m.close(); }
  });
  it("adapter paths match the vendored, pinned CAMARA definitions (server base + operation)", () => {
    const files: Record<string, string> = { SIM_SWAP: "sim-swap", DEVICE_SWAP: "device-swap", CALL_FORWARDING: "call-forwarding-signal", KYC_MATCH: "kyc-match" };
    for (const [sig, file] of Object.entries(files)) {
      const y = readFileSync(`openapi/camara/${file}.yaml`, "utf8");
      const serverBase = /- url: '\{apiRoot\}(\/[^']+)'/.exec(y)?.[1];
      const full = CAMARA_PATHS[sig as keyof typeof CAMARA_PATHS];
      expect(serverBase, file).toBeTruthy();
      expect(full.startsWith(serverBase!), `${sig} ${full} vs ${serverBase}`).toBe(true);
      const op = full.slice(serverBase!.length);
      expect(new RegExp(`^  ${op.replace(/[.*+?^${}()|[\]\\/-]/g, "\\$&")}:`, "m").test(y), `${sig} operation ${op}`).toBe(true);
    }
  });
  it("vendored CAMARA files match their recorded checksums (not edited)", () => {
    for (const line of readFileSync("openapi/camara/SHA256SUMS", "utf8").trim().split("\n")) {
      const [sum, file] = line.split(/\s+/) as [string, string];
      expect(createHash("sha256").update(readFileSync(`openapi/camara/${file}`)).digest("hex")).toBe(sum);
    }
  });
});
