import { describe, it, expect, beforeAll, afterAll } from "vitest";
import { Ajv } from "ajv";
import { mkdtempSync, readFileSync, readdirSync, existsSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { parse, stringify } from "yaml";
import { startHarness, num, type Harness } from "../helpers/harness.js";
import { buildOpenApi } from "../../scripts/gen-openapi.js";
import { buildPortal } from "../../scripts/build-portal.js";
import { ERRORS, CATALOGUE } from "../../src/common/errors.js";
import { validateCallForwardingCheck, validateCreateConsent, validateKycMatch, validateSimSwapCheck } from "../../src/participant-api/schemas.js";

let h: Harness;
beforeAll(async () => { h = await startHarness(); });
afterAll(async () => { await h.stop(); });
type Spec = { paths: Record<string, Record<string, { operationId: string; responses: Record<string, unknown>; security?: unknown[] }>>; components: { schemas: Record<string, Record<string, unknown>> } };
const committed = () => readFileSync("openapi/participant.yaml", "utf8");
const spec = () => parse(committed()) as Spec;

describe("OpenAPI definition is generated from the code and cannot drift", () => {
  it("the committed file equals what the code generates (run `npm run gen:openapi` after changing routes, schemas or errors)", () => {
    expect(committed()).toBe(stringify(buildOpenApi(), { lineWidth: 0 }));
  });
  it("it declares OpenAPI 3.1, every $ref resolves, operation ids are unique, every operation has responses", () => {
    const y = committed(); expect(y).toMatch(/^openapi: 3\.1\.0/);
    const s = spec(); const ids: string[] = [];
    for (const item of Object.values(s.paths)) for (const op of Object.values(item)) { ids.push(op.operationId); expect(Object.keys(op.responses).length).toBeGreaterThan(0); }
    expect(new Set(ids).size).toBe(ids.length);
    for (const m of y.matchAll(/\$ref: '?#\/components\/(\w+)\/(\w+)'?/g)) expect((s.components as Record<string, Record<string, unknown>>)[m[1]!]?.[m[2]!], m[0]).toBeTruthy();
  });
  it("every route the server really registers is documented, and every documented operation really exists", () => {
    const actual = new Set(h.app.routeTable.map((r) => `${r.method} ${r.url.replace(/:(\w+)/g, "{$1}")}`));
    const documented = new Set(Object.entries(spec().paths).flatMap(([p, item]) => Object.keys(item).map((m) => `${m.toUpperCase()} ${p}`)));
    expect([...actual].sort()).toEqual([...documented].sort());
  });
  it("security is declared on every operation (mutual TLS everywhere; token for everything but /oauth/token and the key set)", () => {
    for (const [p, item] of Object.entries(spec().paths)) for (const op of Object.values(item)) {
      expect(JSON.stringify(op.security), p).toContain("mutualTLS");
      if (!["/oauth/token", "/.well-known/jwks.json"].includes(p)) expect(JSON.stringify(op.security), p).toContain("accessToken");
    }
  });
  it("the Problem error codes equal the platform's error codes, and the catalogue covers each", () => {
    const codes = (spec().components.schemas["Problem"]!["properties"] as { code: { enum: string[] } }).code.enum;
    expect(codes.sort()).toEqual(Object.keys(ERRORS).sort()); expect(CATALOGUE.map((e) => e.code).sort()).toEqual(Object.keys(ERRORS).sort());
  });
  it("request schemas in the spec are the validators the server actually runs: the same inputs are accepted and refused", () => {
    const s = spec().components.schemas;
    const ajv = new Ajv({ strict: false });
    const pairs: Array<[string, (b: unknown) => boolean, Record<string, unknown>]> = [
      ["SimSwapCheckRequest", validateSimSwapCheck, { phoneNumber: "+609990000001", purposeCode: "FRAUD_PREVENTION", consentRef: "CONSENT-0001" }],
      ["CallForwardingCheckRequest", validateCallForwardingCheck, { phoneNumber: "+609990000001", purposeCode: "FRAUD_PREVENTION", consentRef: "CONSENT-0001" }],
      ["KycMatchRequest", validateKycMatch, { phoneNumber: "+609990000001", purposeCode: "FRAUD_PREVENTION", consentRef: "CONSENT-0001", name: "Synthetic" }],
      ["CreateConsentRequest", validateCreateConsent, { phoneNumber: "+609990000001", consentRef: "CONSENT-0001", purposeCode: "FRAUD_PREVENTION", signals: ["SIM_SWAP"], expiresAt: "2030-01-01T00:00:00Z" }],
    ];
    for (const [name, validate, good] of pairs) {
      const fromSpec = ajv.compile(s[name]!);
      const cases: Array<Record<string, unknown>> = [good, { ...good, extra: 1 }, { ...good, phoneNumber: "0123" }, { ...good, purposeCode: "MARKETING" }, Object.fromEntries(Object.entries(good).slice(1))];
      for (const c of cases) expect(fromSpec(c), `${name} ${JSON.stringify(c).slice(0, 60)}`).toBe(validate(c));
    }
  });
  it("CONTRACT: real responses from the running server validate against the published schemas", async () => {
    const ajv = new Ajv({ strict: false }); ajv.addFormat("uuid", true); ajv.addFormat("date-time", true);
    const s = spec().components.schemas; const sig = ajv.compile(s["SignalResponse"]!), problem = ajv.compile(s["Problem"]!), tok = ajv.compile(s["TokenResponse"]!), created = ajv.compile(s["ConsentCreated"]!);
    const n = num("1", "9100"); const k = await h.consent(h.bankA, n);
    const ok = await h.call(h.bankA, "POST", "/v1/signals/sim-swap/check", { body: { phoneNumber: n, consentRef: k.ref, purposeCode: "FRAUD_PREVENTION" } });
    expect(ok.status).toBe(200); expect(sig(ok.json), JSON.stringify(sig.errors)).toBe(true);
    const unsupported = await h.call(h.bankA, "POST", "/v1/signals/device-swap/check", { body: { phoneNumber: "+6099901000091", consentRef: (await h.consent(h.bankA, "+6099901000091")).ref, purposeCode: "FRAUD_PREVENTION" } });
    expect(unsupported.json.result).toBe("NOT_SUPPORTED"); expect(sig(unsupported.json)).toBe(true);
    const kyc = await h.call(h.bankA, "POST", "/v1/signals/kyc-match/check", { body: { phoneNumber: n, consentRef: k.ref, purposeCode: "FRAUD_PREVENTION", name: "Synthetic Person" } }); expect(sig(kyc.json)).toBe(true);
    for (const bad of [await h.call(h.bankA, "POST", "/v1/signals/sim-swap/check", { body: { phoneNumber: n } }), await h.call(h.bankA, "POST", "/v1/signals/sim-swap/check", { body: { phoneNumber: n, consentRef: "CONSENT-NOPE-0001", purposeCode: "FRAUD_PREVENTION" } }), await h.call(h.bankA, "POST", "/v1/signals/sim-swap/check", { body: { phoneNumber: n, consentRef: k.ref, purposeCode: "FRAUD_PREVENTION" }, token: "garbage" })]) {
      expect(problem(bad.json), JSON.stringify(problem.errors)).toBe(true); expect(Object.keys(ERRORS)).toContain(bad.json.code);
    }
    const c = await h.call(h.bankA, "POST", "/v1/consents", { body: { phoneNumber: n, consentRef: "CONTRACT-0001", purposeCode: "FRAUD_PREVENTION", signals: ["SIM_SWAP"], expiresAt: new Date(Date.now() + 3600e3).toISOString() } });
    expect(c.status).toBe(201); expect(created(c.json)).toBe(true);
    const form = new URLSearchParams({ grant_type: "client_credentials", client_id: "bank-a", client_assertion_type: "urn:ietf:params:oauth:client-assertion-type:jwt-bearer", client_assertion: await h.assertion(h.bankA) });
    const { request } = await import("undici"); const r = await request(h.cfg.tokenEndpoint, { method: "POST", dispatcher: h.bankA.agent, headers: { "content-type": "application/x-www-form-urlencoded" }, body: form.toString() });
    const t = await r.body.json(); expect(r.statusCode).toBe(200); expect(tok(t), JSON.stringify(tok.errors)).toBe(true);
  });
});

describe("developer portal", () => {
  let dir = ""; let files: string[] = [];
  beforeAll(() => { dir = mkdtempSync(join(tmpdir(), "portal-")); files = buildPortal(dir); });
  it("is reproducible: the committed portal equals a fresh build", () => {
    for (const f of readdirSync(dir)) expect(readFileSync(join("portal", f), "utf8"), f).toBe(readFileSync(join(dir, f), "utf8"));
    expect(readdirSync("portal").sort()).toEqual(readdirSync(dir).sort());
  });
  it("covers authentication, every signal, every error code and the sandbox rules; each page states that it is a sandbox", () => {
    const html = (f: string) => readFileSync(join(dir, f), "utf8");
    for (const f of ["index.html", "authentication.html", "signals.html", "errors.html", "sandbox.html", "versions.html"]) { expect(files).toContain(f); expect(html(f)).toContain("NOT approved for live data"); }
    for (const p of ["/v1/signals/sim-swap/check", "/v1/signals/device-swap/check", "/v1/signals/call-forwarding/check", "/v1/signals/kyc-match/check", "/v1/signals/number-recycling/check", "/v1/signals/kyc-tenure/check", "/v1/signals/device-location/check", "/v1/signals/device-roaming/check", "/v1/consents"]) expect(html("signals.html")).toContain(p);
    for (const e of CATALOGUE) { expect(html("errors.html")).toContain(e.code); expect(html("errors.html")).toContain(e.participantAction.slice(0, 20).replace(/&/g, "&amp;").replace(/'/g, "&#39;")); }
    for (const w of ["UNAVAILABLE", "NOT_SUPPORTED", "private_key_jwt", "X-Request-Signature", "cnf.x5t#S256"]) expect(Object.values(Object.fromEntries(files.filter((f) => f.endsWith(".html")).map((f) => [f, html(f)]))).join("")).toContain(w);
  });
  it("is safe to host publicly: no script, no inline styles, no external resources, no secrets, no real-looking numbers", () => {
    for (const f of files.filter((x) => x.endsWith(".html"))) {
      const t = readFileSync(join(dir, f), "utf8");
      expect(t, f).not.toMatch(/<script|<iframe|<object|<embed|\sstyle=|\son\w+=|javascript:/i);
      expect(t.match(/(?:src|href)="(https?:)?\/\//gi), f).toBeNull();
      expect(/\+[1-9][0-9]{8,14}/.test(t.replace(/\+6099900|\+6099901|\+6099902/g, "")), f).toBe(false);
      expect(t).not.toMatch(/BEGIN (EC |RSA )?PRIVATE KEY|client_secret|password/i);
      for (const m of t.matchAll(/href="\/([a-z]*)"/g)) { const target = m[1] === "" ? "index.html" : `${m[1]}.html`; expect(existsSync(join(dir, target)), `${f} -> /${m[1]}`).toBe(true); }
    }
  });
  it("the hosting configuration enforces a strict content security policy and the portal serves only static files", () => {
    const v = JSON.parse(readFileSync("vercel.json", "utf8")) as { outputDirectory: string; headers: Array<{ headers: Array<{ key: string; value: string }> }>; git: { deploymentEnabled: boolean } };
    const csp = v.headers[0]!.headers.find((x) => x.key === "Content-Security-Policy")!.value;
    expect(csp).toContain("default-src 'none'"); expect(csp).not.toMatch(/unsafe|script-src/); expect(v.outputDirectory).toBe("portal"); expect(v.git.deploymentEnabled).toBe(false);
  });
});
