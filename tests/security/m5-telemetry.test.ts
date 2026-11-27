// T-064: telemetry attributes never carry personal data. OpenTelemetry spans leave the process only through an allow-list.
import { describe, it, expect } from "vitest";
import { InMemorySpanExporter, BasicTracerProvider, SimpleSpanProcessor } from "@opentelemetry/sdk-trace-base";
import { makeTelemetry, sanitiseAttributes, ALLOWED_KEYS, NOOP_TELEMETRY } from "../../src/telemetry/otel.js";
import { startHarness, num } from "../helpers/harness.js";

describe("telemetry attributes: allow-list, value shape and second line of defence", () => {
  it("drops unknown keys, phone-like values, long strings and non-primitive values (and counts them)", () => {
    const c = { dropped: 0 };
    const out = sanitiseAttributes({
      "ts.signal": "SIM_SWAP", "ts.total_ms": 12, correlation_id: "3f1c2d0e-1234-4567-8901-234567890123",
      phoneNumber: "+60999000100", "ts.reason_class": "+60999000100", "ts.outcome": "x".repeat(200), "http.route": "/v1/signals/sim-swap/check", "ts.telco_id": ["a"] as never,
      "ts.error_code": "0999 000 1001", "ts.step": { a: 1 } as never, authorization: "Bearer abc", subject_ref: "ab12cd34",
    }, c);
    expect(Object.keys(out).sort()).toEqual(["correlation_id", "http.route", "ts.signal", "ts.total_ms"]);
    expect(c.dropped).toBe(8);
    expect(sanitiseAttributes({ correlation_id: "not-a-uuid" }).correlation_id).toBeUndefined();       // correlation id must really be a UUID
    for (const k of Object.keys(out)) expect(ALLOWED_KEYS.has(k)).toBe(true);
  });
  it("nothing is exported unless an exporter is configured", () => {
    expect(makeTelemetry({}).enabled).toBe(false); expect(NOOP_TELEMETRY.enabled).toBe(false);
  });
  it("the exporter itself filters again: an attribute set directly on a span (bypassing the helper) never reaches the exporter", async () => {
    const mem = new InMemorySpanExporter();
    const t = makeTelemetry({ exporter: mem });
    t.request({ startMs: performance.now() - 5, endMs: performance.now(), steps: [{ s: "auth", ms: 2 }, { s: "bad step name with spaces +60999000100", ms: 1 }], failed: false, attrs: { "ts.signal": "SIM_SWAP", phone: "+60999000100" } });
    const spans = mem.getFinishedSpans();
    expect(spans.length).toBe(3);
    const text = JSON.stringify(spans.map((s) => ({ n: s.name, a: s.attributes })));
    expect(text).not.toMatch(/60999000100|phone/); expect(spans.some((s) => s.name === "step.other")).toBe(true);
    // bypass: a second provider whose spans carry a raw attribute, exported through the same safe wrapper path
    const mem2 = new InMemorySpanExporter(); const p = new BasicTracerProvider({ spanProcessors: [new SimpleSpanProcessor(mem2)] });
    p.getTracer("x").startSpan("raw", { attributes: { phone: "+60999000100" } }).end();
    expect(JSON.stringify(mem2.getFinishedSpans().map((s) => s.attributes))).toContain("60999000100");   // proves the control is the wrapper, not the SDK
    await t.shutdown();
  });
});

describe("telemetry from a real request path", () => {
  it("every span from real traffic (success, refusal, bad token, hostile input) carries only allow-listed attributes and no number, token or consent reference", async () => {
    const mem = new InMemorySpanExporter(); const tel = makeTelemetry({ exporter: mem });
    const h = await startHarness({ telemetry: tel });
    try {
      const n = num("0", "0900"); const c = await h.consent(h.bankA, n);
      await h.call(h.bankA, "POST", "/v1/signals/sim-swap/check", { body: { phoneNumber: n, consentRef: c.ref, purposeCode: "FRAUD_PREVENTION" } });
      await h.call(h.bankA, "POST", "/v1/signals/sim-swap/check", { body: { phoneNumber: num("0", "0901"), consentRef: "NO-SUCH-CONSENT", purposeCode: "FRAUD_PREVENTION" } });
      await h.call(h.bankA, "GET", "/v1/statements", { token: "garbage" });
      await h.call(h.bankA, "POST", "/v1/signals/sim-swap/check", { rawBody: `{"phoneNumber":"${n}","x":"'; DROP TABLE x;--"}` });
      await h.app.drainLogs();
      const spans = mem.getFinishedSpans();
      expect(spans.length).toBeGreaterThan(10);
      for (const s of spans) for (const k of Object.keys(s.attributes)) expect(ALLOWED_KEYS.has(k), `${s.name}: ${k}`).toBe(true);
      const text = JSON.stringify(spans.map((s) => ({ n: s.name, a: s.attributes })));
      expect(text).not.toContain(n.slice(1)); expect(text).not.toContain(c.ref); expect(text).not.toMatch(/Bearer|garbage|DROP TABLE|\+60999/);
      const roots = spans.filter((s) => s.name === "signal.request");
      expect(roots.length).toBeGreaterThanOrEqual(4);
      expect(roots.some((r) => r.attributes["ts.outcome"] === "FALSE" && r.attributes["ts.signal"] === "SIM_SWAP")).toBe(true);
      expect(roots.every((r) => typeof r.attributes["correlation_id"] === "string")).toBe(true);
      expect(roots.some((r) => (r.attributes["http.response.status_code"] as number) === 401)).toBe(true);
      expect(tel.counters.dropped).toBe(0);                  // our own code never even tries to set a disallowed attribute
    } finally { await h.stop(); await tel.shutdown(); }
  });
});
