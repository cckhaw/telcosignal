// OpenTelemetry tracing with a fail-closed attribute ALLOW-LIST (threat T-064: telemetry must never carry personal data).
//
//  * Attributes are accepted only if the key is on ALLOWED_KEYS and the value has the right shape (short, no digits-heavy strings, no
//    E.164 numbers). Anything else is dropped (and counted), never exported.
//  * The same filter runs a second time on the way out (SafeExporter), so a future code path that sets an attribute directly on a span still
//    cannot leak it.
//  * Spans are created AFTER the response has been sent, from the step timings already measured, so tracing adds nothing to request latency.
//  * Nothing is exported unless an exporter is configured: TS_OTEL_EXPORTER=console writes spans as JSON to stdout (sandbox). An OTLP exporter is
//    deliberately not bundled (dependency + network egress decision, see docs/release/residual-risks.md R-021).
import { trace, SpanStatusCode, type Attributes, type AttributeValue, type Tracer } from "@opentelemetry/api";
import { BasicTracerProvider, SimpleSpanProcessor, ConsoleSpanExporter, type ReadableSpan, type SpanExporter, type SpanProcessor } from "@opentelemetry/sdk-trace-base";
import type { ExportResult } from "@opentelemetry/core";

/** The complete set of attribute keys that may leave the process. Adding a key is a reviewed change (see tests/security/m5-telemetry.test.ts). */
export const ALLOWED_KEYS: ReadonlySet<string> = new Set([
  "correlation_id", "http.request.method", "http.route", "http.response.status_code", "ts.signal", "ts.outcome", "ts.error_code", "ts.telco_id",
  "ts.reason_class", "ts.step", "ts.step.duration_ms", "ts.total_ms", "ts.telco_ms", "ts.overhead_ms", "service.name",
]);
const SAFE_VALUE = /^[A-Za-z0-9_.:/ -]{0,64}$/;
const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/;
const PHONE_LIKE = /\+?[0-9][0-9 ()-]{7,}/;

export interface Counters { dropped: number }
export function sanitiseAttributes(a: Record<string, unknown>, counters?: Counters): Attributes {
  const out: Attributes = {};
  for (const [k, v] of Object.entries(a)) {
    if (v === undefined || v === null) continue;           // absent, not disallowed
    let ok = ALLOWED_KEYS.has(k);
    if (ok) {
      if (typeof v === "number") ok = Number.isFinite(v);
      else if (k === "correlation_id") ok = typeof v === "string" && UUID.test(v);       // a UUID can contain a long run of digits: validate it as a UUID instead of by digit count
      else if (typeof v === "string") ok = SAFE_VALUE.test(v) && !PHONE_LIKE.test(v);
      else ok = false;                                     // booleans/arrays/objects are not used by any allowed attribute
    }
    if (ok) out[k] = v as AttributeValue; else if (counters) counters.dropped++;
  }
  return out;
}

class SafeExporter implements SpanExporter {
  constructor(private inner: SpanExporter, private counters: Counters) {}
  export(spans: ReadableSpan[], cb: (r: ExportResult) => void): void {
    const clean = spans.map((s) => new Proxy(s, { get: (t, p, r) => (p === "attributes" ? sanitiseAttributes(t.attributes as Record<string, unknown>, this.counters) : p === "events" || p === "links" ? [] : p === "resource" ? t.resource : Reflect.get(t, p, r)) }));
    this.inner.export(clean as ReadableSpan[], cb);
  }
  shutdown(): Promise<void> { return this.inner.shutdown(); }
  forceFlush?(): Promise<void> { return this.inner.forceFlush?.() ?? Promise.resolve(); }
}

export interface Telemetry {
  enabled: boolean; counters: Counters;
  /** Emit one trace for a finished request: a root span plus one child per measured step. Never throws. */
  request(r: { startMs: number; endMs: number; attrs: Record<string, unknown>; steps: Array<{ s: string; ms: number }>; failed: boolean }): void;
  shutdown(): Promise<void>;
}
export const NOOP_TELEMETRY: Telemetry = { enabled: false, counters: { dropped: 0 }, request: () => undefined, shutdown: async () => undefined };

export function makeTelemetry(o: { exporter?: SpanExporter | "console" | undefined; serviceName?: string } = {}): Telemetry {
  const choice = o.exporter ?? (process.env["TS_OTEL_EXPORTER"] === "console" ? "console" : undefined);
  if (!choice) return NOOP_TELEMETRY;
  const counters: Counters = { dropped: 0 };
  const inner = choice === "console" ? new ConsoleSpanExporter() : choice;
  const processor: SpanProcessor = new SimpleSpanProcessor(new SafeExporter(inner, counters));
  const provider = new BasicTracerProvider({ spanProcessors: [processor] });
  const tracer: Tracer = provider.getTracer(o.serviceName ?? "telco-signal");
  void trace;
  return {
    enabled: true, counters,
    request({ startMs, endMs, attrs, steps, failed }) {
      try {
        const base = Date.now() - (performance.now() - startMs);            // convert the monotonic clock to wall time once
        const root = tracer.startSpan("signal.request", { startTime: base, attributes: sanitiseAttributes(attrs, counters) });
        let t = startMs;
        for (const st of steps) {
          const s = tracer.startSpan(`step.${/^[a-z_]{1,20}$/.test(st.s) ? st.s : "other"}`, { startTime: base + (t - startMs) }, trace.setSpan(rootCtx(), root));
          s.setAttributes(sanitiseAttributes({ "ts.step": st.s, "ts.step.duration_ms": st.ms }, counters));
          s.end(base + (t - startMs) + st.ms); t += st.ms;
        }
        if (failed) root.setStatus({ code: SpanStatusCode.ERROR });
        root.end(base + (endMs - startMs));
      } catch { /* telemetry must never break serving */ }
    },
    shutdown: () => provider.shutdown(),
  };
}
import { context, type Context } from "@opentelemetry/api";
const rootCtx = (): Context => context.active();
