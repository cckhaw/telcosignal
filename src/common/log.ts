import { pino } from "pino";
import { LOG_REDACT_PATHS, maskText } from "./redact.js";
export function makeLogger(level = process.env["LOG_LEVEL"] ?? "info", destination?: NodeJS.WritableStream) {
  const opts = {
    level,
    redact: { paths: LOG_REDACT_PATHS, censor: "[redacted]" },
    formatters: { log: (o: Record<string, unknown>) => JSON.parse(maskText(JSON.stringify(o))) as Record<string, unknown> },
    hooks: { logMethod(this: unknown, args: unknown[], method: (...a: unknown[]) => void) {
      method.apply(this, args.map((a) => (typeof a === "string" ? maskText(a) : a)));
    } },
    base: { service: "telco-signal" },
  };
  return destination ? pino(opts, destination) : pino(opts);
}
