// Classifies why a request ended the way it did. Used for dashboards (errors by type), alerting and troubleshooting. No data from the request is ever used.
export type ReasonClass = "ok" | "timeout" | "telco_fault" | "client_data" | "circuit_open" | "bulkhead" | "limit" | "kill_switch" | "no_route" | "unsupported" | "disabled" | "rejected" | "other";
export function classifyReason(outcome: string, reason: string): ReasonClass {
  if (outcome === "TRUE" || outcome === "FALSE") return "ok";
  if (/rate limit|quota exceeded|repeat lookups/i.test(reason)) return "limit";
  if (/kill switch/i.test(reason)) return "kill_switch";
  if (/circuit/i.test(reason)) return "circuit_open";
  if (/bulkhead/i.test(reason)) return "bulkhead";
  if (/timeout/i.test(reason)) return "timeout";
  if (/signal disabled/i.test(reason)) return "disabled";
  if (/does not cover|not covered/i.test(reason)) return "unsupported";
  if (/no route|no adapter/i.test(reason)) return "no_route";
  if (/^telco status 4\d\d$|telco rc 14|some fields not available|no match fields/i.test(reason)) return "client_data";
  if (/telco status 5|transport|too large|content type|malformed|schema|unparseable|not bound|aggregator|exception|bad number/i.test(reason)) return "telco_fault";
  if (outcome === "REJECTED") return "rejected";
  return "other";
}
