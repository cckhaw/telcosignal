// Error catalogue. Responses reveal no internals and never whether a number exists.
export const ERRORS = {
  INVALID_REQUEST: { status: 400, title: "Invalid request" },
  AUTHENTICATION_FAILED: { status: 401, title: "Authentication failed" },
  ACCESS_DENIED: { status: 403, title: "Access denied" },
  CONSENT_REQUIRED: { status: 403, title: "Consent or lawful basis not valid for this request" },
  REPLAY_REJECTED: { status: 401, title: "Request rejected" },
  RATE_LIMITED: { status: 429, title: "Too many requests" },
  PAYLOAD_TOO_LARGE: { status: 413, title: "Payload too large" },
  NOT_FOUND: { status: 404, title: "Not found" },
  INTERNAL: { status: 500, title: "Internal error" },
  SERVICE_UNAVAILABLE: { status: 503, title: "Service unavailable" },
} as const;
export type ErrorCode = keyof typeof ERRORS;

export class ApiError extends Error {
  constructor(
    public readonly code: ErrorCode,
    public readonly reason: string = code, // internal reason: audit/security log only, never returned
  ) {
    super(reason);
  }
}

export function problem(code: ErrorCode, correlationId: string) {
  const e = ERRORS[code];
  return { status: e.status, code, message: e.title, correlationId };
}

/** Error catalogue: what each code means and what to do. Shown in the admin portal and the developer portal. Contains no request data. */
export interface CatalogueEntry { code: ErrorCode; status: number; meaning: string; participantAction: string; operatorAction: string }
export const CATALOGUE: CatalogueEntry[] = [
  { code: "INVALID_REQUEST", status: 400, meaning: "The request did not match the published schema (unknown field, wrong type, bad format, missing purpose or consent reference).", participantAction: "Compare the request with the OpenAPI definition; unknown fields are rejected.", operatorAction: "Find the correlation id in Logs; the failing step is 'validate'. No action unless the volume is unusual." },
  { code: "AUTHENTICATION_FAILED", status: 401, meaning: "Token, client certificate binding, signature or client assertion could not be verified.", participantAction: "Fetch a new token with the SAME client certificate; check the key id, clock and signature payload.", operatorAction: "Check credentials (expiry, revocation, certificate thumbprint). A burst from one client may indicate stolen credentials: consider suspending." },
  { code: "ACCESS_DENIED", status: 403, meaning: "The caller is authenticated but not permitted: scope not granted, signal or purpose not entitled, or the participant is suspended.", participantAction: "Request the scope or entitlement through your onboarding contact.", operatorAction: "Check entitlements and scopes for the organisation and any participant kill switch." },
  { code: "CONSENT_REQUIRED", status: 403, meaning: "No valid consent or lawful-basis reference for this subject, purpose and signal (missing, expired, revoked or not permitted). The reason is deliberately not disclosed.", participantAction: "Register or renew the consent before asking for the signal.", operatorAction: "Repeated occurrences from one client can indicate probing; see Alerts and the enumeration flags." },
  { code: "REPLAY_REJECTED", status: 401, meaning: "The signed request is outside the time window or its identifier was already used.", participantAction: "Use a fresh unique request id and a current timestamp; do not retry an identical signed request.", operatorAction: "Check participant clock skew. A burst can be a replay attack: see the security KPIs." },
  { code: "RATE_LIMITED", status: 429, meaning: "A rate limit or quota was exceeded.", participantAction: "Back off and retry later; ask for a higher quota if the volume is legitimate.", operatorAction: "Review limits for the organisation; a sudden rise may be abuse." },
  { code: "PAYLOAD_TOO_LARGE", status: 413, meaning: "The request body exceeded the size limit.", participantAction: "Send only the documented fields.", operatorAction: "None normally." },
  { code: "NOT_FOUND", status: 404, meaning: "No such resource for your organisation (the same answer is given for other organisations' resources).", participantAction: "Check the identifier.", operatorAction: "None." },
  { code: "INTERNAL", status: 500, meaning: "An unexpected platform error. Details are never returned to the caller.", participantAction: "Retry later and quote the correlation id.", operatorAction: "Trace the correlation id; check dependency health and recent changes." },
  { code: "SERVICE_UNAVAILABLE", status: 503, meaning: "A security dependency (for example the replay or rate-limit store) is unavailable, so the platform refuses to serve (fail closed).", participantAction: "Retry with backoff and quote the correlation id.", operatorAction: "Check dependency health (database, Redis)." },
];
export const RESULT_CATALOGUE: Array<{ result: string; meaning: string; action: string }> = [
  { result: "TRUE", meaning: "The signal is positive (for example a SIM swap occurred in the window).", action: "Apply your own risk policy." },
  { result: "FALSE", meaning: "The telco explicitly answered that the signal is negative. It is NEVER returned for a timeout, error or unsupported signal.", action: "Apply your own risk policy." },
  { result: "UNAVAILABLE", meaning: "No reliable answer: timeout, telco fault, invalid telco response, unrouted number, circuit open, or the signal is disabled. Indistinguishable from an unknown number by design.", action: "Treat as unknown (not as safe); retry later or use another control. Not charged." },
  { result: "NOT_SUPPORTED", meaning: "The serving telco does not provide this signal.", action: "Use another control for this subscriber. Not charged." },
];
export const REASON_CLASSES: Array<{ cls: string; meaning: string; operatorAction: string }> = [
  { cls: "timeout", meaning: "The telco did not answer within the 2 s budget.", operatorAction: "Check the telco's health and the circuit breaker; contact the telco if sustained." },
  { cls: "telco_fault", meaning: "Transport error, HTTP 5xx or an invalid/oversized response from the telco or aggregator.", operatorAction: "Check the adapter and the telco; a hostile or broken response was discarded." },
  { cls: "client_data", meaning: "The telco did not know the subscriber (404/422/unknown). Not counted as a telco fault.", operatorAction: "None; a flood of these may be enumeration." },
  { cls: "circuit_open", meaning: "The circuit breaker for this telco is open; the telco was not called.", operatorAction: "Find the underlying fault; the breaker retries automatically." },
  { cls: "bulkhead", meaning: "Too many concurrent calls to this telco; this one was refused.", operatorAction: "Check telco latency and load." },
  { cls: "limit", meaning: "A rate limit or quota applied.", operatorAction: "Review limits." },
  { cls: "kill_switch", meaning: "A kill switch (participant, telco or signal) was engaged.", operatorAction: "Confirm it is intentional; lifting needs a second person." },
  { cls: "no_route", meaning: "No active telco route for the number.", operatorAction: "Check routing prefixes, porting and telco state." },
  { cls: "unsupported", meaning: "The telco does not cover this signal.", operatorAction: "Check coverage." },
  { cls: "disabled", meaning: "The signal is disabled in the registry.", operatorAction: "Check the signal registry." },
  { cls: "rejected", meaning: "Rejected before reaching a telco (consent or entitlement).", operatorAction: "See CONSENT_REQUIRED / ACCESS_DENIED." },
  { cls: "ok", meaning: "Answered normally.", operatorAction: "None." },
];
