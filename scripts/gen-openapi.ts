// Generates openapi/participant.yaml FROM THE CODE (route table, JSON schemas, error catalogue) so the published contract cannot drift.
// `npm run gen:openapi` rewrites it; a test regenerates it and fails if the committed file differs.
import { writeFileSync } from "node:fs";
import { stringify } from "yaml";
import { CATALOGUE, ERRORS, RESULT_CATALOGUE } from "../src/common/errors.js";
import { SCHEMA_CALL_FORWARDING, SCHEMA_CREATE_CONSENT, SCHEMA_KYC_MATCH, SCHEMA_SIM_SWAP } from "../src/participant-api/schemas.js";

const problemRef = (desc: string) => ({ description: desc, content: { "application/problem+json": { schema: { $ref: "#/components/schemas/Problem" } } } });
const ERR = (code: keyof typeof ERRORS) => [String(ERRORS[code].status), problemRef(CATALOGUE.find((e) => e.code === code)!.meaning)] as const;
const errs = (...codes: Array<keyof typeof ERRORS>) => Object.fromEntries(codes.map(ERR));
const sigHeaders = [{ $ref: "#/components/parameters/RequestSignature" }];
const secure = [{ mutualTLS: [], accessToken: [] }];
const signalOp = (id: string, summary: string, scope: string, schema: string, camara: string) => ({
  post: {
    operationId: id, summary, description: `Requires scope \`${scope}\`. Answers are four-state: TRUE, FALSE, UNAVAILABLE, NOT_SUPPORTED. FALSE is returned only when the telco gave an explicit, valid negative; a timeout, error, invalid response or unsupported signal is never FALSE. ${camara}`,
    security: secure, parameters: sigHeaders, requestBody: { required: true, content: { "application/json": { schema: { $ref: `#/components/schemas/${schema}` } } } },
    responses: { "200": { description: "Signal result (UNAVAILABLE and NOT_SUPPORTED are answered with HTTP 200 and are not charged)", content: { "application/json": { schema: { $ref: "#/components/schemas/SignalResponse" } } } }, ...errs("INVALID_REQUEST", "AUTHENTICATION_FAILED", "ACCESS_DENIED", "CONSENT_REQUIRED", "RATE_LIMITED", "SERVICE_UNAVAILABLE", "INTERNAL") },
  },
});
const SCHEMAS: Record<string, unknown> = {
  CreateConsentRequest: SCHEMA_CREATE_CONSENT, SimSwapCheckRequest: SCHEMA_SIM_SWAP, DeviceSwapCheckRequest: SCHEMA_SIM_SWAP, CallForwardingCheckRequest: SCHEMA_CALL_FORWARDING, KycMatchRequest: SCHEMA_KYC_MATCH,
  SignalResponse: { type: "object", required: ["signal", "result", "correlationId"], properties: { signal: { enum: ["SIM_SWAP", "DEVICE_SWAP", "CALL_FORWARDING", "KYC_MATCH"] }, result: { enum: RESULT_CATALOGUE.map((r) => r.result) }, fields: { type: "object", description: "KYC match only: per-attribute MATCH / NO_MATCH / NOT_AVAILABLE", additionalProperties: { enum: ["MATCH", "NO_MATCH", "NOT_AVAILABLE"] } }, correlationId: { type: "string", format: "uuid" } } },
  Problem: { type: "object", required: ["status", "code", "message", "correlationId"], properties: { status: { type: "integer" }, code: { enum: Object.keys(ERRORS) }, message: { type: "string" }, correlationId: { type: "string" } }, description: "Errors never reveal internals and never disclose whether a number exists." },
  TokenResponse: { type: "object", required: ["access_token", "token_type", "expires_in", "scope"], properties: { access_token: { type: "string" }, token_type: { enum: ["Bearer"] }, expires_in: { type: "integer", maximum: 300 }, scope: { type: "string" } } },
  ConsentCreated: { type: "object", required: ["id", "consentRef", "correlationId"], properties: { id: { type: "string", format: "uuid" }, consentRef: { type: "string" }, correlationId: { type: "string" } } },
  Consent: { type: "object", properties: { id: { type: "string", format: "uuid" }, consentRef: { type: "string" }, purposeCode: { type: "string" }, signals: { type: "array", items: { type: "string" } }, expiresAt: { type: "string", format: "date-time" }, revoked: { type: "boolean" }, correlationId: { type: "string" } } },
  StatementSummary: { type: "object", properties: { id: { type: "string", format: "uuid" }, periodStart: { type: "string", format: "date-time" }, periodEnd: { type: "string", format: "date-time" }, currency: { type: "string" }, usageCount: { type: "integer" }, totalMinor: { type: "integer", description: "Integer minor units; prices are placeholders in the sandbox" } } },
};
export function buildOpenApi(): unknown {
  return {
    openapi: "3.1.0",
    info: { title: "Telco Signal API (sandbox reference implementation)", version: "1.0.0", description: "SANDBOX: synthetic data only. NOT approved for live data. No certification or compliance is claimed.\n\nOne API for SIM swap, device swap, call forwarding and KYC match signals from several telcos. Deliberate deviations from the CAMARA definitions (docs/architecture.md section 11): four-state results instead of booleans, no 404 for unknown numbers, mandatory purposeCode + consentRef, sender-constrained tokens and signed requests." },
    servers: [{ url: "https://api.sandbox.invalid", description: "Placeholder: the sandbox runs locally; participant mTLS cannot be terminated on the static developer-portal host" }],
    tags: [{ name: "auth" }, { name: "consent" }, { name: "signals" }, { name: "statements" }],
    paths: {
      "/oauth/token": { post: { tags: ["auth"], operationId: "token", summary: "Client-credentials token (private_key_jwt, mTLS-bound)", security: [{ mutualTLS: [] }], requestBody: { required: true, content: { "application/x-www-form-urlencoded": { schema: { type: "object", additionalProperties: false, required: ["grant_type", "client_id", "client_assertion_type", "client_assertion"], properties: { grant_type: { enum: ["client_credentials"] }, client_id: { type: "string" }, client_assertion_type: { enum: ["urn:ietf:params:oauth:client-assertion-type:jwt-bearer"] }, client_assertion: { type: "string", description: "JWT signed with your registered private key; aud = this endpoint; lifetime at most 60 s; single use" }, scope: { type: "string" } } } } } }, responses: { "200": { description: "Access token bound to your client certificate (cnf.x5t#S256), lifetime at most 5 minutes", content: { "application/json": { schema: { $ref: "#/components/schemas/TokenResponse" } } } }, ...errs("INVALID_REQUEST", "AUTHENTICATION_FAILED", "ACCESS_DENIED", "REPLAY_REJECTED", "RATE_LIMITED", "SERVICE_UNAVAILABLE") } } },
      "/.well-known/jwks.json": { get: { tags: ["auth"], operationId: "jwks", summary: "Platform token-verification keys (public)", security: [{ mutualTLS: [] }], responses: { "200": { description: "JWK Set", content: { "application/json": { schema: { type: "object" } } } } } } },
      "/v1/consents": { post: { tags: ["consent"], operationId: "createConsent", summary: "Register a consent / lawful-basis reference for a subject, purpose and signals", security: secure, parameters: sigHeaders, requestBody: { required: true, content: { "application/json": { schema: { $ref: "#/components/schemas/CreateConsentRequest" } } } }, responses: { "201": { description: "Created", content: { "application/json": { schema: { $ref: "#/components/schemas/ConsentCreated" } } } }, ...errs("INVALID_REQUEST", "AUTHENTICATION_FAILED", "ACCESS_DENIED", "REPLAY_REJECTED", "RATE_LIMITED") } } },
      "/v1/consents/{id}": { get: { tags: ["consent"], operationId: "getConsent", summary: "Read one of your consents", security: secure, parameters: [{ name: "id", in: "path", required: true, schema: { type: "string", format: "uuid" } }], responses: { "200": { description: "OK", content: { "application/json": { schema: { $ref: "#/components/schemas/Consent" } } } }, ...errs("AUTHENTICATION_FAILED", "ACCESS_DENIED", "NOT_FOUND") } } },
      "/v1/consents/{id}/revoke": { post: { tags: ["consent"], operationId: "revokeConsent", summary: "Revoke a consent", security: secure, parameters: [{ name: "id", in: "path", required: true, schema: { type: "string", format: "uuid" } }, ...sigHeaders], responses: { "200": { description: "Revoked" }, ...errs("AUTHENTICATION_FAILED", "ACCESS_DENIED", "NOT_FOUND", "REPLAY_REJECTED") } } },
      "/v1/signals/sim-swap/check": signalOp("checkSimSwap", "Has the SIM been swapped within maxAge hours?", "sim-swap:check", "SimSwapCheckRequest", "Telco A speaks CAMARA SimSwap r4.3 `check`."),
      "/v1/signals/device-swap/check": signalOp("checkDeviceSwap", "Has the device been swapped within maxAge hours?", "device-swap:check", "DeviceSwapCheckRequest", "Telco A speaks CAMARA DeviceSwap r4.3 `check`."),
      "/v1/signals/call-forwarding/check": signalOp("checkCallForwarding", "Is unconditional call forwarding active?", "call-forwarding:check", "CallForwardingCheckRequest", "Telco A speaks CAMARA CallForwardingSignal r4.3."),
      "/v1/signals/kyc-match/check": signalOp("checkKycMatch", "Do the supplied identity attributes match the subscriber record?", "kyc-match:check", "KycMatchRequest", "KYC inputs are processed in memory only and are never stored or logged. Telco A speaks CAMARA KYC Match r2.2."),
      "/v1/statements": { get: { tags: ["statements"], operationId: "listStatements", summary: "Your settlement statements", security: secure, responses: { "200": { description: "OK", content: { "application/json": { schema: { type: "object", properties: { statements: { type: "array", items: { $ref: "#/components/schemas/StatementSummary" } }, correlationId: { type: "string" } } } } } }, ...errs("AUTHENTICATION_FAILED", "ACCESS_DENIED") } } },
      "/v1/statements/{id}": { get: { tags: ["statements"], operationId: "getStatement", summary: "One of your statements, with line items", security: secure, parameters: [{ name: "id", in: "path", required: true, schema: { type: "string", format: "uuid" } }], responses: { "200": { description: "OK" }, ...errs("AUTHENTICATION_FAILED", "ACCESS_DENIED", "NOT_FOUND") } } },
    },
    components: {
      securitySchemes: { mutualTLS: { type: "mutualTLS", description: "TLS 1.3 preferred (1.2 minimum) with a client certificate registered for your client" }, accessToken: { type: "http", scheme: "bearer", bearerFormat: "JWT", description: "Sender-constrained: the token is bound to your client certificate and is useless with any other" } },
      parameters: { RequestSignature: { name: "X-Request-Signature", in: "header", required: true, description: "Compact JWS (ES256 or PS256, your registered key) over {htm, htu, dig (base64url SHA-256 of the body), iat (within 60 s), jti (single use, 16-64 chars)}", schema: { type: "string", maxLength: 4096 } } },
      schemas: SCHEMAS,
    },
  };
}
if (process.argv[1]?.endsWith("gen-openapi.ts")) { writeFileSync("openapi/participant.yaml", stringify(buildOpenApi(), { lineWidth: 0 })); console.log("wrote openapi/participant.yaml"); }
