import Fastify, { type FastifyInstance, type FastifyRequest } from "fastify";
import rateLimit from "@fastify/rate-limit";
import type { Redis } from "ioredis";
import { randomUUID } from "node:crypto";
import type { TLSSocket } from "node:tls";
import type { Logger } from "pino";
import type { Config } from "../common/config.js";
import { ApiError, ERRORS, problem, type ErrorCode } from "../common/errors.js";
import type { Pool } from "../db/pool.js";
import { withOrgTx } from "../db/pool.js";
import type { EphemeralStore } from "../common/store.js";
import type { Kms } from "../kms/types.js";
import type { Audit } from "../audit/audit.js";
import type { AdapterSource } from "../adapters/registry.js";
import { certThumbprint, issueAccessToken, verifyAccessToken, verifyClientAssertion, verifyRequestSignature } from "../identity/tokens.js";
import { clientUsable, lookupClient, type ClientRec } from "../identity/clients.js";
import { consentValid, createConsent, getConsent, revokeConsent, subjectHash } from "../consent/consent.js";
import { routeNumber } from "../router/router.js";
import type { Limiter } from "../ratelimit/limits.js";
import type { AbuseDetector } from "../abuse/enumeration.js";
import { classifyReason } from "../resilience/classify.js";
import { KYC_FIELDS, MAX_RECYCLING_LOOKBACK_DAYS, UUID_RE, validPastDate, validateCallForwardingCheck, validateCreateConsent, validateDeviceLocation, validateDeviceRoaming, validateDeviceSwapCheck, validateKycMatch, validateKycTenure, validateNumberRecycling, validateSimSwapCheck } from "./schemas.js";
import type { KycInput, SignalParams } from "../adapters/types.js";
import type { Signal } from "../consent/consent.js";
import { NOOP_TELEMETRY, type Telemetry } from "../telemetry/otel.js";

export interface Deps { limiter: Limiter; abuse: AbuseDetector; rateLimitRedis?: Redis; cfg: Config; pool: Pool; store: EphemeralStore; kms: Kms; audit: Audit; adapters: AdapterSource; log: Logger; telemetry?: Telemetry }
interface Ctx { client: ClientRec; thumb: string; scopes: string[]; correlationId: string }
const TLS12_CIPHERS = "ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384:ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-CHACHA20-POLY1305:ECDHE-RSA-CHACHA20-POLY1305";

export async function buildParticipantServer(d: Deps): Promise<FastifyInstance> {
  const app = Fastify({
    https: { key: d.cfg.tls.key, cert: d.cfg.tls.cert, ca: d.cfg.tls.participantCa, requestCert: true, rejectUnauthorized: true, minVersion: "TLSv1.2", ciphers: TLS12_CIPHERS, honorCipherOrder: true,
      connectionsCheckingInterval: 1000 },   // slow-header (slow-loris) clients are reaped within seconds of requestTimeout: Node only checks every 30 s by default. (Do NOT also set headersTimeout below connectionTimeout: that combination stops idle connections being reaped; found by the pen test.)
    bodyLimit: 4096, connectionTimeout: 6_000, requestTimeout: 8_000,   // connectionTimeout MUST stay below requestTimeout: with the short checking interval Node otherwise never reaps idle sockets (found by the pen test)
    keepAliveTimeout: 5_000, routerOptions: { maxParamLength: 64 },
    disableRequestLogging: true, trustProxy: false, genReqId: () => randomUUID(), loggerInstance: d.log,
    onProtoPoisoning: "error", onConstructorPoisoning: "error",
  });

  const peerThumb = (req: FastifyRequest): string => {
    const s = req.raw.socket as TLSSocket;
    const c = s.getPeerCertificate(false);
    if (!s.authorized || !c?.raw) throw new ApiError("AUTHENTICATION_FAILED", "no verified client certificate");
    return certThumbprint(c.raw);
  };

  // Rate limiting (abuse / brute-force / DoS): per client certificate, shared across instances via Redis. If Redis is
  // unavailable the limiter errors and the request is refused (fail closed), never silently unlimited.
  await app.register(rateLimit, {
    global: true, max: d.cfg.rateLimitPerSecond, timeWindow: 1000, nameSpace: "ts-rl:", skipOnError: false,
    ...(d.rateLimitRedis ? { redis: d.rateLimitRedis } : {}),
    keyGenerator: (req) => { try { return peerThumb(req as unknown as FastifyRequest); } catch { return `ip:${req.ip}`; } },
    errorResponseBuilder: () => Object.assign(new Error("rate limited"), { statusCode: 429 }),
  });
  // ---------- request tracing: step timings + one request_log row per request (written AFTER the response, never on the request path) ----------
  interface Lc { orgId?: string; clientId?: string; signal?: string; outcome?: string; errorCode?: string; telcoId?: string; telcoMs?: number; reason?: string; reasonClass?: string; subjectRef?: string }
  interface Tr { t0: number; last: number; steps: Array<{ s: string; ms: number }>; lc: Lc }
  const trOf = (req: FastifyRequest) => (req as FastifyRequest & { tr?: Tr }).tr as Tr;
  const lap = (req: FastifyRequest, name: string) => { const t = trOf(req); const n = performance.now(); t.steps.push({ s: name, ms: Math.round((n - t.last) * 10) / 10 }); t.last = n; };
  const pendingLogs = new Set<Promise<void>>();
  app.decorate("drainLogs", async () => { await Promise.allSettled([...pendingLogs]); });
  const routeTable: Array<{ method: string; url: string }> = [];
  app.addHook("onRoute", (r) => { for (const m of ([] as string[]).concat(r.method as string | string[])) if (m !== "HEAD") routeTable.push({ method: m, url: r.url }); });
  app.decorate("routeTable", routeTable);
  // Only HTTP/1.1 is served: HTTP/0.9-style request lines (no version) and 1.0 are refused, and Expect: 100-continue is never honoured
  // (the body limit is enforced before any "100 Continue" invitation to upload).
  app.server.on("checkContinue", (_req, res) => { res.writeHead(417, { connection: "close" }); res.end(); });
  app.server.on("checkExpectation", (_req, res) => { res.writeHead(417, { connection: "close" }); res.end(); });
  app.addHook("onRequest", async (req, reply) => { if (req.raw.httpVersion !== "1.1") return reply.code(505).header("connection", "close").type("text/plain").send("HTTP/1.1 only"); });
  app.addHook("onRequest", async (req) => { const t = performance.now(); (req as FastifyRequest & { tr?: Tr }).tr = { t0: t, last: t, steps: [], lc: {} }; });
  app.addHook("onResponse", async (req, reply) => {
    const t = trOf(req); const route = req.routeOptions?.url;
    if (!t || !route || !["GET", "POST"].includes(req.method)) return;       // unmatched paths are not logged (no attacker-controlled strings in the log)
    const lc = t.lc, status = reply.statusCode, total = Math.round(performance.now() - t.t0);
    const outcome = lc.outcome ?? (status >= 500 ? "ERROR" : status >= 400 ? "REJECTED" : "OK");
    const reason = (lc.reason ?? "").replace(/\+[0-9]{5,}/g, "[n]").slice(0, 200);
    // OpenTelemetry: after the response, from timings already measured; only allow-listed attributes can leave the process (T-064).
    (d.telemetry ?? NOOP_TELEMETRY).request({ startMs: t.t0, endMs: t.t0 + total, steps: t.steps, failed: status >= 500,
      attrs: { correlation_id: String(req.id), "http.request.method": req.method, "http.route": route, "http.response.status_code": status, "ts.signal": lc.signal, "ts.outcome": outcome, "ts.error_code": lc.errorCode, "ts.telco_id": lc.telcoId, "ts.reason_class": lc.reasonClass ?? classifyReason(outcome, reason), "ts.total_ms": total, "ts.telco_ms": Math.round(lc.telcoMs ?? 0), "ts.overhead_ms": Math.max(0, total - Math.round(lc.telcoMs ?? 0)) } });
    const p = (async () => {
      try {
        await d.pool.query(
          `INSERT INTO request_log(correlation_id, org_id, client_id, method, route, signal, http_status, outcome, error_code, telco_id, reason_class, reason, total_ms, telco_ms, steps, subject_ref)
           VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15::jsonb,$16)`,
          [String(req.id), lc.orgId ?? null, lc.clientId ?? null, req.method, route, lc.signal ?? null, status, outcome, lc.errorCode ?? null, lc.telcoId ?? null, lc.reasonClass ?? classifyReason(outcome, reason), reason, total, Math.round(lc.telcoMs ?? 0), JSON.stringify(t.steps), lc.subjectRef ?? null]);
      } catch { d.log.error({ correlation_id: String(req.id) }, "request_log_write_failed"); }     // observability must never break serving; the failure itself is logged
    })();
    pendingLogs.add(p); void p.finally(() => pendingLogs.delete(p));
  });
  app.addHook("onSend", async (_req, reply, payload) => {
    reply.header("cache-control", "no-store").header("x-content-type-options", "nosniff").header("strict-transport-security", "max-age=63072000; includeSubDomains");
    return payload;
  });
  app.addContentTypeParser("application/json", { parseAs: "buffer", bodyLimit: 4096 }, (_r, body, done) => done(null, body));
  app.addContentTypeParser("application/x-www-form-urlencoded", { parseAs: "string", bodyLimit: 4096 }, (_r, body, done) => done(null, body));

  const secEvent = (e: { cid: string; action: string; outcome: string; actor?: string; org?: string; reason?: string }) =>
    d.log.warn({ "event.category": "security", "event.action": e.action, "event.outcome": e.outcome, correlation_id: e.cid, actor: e.actor ?? "anonymous", reason: e.reason }, "security_event");

  // AB-09 timing floor: error paths and answers that involve no telco call are held to a minimum response time so latency
  // cannot be used to tell which step refused (or whether a number is routable). Shedding rate-limited traffic is NOT delayed.
  const floorMs = d.cfg.minResponseMs ?? 0;
  const floorDelay = async (req: FastifyRequest): Promise<void> => {
    const t = trOf(req); if (!t || floorMs <= 0) return;
    const wait = floorMs - (performance.now() - t.t0);
    if (wait > 0) await new Promise((r) => setTimeout(r, wait));
  };

  app.setErrorHandler(async (err, req, reply) => {
    const cid = (req.id as string) ?? randomUUID();
    let code: ErrorCode = "INTERNAL";
    let reason = "unhandled";
    if (err instanceof ApiError) { code = err.code; reason = err.reason; }
    else if ((err as { statusCode?: number }).statusCode === 413) { code = "PAYLOAD_TOO_LARGE"; reason = "body too large"; }
    else if ((err as { statusCode?: number }).statusCode === 429) { code = "RATE_LIMITED"; reason = "rate limit exceeded"; }
    else if (((err as { statusCode?: number }).statusCode ?? 500) < 500) { code = "INVALID_REQUEST"; reason = (err as { code?: string }).code ?? "client error"; }
    else d.log.error({ correlation_id: cid, err_name: (err as Error).name }, "internal_error");   // no message/stack: may contain data
    { const t = trOf(req); if (t) { t.lc.errorCode = code; t.lc.reason = t.lc.reason ?? reason; if (!t.lc.outcome) t.lc.outcome = ERRORS[code].status >= 500 ? "ERROR" : "REJECTED"; } }
    const actor = (req as FastifyRequest & { actor?: string }).actor ?? "anonymous";
    secEvent({ cid, action: `request.${code.toLowerCase()}`, outcome: "failure", actor, reason });
    // Rate-limited and oversized requests are counted in the security log and request log, NOT written to the hash-chained audit
    // (an attacker above the limit must not be able to turn every refused request into a serialised database write).
    if (code !== "INTERNAL" && code !== "RATE_LIMITED" && code !== "PAYLOAD_TOO_LARGE") await d.audit.record({ correlationId: cid, actor, action: "request.rejected", outcome: code, detail: { reason } }).catch(() => undefined);
    const p = problem(code, cid);
    if (code !== "RATE_LIMITED") await floorDelay(req);     // AB-09: refusals do not return measurably faster than a normal answer
    return reply.code(p.status).type("application/problem+json").send(p);
  });
  app.setNotFoundHandler(async (req, reply) => { const p = problem("NOT_FOUND", req.id as string); return reply.code(404).send(p); });


  async function authenticate(req: FastifyRequest, scope: string): Promise<Ctx> {
    const thumb = peerThumb(req);
    const h = req.headers.authorization;
    if (!h?.startsWith("Bearer ") || h.length > 4096) throw new ApiError("AUTHENTICATION_FAILED", "missing bearer token");
    const claims = await verifyAccessToken(d.kms, { issuer: d.cfg.issuer, audience: d.cfg.audience }, h.slice(7), thumb);
    (req as FastifyRequest & { actor?: string }).actor = claims.clientId;
    trOf(req).lc.clientId = claims.clientId;
    const client = await lookupClient(d.pool, claims.clientId);          // revocation/suspension takes effect immediately
    if (!client || !clientUsable(client)) throw new ApiError("AUTHENTICATION_FAILED", "client not usable");
    trOf(req).lc.orgId = client.orgId;
    if (!claims.scopes.includes(scope) || !client.scopes.includes(scope)) throw new ApiError("ACCESS_DENIED", `scope ${scope} not granted`);
    return { client, thumb, scopes: claims.scopes, correlationId: req.id as string };
  }
  /** A POST without a body (or with an unparsed content type) has no Buffer: treat it as empty so every later step sees a Buffer and answers 400, never a 500. */
  const bodyBuf = (req: FastifyRequest): Buffer => (Buffer.isBuffer(req.body) ? req.body : Buffer.alloc(0));
  const parseBody = (req: FastifyRequest): unknown => {
    try { return JSON.parse(bodyBuf(req).toString("utf8")); } catch { throw new ApiError("INVALID_REQUEST", "malformed json"); }
  };

  // ---------- token endpoint (client credentials + private_key_jwt, mTLS-bound) ----------
  app.post("/oauth/token", { config: { rateLimit: { max: d.cfg.tokenRateLimitPerSecond, timeWindow: 1000 } } }, async (req, reply) => {
    const cid = req.id as string;
    const thumb = peerThumb(req);
    const f = new URLSearchParams(req.body as string);
    const allowed = new Set(["grant_type", "client_id", "client_assertion_type", "client_assertion", "scope"]);
    for (const k of f.keys()) if (!allowed.has(k)) throw new ApiError("INVALID_REQUEST", "unexpected parameter");
    if (f.get("grant_type") !== "client_credentials" || f.get("client_assertion_type") !== "urn:ietf:params:oauth:client-assertion-type:jwt-bearer")
      throw new ApiError("INVALID_REQUEST", "unsupported grant or client authentication");
    const clientId = f.get("client_id") ?? "", assertion = f.get("client_assertion") ?? "";
    if (!clientId || !assertion || assertion.length > 4000) throw new ApiError("INVALID_REQUEST", "missing parameters");
    (req as FastifyRequest & { actor?: string }).actor = clientId;
    const client = await lookupClient(d.pool, clientId);
    if (!client || !clientUsable(client)) throw new ApiError("AUTHENTICATION_FAILED", "client not usable");
    await verifyClientAssertion(d.pool, d.store, { assertion, clientId, audience: d.cfg.tokenEndpoint, thumb });
    const requested = (f.get("scope") ?? "").split(" ").filter(Boolean);
    const scope = (requested.length ? requested : client.scopes).filter((s) => client.scopes.includes(s));
    if (!scope.length || (requested.length && scope.length !== requested.length)) throw new ApiError("ACCESS_DENIED", "requested scope not permitted");
    const t = await issueAccessToken(d.kms, { issuer: d.cfg.issuer, audience: d.cfg.audience }, { clientId, scope, thumb });
    await d.audit.record({ correlationId: cid, actor: clientId, action: "token.issued", orgId: client.orgId, outcome: "OK", detail: { scope: scope.join(" ") } });
    return reply.header("content-type", "application/json").send({ access_token: t.token, token_type: "Bearer", expires_in: t.expiresIn, scope: scope.join(" ") });
  });
  app.get("/.well-known/jwks.json", async () => d.kms.verificationJwks());

  // ---------- consent management ----------
  app.post("/v1/consents", async (req, reply) => {
    const ctx = await authenticate(req, "consent:write");
    await verifyRequestSignature(d.pool, d.store, { jws: hdr(req, "x-request-signature"), clientId: ctx.client.clientId, thumb: ctx.thumb, method: "POST", path: "/v1/consents", rawBody: bodyBuf(req), skewSeconds: d.cfg.requestSkewSeconds });
    const b = parseBody(req);
    if (!validateCreateConsent(b)) throw new ApiError("INVALID_REQUEST", "schema");
    const body = b as { phoneNumber: string; consentRef: string; purposeCode: string; signals: string[]; expiresAt: string };
    await d.limiter.consentCreate(ctx.client.orgId);
    const exp = new Date(body.expiresAt);
    const maxDays = Number((await d.pool.query("SELECT value FROM platform_setting WHERE key='consent.max_days'")).rows[0]?.value ?? 0);   // configurable policy; fail closed if unset
    if (Number.isNaN(exp.getTime()) || exp.getTime() <= Date.now() || !maxDays || exp.getTime() > Date.now() + maxDays * 864e5) throw new ApiError("INVALID_REQUEST", "expiry out of range");
    const hash = await subjectHash(d.kms, body.phoneNumber);
    const id = await withOrgTx(d.pool, ctx.client.orgId, (tx) => createConsent(tx, ctx.client.orgId, { consentRef: body.consentRef, subjectHash: hash, purpose: body.purposeCode, signals: body.signals, expiresAt: exp }));
    if (!id) throw new ApiError("INVALID_REQUEST", "duplicate consent reference");
    await d.audit.record({ correlationId: ctx.correlationId, actor: ctx.client.clientId, action: "consent.created", orgId: ctx.client.orgId, outcome: "OK", detail: { purpose: body.purposeCode } });
    return reply.code(201).send({ id, consentRef: body.consentRef, correlationId: ctx.correlationId });
  });
  app.get("/v1/consents/:id", async (req) => {
    const ctx = await authenticate(req, "consent:read");
    const id = (req.params as { id: string }).id;
    if (!UUID_RE.test(id)) throw new ApiError("NOT_FOUND", "bad id");
    const c = await withOrgTx(d.pool, ctx.client.orgId, (tx) => getConsent(tx, id));
    if (!c) throw new ApiError("NOT_FOUND", "no such consent for this organisation");   // same answer for "other org's" and "nonexistent"
    return { id: c.id, consentRef: c.consent_ref, purposeCode: c.purpose_code, signals: c.signals, expiresAt: c.expires_at, revoked: c.revoked_at !== null, correlationId: ctx.correlationId };
  });
  app.post("/v1/consents/:id/revoke", async (req) => {
    const ctx = await authenticate(req, "consent:write");
    const id = (req.params as { id: string }).id;
    if (!UUID_RE.test(id)) throw new ApiError("NOT_FOUND", "bad id");
    await verifyRequestSignature(d.pool, d.store, { jws: hdr(req, "x-request-signature"), clientId: ctx.client.clientId, thumb: ctx.thumb, method: "POST", path: `/v1/consents/${id}/revoke`, rawBody: Buffer.alloc(0), skewSeconds: d.cfg.requestSkewSeconds });
    const ok = await withOrgTx(d.pool, ctx.client.orgId, (tx) => revokeConsent(tx, id));
    if (!ok) throw new ApiError("NOT_FOUND", "no such active consent for this organisation");
    await d.audit.record({ correlationId: ctx.correlationId, actor: ctx.client.clientId, action: "consent.revoked", orgId: ctx.client.orgId, outcome: "OK" });
    return { id, revoked: true, correlationId: ctx.correlationId };
  });

  // ---------- statements (participants see only their own; RLS enforces it) ----------
  app.get("/v1/statements", async (req) => {
    const ctx = await authenticate(req, "statements:read");
    const r = await withOrgTx(d.pool, ctx.client.orgId, (tx) => tx.query("SELECT id, period_start, period_end, currency, usage_count, total_minor FROM statement ORDER BY period_start DESC LIMIT 100"));
    return { statements: r.rows.map((x) => ({ id: x.id, periodStart: x.period_start, periodEnd: x.period_end, currency: x.currency, usageCount: x.usage_count, totalMinor: Number(x.total_minor) })), correlationId: ctx.correlationId };
  });
  app.get("/v1/statements/:id", async (req) => {
    const ctx = await authenticate(req, "statements:read");
    const id = (req.params as { id: string }).id;
    if (!UUID_RE.test(id)) throw new ApiError("NOT_FOUND", "bad id");
    const r = await withOrgTx(d.pool, ctx.client.orgId, (tx) => tx.query("SELECT id, period_start, period_end, currency, lines, usage_count, total_minor FROM statement WHERE id = $1", [id]));
    const x = r.rows[0];
    if (!x) throw new ApiError("NOT_FOUND", "no such statement for this organisation");   // same answer for another organisation's statement and a nonexistent one
    return { id: x.id, periodStart: x.period_start, periodEnd: x.period_end, currency: x.currency, lines: x.lines, usageCount: x.usage_count, totalMinor: Number(x.total_minor), correlationId: ctx.correlationId };
  });

  // ---------- signals (one hardened pipeline for every signal) ----------
  interface SignalDef { path: string; scope: string; signal: Signal; validate: (b: unknown) => boolean; maxAge: boolean; params?: (b: Record<string, unknown>) => SignalParams | null }
  const SIGNAL_DEFS: SignalDef[] = [
    { path: "/v1/signals/sim-swap/check", scope: "sim-swap:check", signal: "SIM_SWAP", validate: validateSimSwapCheck, maxAge: true },
    { path: "/v1/signals/device-swap/check", scope: "device-swap:check", signal: "DEVICE_SWAP", validate: validateDeviceSwapCheck, maxAge: true },
    { path: "/v1/signals/call-forwarding/check", scope: "call-forwarding:check", signal: "CALL_FORWARDING", validate: validateCallForwardingCheck, maxAge: false },
    { path: "/v1/signals/kyc-match/check", scope: "kyc-match:check", signal: "KYC_MATCH", validate: validateKycMatch, maxAge: false },
    // Second-wave signals. `params` turns the validated body into adapter parameters and returns null for semantically invalid values (400, same as a schema failure).
    { path: "/v1/signals/number-recycling/check", scope: "number-recycling:check", signal: "NUMBER_RECYCLING", validate: validateNumberRecycling, maxAge: false,
      params: (b) => validPastDate(String(b["specifiedDate"]), MAX_RECYCLING_LOOKBACK_DAYS) ? { specifiedDate: String(b["specifiedDate"]) } : null },
    { path: "/v1/signals/kyc-tenure/check", scope: "kyc-tenure:check", signal: "KYC_TENURE", validate: validateKycTenure, maxAge: false, params: (b) => ({ minTenureDays: Number(b["minTenureDays"]) }) },
    { path: "/v1/signals/device-location/check", scope: "device-location:check", signal: "DEVICE_LOCATION", validate: validateDeviceLocation, maxAge: false,
      params: (b) => ({ area: { latitude: Number(b["latitude"]), longitude: Number(b["longitude"]), radiusMeters: Number(b["radiusMeters"]) }, ...(typeof b["maxAgeSeconds"] === "number" ? { maxAgeSeconds: b["maxAgeSeconds"] } : {}) }) },
    { path: "/v1/signals/device-roaming/check", scope: "device-roaming:check", signal: "DEVICE_ROAMING", validate: validateDeviceRoaming, maxAge: false },
  ];
  for (const def of SIGNAL_DEFS) {
    app.post(def.path, async (req, reply) => {
      const t0 = performance.now();
      const ctx = await authenticate(req, def.scope); trOf(req).lc.signal = def.signal; lap(req, "auth");
      await verifyRequestSignature(d.pool, d.store, { jws: hdr(req, "x-request-signature"), clientId: ctx.client.clientId, thumb: ctx.thumb, method: "POST", path: def.path, rawBody: bodyBuf(req), skewSeconds: d.cfg.requestSkewSeconds });
      lap(req, "signature");
      const b = parseBody(req);
      if (!def.validate(b)) throw new ApiError("INVALID_REQUEST", "schema");
      const sp = def.params ? def.params(b as Record<string, unknown>) : undefined;
      if (sp === null) throw new ApiError("INVALID_REQUEST", "schema");
      lap(req, "validate");
      const body = b as { phoneNumber: string; maxAge?: number; purposeCode: string; consentRef: string } & KycInput;
      const org = ctx.client.orgId;
      const meter = async (outcome: string, telco: string | null, telcoMs: number, reasonClass = "rejected") => {
        const billable = outcome === "TRUE" || outcome === "FALSE";   // no charge on platform/telco failure, unsupported or rejection
        await withOrgTx(d.pool, org, (tx) => tx.query(
          "INSERT INTO usage_record(org_id, signal, telco_id, outcome, billable, total_ms, telco_ms, correlation_id, reason_class) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9)",
          [org, def.signal, telco, outcome, billable, Math.max(0, Math.round(performance.now() - t0)), Math.round(telcoMs), ctx.correlationId, reasonClass]));
      };

      // Kill switches fail closed: if state cannot be read, the request is not served.
      const ks = await d.pool.query("SELECT scope FROM kill_switch WHERE enabled AND ((scope='participant' AND key=$1) OR (scope='signal' AND key=$2))", [ctx.client.clientId, def.signal]);
      if (ks.rows.some((r) => r.scope === "participant")) { await meter("REJECTED", null, 0, "kill_switch"); throw new ApiError("ACCESS_DENIED", "participant kill switch"); }
      const sg = await d.pool.query("SELECT enabled FROM signals WHERE id = $1", [def.signal]);
      const signalOn = sg.rows[0]?.enabled === true && !ks.rows.some((r) => r.scope === "signal");

      lap(req, "policy");
      // Entitlement: the organisation must be allowed this signal for this purpose (set during onboarding, changed only with approval).
      const ent = await d.pool.query("SELECT purposes FROM org_entitlement WHERE org_id=$1 AND signal=$2", [org, def.signal]).catch(() => { throw new ApiError("SERVICE_UNAVAILABLE", "entitlement lookup failed"); });
      if (!(ent.rows[0]?.purposes as string[] | undefined)?.includes(body.purposeCode)) { await meter("REJECTED", null, 0, "rejected"); throw new ApiError("ACCESS_DENIED", "signal/purpose not entitled"); }
      // Hard quotas first (cheap, before any consent/DB/telco work). Exceeding one is a generic 429; fail closed if the limiter store is down.
      const hash = await subjectHash(d.kms, body.phoneNumber); trOf(req).lc.subjectRef = hash.toString("hex").slice(0, 8);
      try {
        await d.limiter.participantSignal(org, def.signal);
        await d.limiter.subject(org, hash.toString("hex").slice(0, 32));
        if (def.signal === "DEVICE_LOCATION") await d.limiter.locationSubject(org, hash.toString("hex").slice(0, 32));    // stops triangulation by repeated probes
      } catch (e) { if (e instanceof ApiError && e.code === "RATE_LIMITED") await meter("REJECTED", null, 0, "limit"); throw e; }
      lap(req, "limits");
      const consentOk = await withOrgTx(d.pool, org, (tx) => consentValid(tx, { consentRef: body.consentRef, subjectHash: hash, purpose: body.purposeCode, signal: def.signal }));
      // Enumeration / bulk-lookup heuristics see every attempt, including ones without valid consent (probing).
      await d.abuse.observe({ orgId: org, clientId: ctx.client.clientId, msisdn: body.phoneNumber, correlationId: ctx.correlationId, consentOk });
      lap(req, "consent");
      if (!consentOk) { await meter("REJECTED", null, 0, "rejected"); throw new ApiError("CONSENT_REQUIRED", "consent missing, expired, revoked, wrong subject/purpose/signal"); }

      let status: "TRUE" | "FALSE" | "UNAVAILABLE" | "NOT_SUPPORTED" = "UNAVAILABLE", telcoId: string | null = null, telcoMs = 0, reason = "no route";
      let fields: Record<string, string> | undefined;
      if (!signalOn) reason = "signal disabled";
      else {
        const route = await routeNumber(d.pool, d.kms, body.phoneNumber, def.signal); lap(req, "route");
        if (route.kind !== "none") telcoId = route.telcoId;
        if (route.kind === "unsupported") { status = "NOT_SUPPORTED"; reason = "telco does not cover this signal"; }
        else if (route.kind === "route") {
          const adapter = await d.adapters.get(route.telcoId);
          const tk = await d.pool.query("SELECT 1 FROM kill_switch WHERE enabled AND scope='telco' AND key=$1", [route.telcoId]);
          if (!adapter) reason = "no adapter";
          else if (tk.rowCount) reason = "telco kill switch";
          else if (!(await d.limiter.telco(route.telcoId))) reason = "telco connection rate limit";
          else {
            const kyc: KycInput = {};
            if (def.signal === "KYC_MATCH") for (const f of KYC_FIELDS) { const v = (body as Record<string, unknown>)[f]; if (typeof v === "string") kyc[f] = v; }
            const r = await adapter.call({ signal: def.signal, msisdn: body.phoneNumber, ...(def.maxAge && body.maxAge !== undefined ? { maxAgeHours: body.maxAge } : {}), ...(def.signal === "KYC_MATCH" ? { kyc } : {}), ...(sp ? { params: sp } : {}), correlationId: ctx.correlationId });
            status = r.status; telcoMs = r.telcoMs; reason = r.reason; fields = r.fields; lap(req, "adapter");
          }
        }
      }
      const rc = classifyReason(status, reason);
      Object.assign(trOf(req).lc, { outcome: status, telcoId: telcoId ?? undefined, telcoMs, reason, reasonClass: rc });
      await meter(status, telcoId, telcoMs, rc);
      await d.audit.record({ correlationId: ctx.correlationId, actor: ctx.client.clientId, action: `signal.${def.signal.toLowerCase()}.check`, orgId: org, outcome: status, detail: { telco: telcoId ?? "none", telco_ms: Math.round(telcoMs), reason } });
      lap(req, "finalise");
      if (telcoMs === 0) await floorDelay(req);        // no telco round trip happened: look like one that did
      return reply.send({ signal: def.signal, result: status, ...(fields ? { fields } : {}), correlationId: ctx.correlationId });
    });
  }

  return app as unknown as FastifyInstance;
}
function hdr(req: FastifyRequest, name: string): string | undefined {
  const v = req.headers[name];
  return typeof v === "string" && v.length <= 4096 ? v : undefined;
}
