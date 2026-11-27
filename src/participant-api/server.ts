import Fastify, { type FastifyInstance, type FastifyRequest } from "fastify";
import rateLimit from "@fastify/rate-limit";
import type { Redis } from "ioredis";
import { randomUUID } from "node:crypto";
import type { TLSSocket } from "node:tls";
import type { Logger } from "pino";
import type { Config } from "../common/config.js";
import { ApiError, problem, type ErrorCode } from "../common/errors.js";
import type { Pool } from "../db/pool.js";
import { withOrgTx } from "../db/pool.js";
import type { EphemeralStore } from "../common/store.js";
import type { Kms } from "../kms/types.js";
import type { Audit } from "../audit/audit.js";
import type { TelcoAdapter } from "../adapters/types.js";
import { certThumbprint, issueAccessToken, verifyAccessToken, verifyClientAssertion, verifyRequestSignature } from "../identity/tokens.js";
import { clientUsable, lookupClient, type ClientRec } from "../identity/clients.js";
import { consentValid, createConsent, getConsent, revokeConsent, subjectHash } from "../consent/consent.js";
import { routeNumber } from "../router/router.js";
import { UUID_RE, validateCreateConsent, validateSimSwapCheck } from "./schemas.js";

export interface Deps { rateLimitRedis?: Redis; cfg: Config; pool: Pool; store: EphemeralStore; kms: Kms; audit: Audit; adapters: Map<string, TelcoAdapter>; log: Logger }
interface Ctx { client: ClientRec; thumb: string; scopes: string[]; correlationId: string }
const TLS12_CIPHERS = "ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384:ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-CHACHA20-POLY1305:ECDHE-RSA-CHACHA20-POLY1305";

export async function buildParticipantServer(d: Deps): Promise<FastifyInstance> {
  const app = Fastify({
    https: { key: d.cfg.tls.key, cert: d.cfg.tls.cert, ca: d.cfg.tls.participantCa, requestCert: true, rejectUnauthorized: true, minVersion: "TLSv1.2", ciphers: TLS12_CIPHERS, honorCipherOrder: true },
    bodyLimit: 4096, connectionTimeout: 10_000, requestTimeout: 8_000, keepAliveTimeout: 5_000, routerOptions: { maxParamLength: 64 },
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
  app.addHook("onSend", async (_req, reply, payload) => {
    reply.header("cache-control", "no-store").header("x-content-type-options", "nosniff").header("strict-transport-security", "max-age=63072000; includeSubDomains");
    return payload;
  });
  app.addContentTypeParser("application/json", { parseAs: "buffer", bodyLimit: 4096 }, (_r, body, done) => done(null, body));
  app.addContentTypeParser("application/x-www-form-urlencoded", { parseAs: "string", bodyLimit: 4096 }, (_r, body, done) => done(null, body));

  const secEvent = (e: { cid: string; action: string; outcome: string; actor?: string; org?: string; reason?: string }) =>
    d.log.warn({ "event.category": "security", "event.action": e.action, "event.outcome": e.outcome, correlation_id: e.cid, actor: e.actor ?? "anonymous", reason: e.reason }, "security_event");

  app.setErrorHandler(async (err, req, reply) => {
    const cid = (req.id as string) ?? randomUUID();
    let code: ErrorCode = "INTERNAL";
    let reason = "unhandled";
    if (err instanceof ApiError) { code = err.code; reason = err.reason; }
    else if ((err as { statusCode?: number }).statusCode === 413) { code = "PAYLOAD_TOO_LARGE"; reason = "body too large"; }
    else if ((err as { statusCode?: number }).statusCode === 429) { code = "RATE_LIMITED"; reason = "rate limit exceeded"; }
    else if (((err as { statusCode?: number }).statusCode ?? 500) < 500) { code = "INVALID_REQUEST"; reason = (err as { code?: string }).code ?? "client error"; }
    else d.log.error({ correlation_id: cid, err_name: (err as Error).name }, "internal_error");   // no message/stack: may contain data
    const actor = (req as FastifyRequest & { actor?: string }).actor ?? "anonymous";
    secEvent({ cid, action: `request.${code.toLowerCase()}`, outcome: "failure", actor, reason });
    if (code !== "INTERNAL") await d.audit.record({ correlationId: cid, actor, action: "request.rejected", outcome: code, detail: { reason } }).catch(() => undefined);
    const p = problem(code, cid);
    return reply.code(p.status).type("application/problem+json").send(p);
  });
  app.setNotFoundHandler(async (req, reply) => { const p = problem("NOT_FOUND", req.id as string); return reply.code(404).send(p); });


  async function authenticate(req: FastifyRequest, scope: string): Promise<Ctx> {
    const thumb = peerThumb(req);
    const h = req.headers.authorization;
    if (!h?.startsWith("Bearer ") || h.length > 4096) throw new ApiError("AUTHENTICATION_FAILED", "missing bearer token");
    const claims = await verifyAccessToken(d.kms, { issuer: d.cfg.issuer, audience: d.cfg.audience }, h.slice(7), thumb);
    (req as FastifyRequest & { actor?: string }).actor = claims.clientId;
    const client = await lookupClient(d.pool, claims.clientId);          // revocation/suspension takes effect immediately
    if (!client || !clientUsable(client)) throw new ApiError("AUTHENTICATION_FAILED", "client not usable");
    if (!claims.scopes.includes(scope) || !client.scopes.includes(scope)) throw new ApiError("ACCESS_DENIED", `scope ${scope} not granted`);
    return { client, thumb, scopes: claims.scopes, correlationId: req.id as string };
  }
  const parseBody = (raw: unknown): unknown => {
    try { return JSON.parse((raw as Buffer).toString("utf8")); } catch { throw new ApiError("INVALID_REQUEST", "malformed json"); }
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
    await verifyRequestSignature(d.pool, d.store, { jws: hdr(req, "x-request-signature"), clientId: ctx.client.clientId, thumb: ctx.thumb, method: "POST", path: "/v1/consents", rawBody: req.body as Buffer, skewSeconds: d.cfg.requestSkewSeconds });
    const b = parseBody(req.body);
    if (!validateCreateConsent(b)) throw new ApiError("INVALID_REQUEST", "schema");
    const body = b as { phoneNumber: string; consentRef: string; purposeCode: string; signals: string[]; expiresAt: string };
    const exp = new Date(body.expiresAt);
    if (Number.isNaN(exp.getTime()) || exp.getTime() <= Date.now() || exp.getTime() > Date.now() + 400 * 864e5) throw new ApiError("INVALID_REQUEST", "expiry out of range");
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

  // ---------- SIM swap ----------
  app.post("/v1/signals/sim-swap/check", async (req, reply) => {
    const t0 = performance.now();
    const ctx = await authenticate(req, "sim-swap:check");
    await verifyRequestSignature(d.pool, d.store, { jws: hdr(req, "x-request-signature"), clientId: ctx.client.clientId, thumb: ctx.thumb, method: "POST", path: "/v1/signals/sim-swap/check", rawBody: req.body as Buffer, skewSeconds: d.cfg.requestSkewSeconds });
    const b = parseBody(req.body);
    if (!validateSimSwapCheck(b)) throw new ApiError("INVALID_REQUEST", "schema");
    const body = b as { phoneNumber: string; maxAge?: number; purposeCode: string; consentRef: string };
    const org = ctx.client.orgId;
    const meter = async (outcome: string, telco: string | null, telcoMs: number) => {
      const billable = outcome === "TRUE" || outcome === "FALSE";   // no charge on platform/telco failure, unsupported or rejection
      await withOrgTx(d.pool, org, (tx) => tx.query(
        "INSERT INTO usage_record(org_id, signal, telco_id, outcome, billable, total_ms, telco_ms, correlation_id) VALUES ($1,'SIM_SWAP',$2,$3,$4,$5,$6,$7)",
        [org, telco, outcome, billable, Math.max(0, Math.round(performance.now() - t0)), Math.round(telcoMs), ctx.correlationId]));
    };

    // Kill switches fail closed: if state cannot be read, the request is not served.
    const ks = await d.pool.query("SELECT scope, key FROM kill_switch WHERE enabled AND ((scope='participant' AND key=$1) OR (scope='signal' AND key='SIM_SWAP'))", [ctx.client.clientId]);
    if (ks.rows.some((r) => r.scope === "participant")) { await meter("REJECTED", null, 0); throw new ApiError("ACCESS_DENIED", "participant kill switch"); }

    const hash = await subjectHash(d.kms, body.phoneNumber);
    const consentOk = await withOrgTx(d.pool, org, (tx) => consentValid(tx, { consentRef: body.consentRef, subjectHash: hash, purpose: body.purposeCode, signal: "SIM_SWAP" }));
    if (!consentOk) { await meter("REJECTED", null, 0); throw new ApiError("CONSENT_REQUIRED", "consent missing, expired, revoked, wrong subject/purpose/signal"); }

    let status: "TRUE" | "FALSE" | "UNAVAILABLE" | "NOT_SUPPORTED" = "UNAVAILABLE", telcoId: string | null = null, telcoMs = 0, reason = "no route";
    if (ks.rows.some((r) => r.scope === "signal")) reason = "signal kill switch";
    else {
      telcoId = await routeNumber(d.pool, body.phoneNumber);
      const adapter = telcoId ? d.adapters.get(telcoId) : undefined;
      if (adapter) {
        const tk = await d.pool.query("SELECT 1 FROM kill_switch WHERE enabled AND scope='telco' AND key=$1", [telcoId]);
        if (tk.rowCount) reason = "telco kill switch";
        else { const r = await adapter.call({ signal: "SIM_SWAP", msisdn: body.phoneNumber, ...(body.maxAge !== undefined ? { maxAgeHours: body.maxAge } : {}), correlationId: ctx.correlationId }); status = r.status; telcoMs = r.telcoMs; reason = r.reason; }
      }
    }
    await meter(status, telcoId, telcoMs);
    await d.audit.record({ correlationId: ctx.correlationId, actor: ctx.client.clientId, action: "signal.sim_swap.check", orgId: org, outcome: status, detail: { telco: telcoId ?? "none", telco_ms: Math.round(telcoMs), reason } });
    return reply.send({ signal: "SIM_SWAP", result: status, correlationId: ctx.correlationId });
  });

  return app as unknown as FastifyInstance;
}
function hdr(req: FastifyRequest, name: string): string | undefined {
  const v = req.headers[name];
  return typeof v === "string" && v.length <= 4096 ? v : undefined;
}
