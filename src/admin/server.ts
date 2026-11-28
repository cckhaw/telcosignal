import rateLimit from "@fastify/rate-limit";
import type { Redis } from "ioredis";
import Fastify, { type FastifyInstance, type FastifyReply, type FastifyRequest } from "fastify";
import { createHash, randomBytes, timingSafeEqual } from "node:crypto";
import { SignJWT, createLocalJWKSet, jwtVerify, jwtVerify as verifyJwt, type JWK } from "jose";
import { Agent, request } from "undici";
import type { Logger } from "pino";
import type { Pool, Tx } from "../db/pool.js";
import type { Audit } from "../audit/audit.js";
import type { Kms } from "../kms/types.js";
import type { AdapterRegistry } from "../adapters/registry.js";
import { ACR_PRESENT } from "./acr.js";
import { esc, h, page, raw, type PageUser, type Raw } from "./ui.js";

export const STAFF = ["platform_admin", "operations", "integration_engineer", "security_auditor", "finance"] as const;
export const RESTRICTED = ["telco_user", "bank_user"] as const;
export const ALL_ROLES: readonly string[] = [...STAFF, ...RESTRICTED];

export interface AdminConfig {
  tls: { cert: string; key: string };
  origin: string;                                  // set after listen (https://host:port)
  allowedCidrs: string[];                          // source-address allow-list for the isolated admin interface
  idleMinutes: number; absoluteHours: number;
  rateLimit: { perMinute: number; loginPerMinute: number };   // per session (per source address before sign-in); in-process counters
  syntheticPrefixes: string[];                     // the only numbers the console/tests/porting forms accept
  oidc: { issuer: string; clientId: string; clientSecret: string; authEndpoint: string; tokenEndpoint: string; jwksUri: string; ca: string; redirectUri: string; allowMockParams: boolean };
}
/** rateLimitRedis (R-015): when given, the portal's request counters are shared by every portal instance and fail closed if Redis is down; without it they are per process. */
export interface AdminDeps { cfg: AdminConfig; pool: Pool; audit: Audit; kms: Kms; log: Logger; registry?: AdapterRegistry; rateLimitRedis?: Redis }
export interface SessionUser extends PageUser { csrf: string; authTime: Date; createdAt: Date; lastSeenAt: Date; expiresAt: Date; idHash: Buffer }
export class HttpError extends Error { constructor(readonly status: number, message: string) { super(message); } }

const SESSION_COOKIE = "__Host-ts_admin", LOGIN_COOKIE = "__Host-ts_login";
const sha = (s: string) => createHash("sha256").update(s).digest();
const safeEq = (a: string, b: string) => { const x = Buffer.from(a), y = Buffer.from(b); return x.length === y.length && timingSafeEqual(x, y); };

export function ipAllowed(ip: string, list: string[]): boolean {
  const addr = ip.replace(/^::ffff:/, "");
  return list.some((entry) => {
    if (!entry.includes("/")) return entry === addr;
    const [net, bitsS] = entry.split("/") as [string, string]; const bits = Number(bitsS);
    const toInt = (s: string) => s.split(".").reduce((a, o) => ((a << 8) + Number(o)) >>> 0, 0);
    if (!/^\d+\.\d+\.\d+\.\d+$/.test(addr) || !/^\d+\.\d+\.\d+\.\d+$/.test(net)) return false;
    const mask = bits === 0 ? 0 : (~0 << (32 - bits)) >>> 0;
    return (toInt(addr) & mask) === (toInt(net) & mask);
  });
}
const parseCookies = (h: string | undefined): Record<string, string> => Object.fromEntries((h ?? "").split(";").map((c) => c.trim()).filter(Boolean).map((c) => { const i = c.indexOf("="); return [c.slice(0, i), c.slice(i + 1)]; }));
const cookie = (name: string, value: string, o: { maxAge: number; sameSite: "Strict" | "Lax" }) => `${name}=${value}; Path=/; Secure; HttpOnly; SameSite=${o.sameSite}; Max-Age=${o.maxAge}`;

export interface RouteCtx { req: FastifyRequest; reply: FastifyReply; user: SessionUser; nonce: string; form: Record<string, string>; params: Record<string, string>; tx<T>(fn: (tx: Tx) => Promise<T>): Promise<T>; authAgeSeconds: number; html(title: string, body: Raw, status?: number): FastifyReply; audit(action: string, outcome: string, orgId?: string, detail?: Record<string, string | number | boolean | null>): Promise<void>; redirect(to: string): FastifyReply }
type Handler = (c: RouteCtx) => Promise<unknown>;

export async function buildAdminServer(d: AdminDeps): Promise<{ app: FastifyInstance; route: (m: "GET" | "POST", path: string, roles: readonly string[], fn: Handler) => void }> {
  // The mock-IdP test parameters (forcing an MFA method, tampering with tokens) are a sandbox convenience. Refuse to start with them on unless the
  // identity provider is on this machine, so a forgotten flag can never reach a real deployment.
  if (d.cfg.oidc.allowMockParams && !["localhost", "127.0.0.1", "[::1]", "::1"].includes(new URL(d.cfg.oidc.issuer).hostname)) throw new Error("mock OIDC parameters are enabled but the identity provider is not local: refusing to start");
  const app = Fastify({
    https: { key: d.cfg.tls.key, cert: d.cfg.tls.cert, minVersion: "TLSv1.2", connectionsCheckingInterval: 1000 }, bodyLimit: 32 * 1024, connectionTimeout: 10_000, requestTimeout: 15_000,
    disableRequestLogging: true, trustProxy: false, loggerInstance: d.log, onProtoPoisoning: "error", onConstructorPoisoning: "error", routerOptions: { maxParamLength: 80 },
  });
  const oidcAgent = new Agent({ connect: { ca: d.cfg.oidc.ca, rejectUnauthorized: true } });

  app.server.on("checkContinue", (_req, res) => { res.writeHead(417, { connection: "close" }); res.end(); });
  app.server.on("checkExpectation", (_req, res) => { res.writeHead(417, { connection: "close" }); res.end(); });
  app.addHook("onRequest", async (req, reply) => {
    if (req.raw.httpVersion !== "1.1") return reply.code(505).header("connection", "close").type("text/plain").send("HTTP/1.1 only");
    if (!ipAllowed(req.ip, d.cfg.allowedCidrs)) return reply.code(403).type("text/plain").send("forbidden");       // isolated interface: source allow-list, fail closed
    (req as FastifyRequest & { nonce?: string }).nonce = randomBytes(16).toString("base64url");
  });
  app.addHook("onSend", async (req, reply, payload) => {
    const nonce = (req as FastifyRequest & { nonce?: string }).nonce ?? "";
    reply.header("content-security-policy", `default-src 'none'; style-src 'nonce-${nonce}'; form-action 'self'; frame-ancestors 'none'; base-uri 'none'`)
      .header("cache-control", "no-store").header("x-content-type-options", "nosniff").header("x-frame-options", "DENY").header("referrer-policy", "no-referrer")
      .header("cross-origin-opener-policy", "same-origin").header("cross-origin-resource-policy", "same-origin").header("strict-transport-security", "max-age=63072000; includeSubDomains")
      .header("permissions-policy", "camera=(), microphone=(), geolocation=()");
    return payload;
  });
  // Rate limiting: per session once signed in (per source address otherwise); stricter on the sign-in endpoints.
  await app.register(rateLimit, {
    global: true, max: d.cfg.rateLimit.perMinute, timeWindow: 60_000, nameSpace: "admin-rl:",
    ...(d.rateLimitRedis ? { redis: d.rateLimitRedis, skipOnError: false } : {}),
    keyGenerator: (req) => { const c = parseCookies(req.headers.cookie)[SESSION_COOKIE]; return c && /^[A-Za-z0-9_-]{43}$/.test(c) ? `s:${sha(c).toString("hex").slice(0, 24)}` : `ip:${req.ip}`; },
    errorResponseBuilder: () => Object.assign(new Error("rate limited"), { statusCode: 429 }),
  });
  app.addContentTypeParser("application/x-www-form-urlencoded", { parseAs: "string", bodyLimit: 32 * 1024 }, (_r, body, done) => done(null, body));
  app.setNotFoundHandler(async (req, reply) => reply.code(404).type("text/html").send(page({ title: "Not found", nonce: (req as FastifyRequest & { nonce?: string }).nonce ?? "", body: h`<p>Not found.</p>` })));
  app.setErrorHandler(async (err, req, reply) => {
    const nonce = (req as FastifyRequest & { nonce?: string }).nonce ?? "";
    const sc = (err as { statusCode?: number }).statusCode;
    const status = err instanceof HttpError ? err.status : sc && sc < 500 ? sc : 500;
    if (status >= 500) d.log.error({ err_name: (err as Error).name }, "admin_internal_error");
    return reply.code(status).type("text/html").send(page({ title: "Error", nonce, body: h`<p class="err">${status >= 500 ? "Internal error" : err instanceof HttpError ? err.message : "Request rejected"}</p>` }));
  });

  // ---------- sessions ----------
  async function loadSession(req: FastifyRequest): Promise<SessionUser | null> {
    const id = parseCookies(req.headers.cookie)[SESSION_COOKIE];
    if (!id || !/^[A-Za-z0-9_-]{43}$/.test(id)) return null;
    const idHash = sha(id);
    const r = await d.pool.query("SELECT * FROM admin_lookup_session($1)", [idHash]);
    const x = r.rows[0];
    if (!x) return null;
    const now = Date.now();
    if (new Date(x.expires_at).getTime() <= now || now - new Date(x.last_seen_at).getTime() > d.cfg.idleMinutes * 60_000) {
      await d.pool.query("UPDATE admin_session SET ended_at = now() WHERE id_hash = $1", [idHash]);     // idle or absolute timeout
      return null;
    }
    if (now - new Date(x.last_seen_at).getTime() > 10_000) await d.pool.query("UPDATE admin_session SET last_seen_at = now() WHERE id_hash = $1", [idHash]);
    return { sub: x.sub, displayName: x.display_name, role: x.role, orgId: x.org_id, csrf: x.csrf, authTime: new Date(x.auth_time), createdAt: new Date(x.created_at), lastSeenAt: new Date(x.last_seen_at), expiresAt: new Date(x.expires_at), idHash };
  }
  async function createSession(sub: string, authTime: Date): Promise<{ id: string }> {
    const id = randomBytes(32).toString("base64url");           // 256 bits; only the SHA-256 is stored
    await d.pool.query("INSERT INTO admin_session(id_hash, sub, csrf, expires_at, auth_time) VALUES ($1,$2,$3, now() + make_interval(hours => $4), $5)", [sha(id), sub, randomBytes(32).toString("base64url"), d.cfg.absoluteHours, authTime]);
    return { id };
  }

  // ---------- OIDC login (authorization code + PKCE, strict ID-token validation, phishing-resistant MFA required) ----------
  const loginLimit = { config: { rateLimit: { max: d.cfg.rateLimit.loginPerMinute, timeWindow: 60_000 } } };
  app.get("/login", loginLimit, async (req, reply) => {
    const q = req.query as Record<string, string | undefined>;
    const state = randomBytes(24).toString("base64url"), nonce = randomBytes(24).toString("base64url"), verifier = randomBytes(48).toString("base64url");
    const stepUp = q["stepup"] === "1";
    const ret = q["return"] && /^\/(?!\/)[A-Za-z0-9/_-]*$/.test(q["return"]) ? q["return"] : "/";
    const { kid, privateKey } = await d.kms.currentSigningKey();
    const jws = await new SignJWT({ st: state, n: nonce, cv: verifier, su: stepUp, rt: ret }).setProtectedHeader({ alg: "ES256", kid, typ: "login+jwt" }).setIssuedAt().setExpirationTime("5m").setIssuer("admin-portal").sign(privateKey);
    const u = new URL(d.cfg.oidc.authEndpoint);
    for (const [k, v] of Object.entries({ response_type: "code", client_id: d.cfg.oidc.clientId, redirect_uri: d.cfg.oidc.redirectUri, scope: "openid", state, nonce, code_challenge: createHash("sha256").update(verifier).digest("base64url"), code_challenge_method: "S256", ...(stepUp ? { max_age: "0", prompt: "login" } : {}) })) u.searchParams.set(k, v);
    if (d.cfg.oidc.allowMockParams) for (const [k, v] of Object.entries(q)) if (k.startsWith("mock_") || k === "login_hint") u.searchParams.set(k, String(v));   // sandbox only
    return reply.header("set-cookie", cookie(LOGIN_COOKIE, jws, { maxAge: 300, sameSite: "Lax" })).redirect(u.toString());
  });
  app.get("/oidc/callback", loginLimit, async (req, reply) => {
    const q = req.query as Record<string, string | undefined>;
    const fail = async (why: string, sub = "unknown") => {
      d.log.warn({ "event.category": "security", "event.action": "admin.login", "event.outcome": "failure", reason: why }, "security_event");
      await d.audit.record({ correlationId: randomBytes(8).toString("hex"), actor: sub, action: "admin.login", outcome: "DENIED", detail: { reason: why } }).catch(() => undefined);
      return reply.code(401).header("set-cookie", cookie(LOGIN_COOKIE, "", { maxAge: 0, sameSite: "Lax" })).type("text/html").send(page({ title: "Sign-in refused", nonce: (req as FastifyRequest & { nonce?: string }).nonce ?? "", body: h`<p class="err">Sign-in was refused.</p>` }));
    };
    try {
      const lc = parseCookies(req.headers.cookie)[LOGIN_COOKIE];
      if (!lc || !q["code"] || !q["state"]) return fail("missing login state");
      const jwks = await d.kms.verificationJwks();
      const { payload: ls } = await jwtVerify(lc, createLocalJWKSet(jwks as never), { issuer: "admin-portal", algorithms: ["ES256"], typ: "login+jwt" });
      if (!safeEq(String(ls["st"]), q["state"])) return fail("state mismatch");
      const tr = await request(d.cfg.oidc.tokenEndpoint, { method: "POST", dispatcher: oidcAgent, headers: { "content-type": "application/x-www-form-urlencoded" }, signal: AbortSignal.timeout(5000),
        body: new URLSearchParams({ grant_type: "authorization_code", code: q["code"], redirect_uri: d.cfg.oidc.redirectUri, client_id: d.cfg.oidc.clientId, client_secret: d.cfg.oidc.clientSecret, code_verifier: String(ls["cv"]) }).toString() });
      const tj = (await tr.body.json()) as { id_token?: string };
      if (tr.statusCode !== 200 || !tj.id_token) return fail("token exchange failed");
      const jr = await request(d.cfg.oidc.jwksUri, { dispatcher: oidcAgent, signal: AbortSignal.timeout(5000) });
      const idp = createLocalJWKSet((await jr.body.json()) as { keys: JWK[] });
      const { payload } = await verifyJwt(tj.id_token, idp, { issuer: d.cfg.oidc.issuer, audience: d.cfg.oidc.clientId, algorithms: ["ES256"], requiredClaims: ["sub", "exp", "iat", "auth_time", "nonce", "acr", "amr"], clockTolerance: 5 });
      if (!safeEq(String(payload["nonce"]), String(ls["n"]))) return fail("nonce mismatch");
      const amr = payload["amr"]; const sub = String(payload.sub);
      if (payload["acr"] !== ACR_PRESENT || !Array.isArray(amr) || !amr.includes("hwk")) return fail("phishing-resistant MFA not used", sub);       // fail closed
      const authTime = new Date(Number(payload["auth_time"]) * 1000), age = (Date.now() - authTime.getTime()) / 1000;
      if (age > (ls["su"] ? 120 : 600) || age < -30) return fail("authentication is not recent enough", sub);                                   // step-up needs a FRESH authentication
      const u = await d.pool.query("SELECT * FROM admin_lookup_user($1)", [sub]);
      if (!u.rows[0]) return fail("no active account for this identity", sub);                                                                       // no JIT provisioning, no default accounts
      const s = await createSession(sub, authTime);                                                                                                 // always a NEW session id (rotation)
      await d.audit.record({ correlationId: randomBytes(8).toString("hex"), actor: sub, action: ls["su"] ? "admin.stepup" : "admin.login", orgId: u.rows[0].org_id ?? "", outcome: "OK", detail: { role: u.rows[0].role } });
      return reply.header("set-cookie", [cookie(SESSION_COOKIE, s.id, { maxAge: d.cfg.absoluteHours * 3600, sameSite: "Strict" }), cookie(LOGIN_COOKIE, "", { maxAge: 0, sameSite: "Lax" })]).redirect(String(ls["rt"] ?? "/"));
    } catch { return fail("validation failed"); }
  });

  // ---------- route registration with RBAC, CSRF, Origin and tenant scoping ----------
  function route(method: "GET" | "POST", path: string, roles: readonly string[], fn: Handler) {
    app.route({ method, url: path, handler: async (req, reply) => {
      const nonce = (req as FastifyRequest & { nonce?: string }).nonce ?? "";
      const user = await loadSession(req);
      if (!user) return reply.redirect("/login");
      if (!roles.includes(user.role)) {
        await d.audit.record({ correlationId: String(req.id), actor: user.sub, action: "admin.denied", orgId: user.orgId ?? "", outcome: "ROLE", detail: { path: path.replace(/:[a-z]+/g, "*"), role: user.role } }).catch(() => undefined);
        throw new HttpError(403, "Your role may not do that.");
      }
      let form: Record<string, string> = {};
      if (method === "POST") {
        // CSRF: same-origin POST only (Origin must match), form-encoded body only, synchroniser token bound to the session.
        if (req.headers.origin !== d.cfg.origin) throw new HttpError(403, "Cross-origin request refused.");
        if (!String(req.headers["content-type"] ?? "").startsWith("application/x-www-form-urlencoded")) throw new HttpError(415, "Unsupported content type.");
        const sp = new URLSearchParams(String(req.body ?? ""));
        form = Object.fromEntries([...sp.entries()].map(([k, v]) => [k, v.slice(0, 4000)]));
        if (!safeEq(form["_csrf"] ?? "", user.csrf)) throw new HttpError(403, "Invalid CSRF token.");
      }
      const staff = (STAFF as readonly string[]).includes(user.role);
      const ctx: RouteCtx = {
        req, reply, user, nonce, form, params: req.params as Record<string, string>, authAgeSeconds: Math.floor((Date.now() - user.authTime.getTime()) / 1000),
        async tx(fn2) {          // every database read/write of the portal runs with the caller's tenant scope enforced by RLS
          const c = await d.pool.connect();
          try {
            await c.query("BEGIN");
            await c.query("SELECT set_config('app.admin_scope', $1, true), set_config('app.org_id', $2, true)", [staff ? "all" : "org", staff ? "" : user.orgId ?? ""]);
            const r = await fn2(c); await c.query("COMMIT"); return r;
          } catch (e) { await c.query("ROLLBACK").catch(() => undefined); throw e; } finally { c.release(); }
        },
        html: (title, body, status = 200) => reply.code(status).type("text/html").send(page({ title, nonce, user, csrf: user.csrf, body })),
        audit: (action, outcome, orgId, detail) => d.audit.record({ correlationId: String(req.id), actor: user.sub, action, orgId: orgId ?? user.orgId ?? "", outcome, ...(detail ? { detail } : {}) }),
        redirect: (to) => reply.redirect(to),
      };
      try { return await fn(ctx); }
      catch (e) {
        const pg = e as { code?: string; message?: string };
        if (e instanceof HttpError) throw e;
        if (pg.code === "42501") { await ctx.audit("admin.denied", "DB", undefined, { path: path.replace(/:[a-z]+/g, "*") }).catch(() => undefined); throw new HttpError(403, (pg.message ?? "not permitted").replace(/^.*ERROR:\s*/, "")); }
        if (pg.code === "P0001") throw new HttpError(409, pg.message ?? "refused");                // our own RAISE EXCEPTION messages (authored here, no internals)
        if (pg.code === "23505") throw new HttpError(409, "That already exists.");
        if (pg.code && /^(22|23)/.test(pg.code)) throw new HttpError(400, "Invalid input.");
        throw e;
      }
    } });
  }
  route("POST", "/logout", ALL_ROLES, async (c) => {
    await d.pool.query("UPDATE admin_session SET ended_at = now() WHERE id_hash = $1", [c.user.idHash]);
    await c.audit("admin.logout", "OK");
    return c.reply.header("set-cookie", cookie(SESSION_COOKIE, "", { maxAge: 0, sameSite: "Strict" })).redirect("/login");
  });
  void esc; void raw;
  return { app: app as unknown as FastifyInstance, route };
}
