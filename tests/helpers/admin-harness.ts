import { Agent, request } from "undici";
import { Writable } from "node:stream";
import { randomBytes } from "node:crypto";
import pg from "pg";
import type { FastifyInstance } from "fastify";
import { makePool, type Pool } from "../../src/db/pool.js";
import { Audit } from "../../src/audit/audit.js";
import { makeLogger } from "../../src/common/log.js";
import { buildAdmin, staffScopedPool, type AdminConfig } from "../../src/admin/index.js";
import { AdapterRegistry } from "../../src/adapters/registry.js";
import { DEFAULT_RESILIENCE } from "../../src/resilience/breaker.js";
import { startMockIdp, type MockIdp } from "../../mock/idp.js";
import type { Harness } from "./harness.js";

export interface AdminUserSeed { sub: string; name: string; role: string; org?: string }
export interface Admin {
  h: Harness; app: FastifyInstance; port: number; origin: string; pool: Pool; idp: MockIdp; logs: string[]; agent: Agent; cfg: AdminConfig;
  login(sub: string, o?: Record<string, string>, extra?: Record<string, string>): Promise<Session>;
  stop(): Promise<void>;
  users: Record<string, string>;
}
export interface Session {
  ok: boolean; status: number; cookie: string; setCookie: string[]; csrf: string; location?: string;
  get(path: string, o?: { headers?: Record<string, string> }): Promise<R>;
  post(path: string, form: Record<string, string>, o?: { csrf?: string | null; origin?: string | null; contentType?: string; raw?: string }): Promise<R>;
}
export interface R { status: number; text: string; headers: Record<string, string | string[] | undefined>; location?: string }

export async function startAdmin(h: Harness, o: { allowedCidrs?: string[]; idleMinutes?: number; reuseUsers?: boolean; perMinute?: number; loginPerMinute?: number; rateLimitRedis?: import("ioredis").Redis } = {}): Promise<Admin> {
  const logs: string[] = [];
  const log = makeLogger("debug", new Writable({ write(c, _e, cb) { logs.push(String(c)); cb(); } }));
  const srvCert = h.pki.issue("admin-server", { server: true }), idpCert = h.pki.issue("idp-server", { server: true });
  const clientSecret = randomBytes(24).toString("base64url");
  const idp = await startMockIdp({ cert: idpCert.cert, key: idpCert.key }, { clientId: "admin-portal", clientSecret, redirectUri: "https://localhost:0/oidc/callback" });
  const pool = makePool(h.urls.admin);
  const audit = new Audit(pool, h.auditSink);
  const cfg: AdminConfig = {
    tls: { cert: srvCert.cert, key: srvCert.key }, origin: "", allowedCidrs: o.allowedCidrs ?? ["127.0.0.1", "::1"], idleMinutes: o.idleMinutes ?? 15, absoluteHours: 8, rateLimit: { perMinute: o.perMinute ?? 100_000, loginPerMinute: o.loginPerMinute ?? 100_000 }, syntheticPrefixes: ["+60999"],
    oidc: { issuer: idp.issuer, clientId: "admin-portal", clientSecret, authEndpoint: `${idp.origin}/authorize`, tokenEndpoint: `${idp.origin}/token`, jwksUri: `${idp.origin}/jwks`, ca: h.pki.caCert, redirectUri: "", allowMockParams: true },
  };
  // the portal's conformance runner uses the portal's OWN restricted role, exactly as in production
  const registry = new AdapterRegistry(staffScopedPool(pool), { mtls: { ca: h.pki.caCert, cert: h.platformOut.cert, key: h.platformOut.key, allowPrivateAddresses: true }, timeoutMs: 1500, resilience: DEFAULT_RESILIENCE, envAllowList: [], ttlMs: 50, allowLoopback: true });
  const app = await buildAdmin({ cfg, pool, audit, kms: h.kms, log, registry, ...(o.rateLimitRedis ? { rateLimitRedis: o.rateLimitRedis } : {}) });
  await app.listen({ port: 0, host: "127.0.0.1" });
  const port = (app.server.address() as { port: number }).port;
  cfg.origin = `https://localhost:${port}`; cfg.oidc.redirectUri = `${cfg.origin}/oidc/callback`; idp.setRedirect(cfg.oidc.redirectUri);
  const agent = new Agent({ connect: { ca: h.pki.caCert } });

  // seed admin users as the schema owner (no default accounts exist in a fresh database)
  const before = (await h.migrator.query("SELECT count(*)::int n FROM admin_user")).rows[0].n;
  if (!o.reuseUsers && before !== 0) throw new Error("fresh database must contain no admin accounts");
  const seed: AdminUserSeed[] = [
    { sub: "alice", name: "Alice Admin", role: "platform_admin" }, { sub: "bob", name: "Bob Admin", role: "platform_admin" }, { sub: "olivia", name: "Olivia Ops", role: "operations" },
    { sub: "ian", name: "Ian Integration", role: "integration_engineer" }, { sub: "fiona", name: "Fiona Finance", role: "finance" }, { sub: "sam", name: "Sam Security", role: "security_auditor" },
    { sub: "banker-a", name: "Banker A", role: "bank_user", org: h.orgA }, { sub: "banker-b", name: "Banker B", role: "bank_user", org: h.orgB },
  ];
  if (!o.reuseUsers) for (const u of seed) await h.migrator.query("INSERT INTO admin_user(sub, display_name, role, org_id) VALUES ($1,$2,$3,$4)", [u.sub, u.name, u.role, u.org ?? null]);

  const mk = (cookie: string, csrf: string): Pick<Session, "get" | "post"> => {
    const send = async (method: string, path: string, headers: Record<string, string>, body?: string): Promise<R> => {
      const r = await request(`${cfg.origin}${path}`, { method: method as "GET", dispatcher: agent, headers: { ...(cookie ? { cookie } : {}), ...headers }, body: body ?? null, maxRedirections: 0 } as never);
      const text = await r.body.text(); const loc = r.headers["location"];
      return { status: r.statusCode, text, headers: r.headers as R["headers"], ...(typeof loc === "string" ? { location: loc } : {}) };
    };
    return {
      get: (path, opts) => send("GET", path, opts?.headers ?? {}),
      post: (path, form, opts = {}) => {
        const f = { ...form }; const token = opts.csrf === undefined ? csrf : opts.csrf; if (token !== null) f["_csrf"] = token;
        const hdr: Record<string, string> = { "content-type": opts.contentType ?? "application/x-www-form-urlencoded" };
        if (opts.origin !== null) hdr["origin"] = opts.origin ?? cfg.origin;
        return send("POST", path, hdr, opts.raw ?? new URLSearchParams(f).toString());
      },
    };
  };
  const login = async (sub: string, params: Record<string, string> = {}, extra: Record<string, string> = {}): Promise<Session> => {
    const qs = new URLSearchParams({ login_hint: sub, ...params }).toString();
    const raw = (url: string, headers: Record<string, string> = {}) => request(url, { method: "GET", dispatcher: agent, headers, maxRedirections: 0 } as never).then(async (r) => { await r.body.dump(); return { status: r.statusCode, headers: r.headers }; });
    const a = await raw(`${cfg.origin}/login?${qs}`);
    const loginCookie = ([] as string[]).concat(a.headers["set-cookie"] ?? []).map((c) => c.split(";")[0]!).join("; ");
    let loc = String(a.headers["location"] ?? "");
    const b = await raw(loc);                                    // IdP authorize -> redirect back with code
    loc = String(b.headers["location"] ?? "");
    if (!loc.startsWith(cfg.origin)) return { ok: false, status: b.status, cookie: "", setCookie: [], csrf: "", ...mk("", "") };
    let url = loc;
    if (extra["state"]) url = url.replace(/state=[^&]*/, `state=${extra["state"]}`);
    const c = await raw(url, extra["noLoginCookie"] ? {} : { cookie: loginCookie });
    const sc = ([] as string[]).concat(c.headers["set-cookie"] ?? []);
    const sess = sc.find((x) => x.startsWith("__Host-ts_admin=") && !x.startsWith("__Host-ts_admin=;"));
    const cookie = sess ? sess.split(";")[0]! : "";
    let csrf = "";
    if (cookie) { const home = await mk(cookie, "").get("/"); csrf = /name="_csrf" value="([^"]+)"/.exec(home.text)?.[1] ?? ""; }
    return { ok: c.status === 302 && !!cookie, status: c.status, cookie, setCookie: sc, csrf, location: String(c.headers["location"] ?? ""), ...mk(cookie, csrf) };
  };
  const users = Object.fromEntries(seed.map((u) => [u.sub, u.sub]));
  return {
    h, app, port, origin: cfg.origin, pool, idp, logs, agent, cfg, users, login,
    async stop() { await app.close(); await idp.close(); await agent.close(); await pool.end(); },
  };
}
void pg;
