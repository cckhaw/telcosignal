// Admin portal process (isolated interface). Separate database role, separate key directory for its own signing, separate TLS context.
import { readFileSync } from "node:fs";
import { makeLogger } from "../common/log.js";
import { makePool } from "../db/pool.js";
import { Audit } from "../audit/audit.js";
import { LocalKms } from "../kms/local.js";
import type { Kms } from "../kms/types.js";
import { AdapterRegistry } from "../adapters/registry.js";
import { buildAdmin, staffScopedPool, type AdminConfig } from "./index.js";
import { SANDBOX_BANNER } from "../common/banner.js";

const env = (n: string) => { const v = process.env[n]; if (!v) throw new Error(`missing required configuration ${n}`); return v; };
const file = (n: string) => readFileSync(env(`${n}_FILE`), "utf8");
const log = makeLogger();
const pool = makePool(env("TS_ADMIN_DB_URL"));
const audit = new Audit(pool, env("TS_AUDIT_SINK"));
// Login-state cookies are signed with the ADMIN plane's own key; the participant token-signing key is never available to the portal.
// The portal does share the number-hashing key (needed to hash numbers for porting changes without ever storing them).
const hmacKms = new LocalKms(env("TS_KMS_DIR")), signKms = new LocalKms(env("TS_ADMIN_KMS_DIR"));
const kms: Kms = {
  hmac: (k, d) => hmacKms.hmac(k, d), encrypt: (k, p, a) => signKms.encrypt(k, p, a), decrypt: (k, e, a) => signKms.decrypt(k, e, a),
  currentSigningKey: () => signKms.currentSigningKey(), verificationJwks: () => signKms.verificationJwks(), rotate: (k) => signKms.rotate(k),
};
const origin = env("TS_ADMIN_ORIGIN");
const cfg: AdminConfig = {
  tls: { cert: file("TS_ADMIN_TLS_CERT"), key: file("TS_ADMIN_TLS_KEY") }, origin,
  allowedCidrs: (process.env["TS_ADMIN_ALLOWED_CIDRS"] ?? "127.0.0.1,::1").split(",").map((s) => s.trim()).filter(Boolean),
  rateLimit: { perMinute: Number(process.env["TS_ADMIN_RATE_PER_MIN"] ?? 600), loginPerMinute: Number(process.env["TS_ADMIN_LOGIN_PER_MIN"] ?? 60) },
  idleMinutes: Number(process.env["TS_ADMIN_IDLE_MINUTES"] ?? 15), absoluteHours: Number(process.env["TS_ADMIN_ABSOLUTE_HOURS"] ?? 8),
  syntheticPrefixes: (process.env["TS_SYNTHETIC_PREFIXES"] ?? "+60999").split(",").map((s) => s.trim()),
  oidc: { issuer: env("TS_OIDC_ISSUER"), clientId: env("TS_OIDC_CLIENT_ID"), clientSecret: file("TS_OIDC_CLIENT_SECRET").trim(), authEndpoint: env("TS_OIDC_AUTH_ENDPOINT"), tokenEndpoint: env("TS_OIDC_TOKEN_ENDPOINT"), jwksUri: env("TS_OIDC_JWKS_URI"), ca: file("TS_OIDC_CA"), redirectUri: `${origin}/oidc/callback`, allowMockParams: process.env["TS_ADMIN_ALLOW_MOCK_PARAMS"] === "true" },
};
const registry = new AdapterRegistry(staffScopedPool(pool), {
  mtls: { ca: file("TS_TELCO_CA"), cert: file("TS_TELCO_CLIENT_CERT"), key: file("TS_TELCO_CLIENT_KEY"), allowPrivateAddresses: process.env["TS_ALLOW_LOOPBACK"] === "true" }, timeoutMs: Number(process.env["TS_TELCO_TIMEOUT_MS"] ?? 2000),
  resilience: { windowMs: 10_000, minRequests: 8, failureRate: 0.5, openMs: 15_000, maxConcurrent: 10 }, envAllowList: [], allowLoopback: process.env["TS_ALLOW_LOOPBACK"] === "true",
});
const app = await buildAdmin({ cfg, pool, audit, kms, log, registry });
await app.listen({ port: Number(env("TS_ADMIN_PORT")), host: process.env["TS_ADMIN_BIND"] ?? "127.0.0.1" });
log.info({ origin }, SANDBOX_BANNER);
for (const sig of ["SIGTERM", "SIGINT"] as const) process.on(sig, () => { void (async () => { await app.close(); await registry.close(); await pool.end(); process.exit(0); })(); });
