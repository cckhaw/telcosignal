import { loadConfig } from "./common/config.js";
import { makeLogger } from "./common/log.js";
import { makePool } from "./db/pool.js";
import { RedisStore } from "./common/store.js";
import { LocalKms } from "./kms/local.js";
import { Audit } from "./audit/audit.js";
import { AdapterRegistry } from "./adapters/registry.js";
import { buildParticipantServer } from "./participant-api/server.js";
import { SANDBOX_BANNER } from "./common/banner.js";
import { Limiter } from "./ratelimit/limits.js";
import { AbuseDetector } from "./abuse/enumeration.js";

const log = makeLogger();
const cfg = loadConfig();
const pool = makePool(cfg.databaseUrl);
const store = new RedisStore(cfg.redisUrl);
const kms = new LocalKms(cfg.kmsDir);
const audit = new Audit(pool, cfg.auditSinkPath);

const registry = new AdapterRegistry(pool, { mtls: cfg.telcoMtls, timeoutMs: cfg.telcoTimeoutMs, resilience: cfg.resilience, envAllowList: cfg.telcoAllowList, allowLoopback: process.env["TS_ALLOW_LOOPBACK"] === "true" });
const limiter = new Limiter(store, pool, cfg.limits);
const abuse = new AbuseDetector(store, pool, kms, audit, log, cfg.abuse);
const app = await buildParticipantServer({ cfg, pool, store, kms, audit, adapters: registry, log, limiter, abuse, rateLimitRedis: store.redis });
await app.listen({ port: cfg.participantPort, host: process.env["TS_BIND"] ?? "0.0.0.0" });
log.info({ port: cfg.participantPort, dynamic_adapter_registry: true }, SANDBOX_BANNER);

for (const sig of ["SIGTERM", "SIGINT"] as const) process.on(sig, () => {
  void (async () => { await app.close(); await pool.end(); await store.close(); process.exit(0); })();
});
