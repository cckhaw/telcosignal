import { loadConfig } from "./common/config.js";
import { makeLogger } from "./common/log.js";
import { makePool } from "./db/pool.js";
import { RedisStore } from "./common/store.js";
import { LocalKms } from "./kms/local.js";
import { Audit } from "./audit/audit.js";
import { TelcoAAdapter } from "./adapters/telcoA.js";
import { TelcoBAdapter } from "./adapters/telcoB.js";
import { TelcoCAdapter } from "./adapters/telcoC.js";
import type { TelcoAdapter } from "./adapters/types.js";
import { buildParticipantServer } from "./participant-api/server.js";
import { SANDBOX_BANNER } from "./common/banner.js";
import { Limiter } from "./ratelimit/limits.js";
import { AbuseDetector } from "./abuse/enumeration.js";
import { ResilientAdapter } from "./resilience/breaker.js";

const log = makeLogger();
const cfg = loadConfig();
const pool = makePool(cfg.databaseUrl);
const store = new RedisStore(cfg.redisUrl);
const kms = new LocalKms(cfg.kmsDir);
const audit = new Audit(pool, cfg.auditSinkPath);

const adapters = new Map<string, TelcoAdapter>();
const { rows } = await pool.query("SELECT id, adapter, base_url FROM telcos WHERE state = 'active'");
for (const t of rows as Array<{ id: string; adapter: string; base_url: string }>) {
  // Construction enforces the outbound allow-list and https; a bad row fails startup rather than weakening the control.
  if (t.adapter === "camara") adapters.set(t.id, new TelcoAAdapter(t.id, t.base_url, cfg.telcoAllowList, cfg.telcoMtls, cfg.telcoTimeoutMs));
  else if (t.adapter === "proprietary") adapters.set(t.id, new TelcoBAdapter(t.id, t.base_url, cfg.telcoAllowList, cfg.telcoMtls, cfg.telcoTimeoutMs));
  else adapters.set(t.id, new TelcoCAdapter(t.id, t.id, t.base_url, cfg.telcoAllowList, cfg.telcoMtls, cfg.telcoTimeoutMs));
}
const limiter = new Limiter(store, pool, cfg.limits);
const abuse = new AbuseDetector(store, pool, kms, audit, log, cfg.abuse);
const resilient = new Map<string, TelcoAdapter>([...adapters].map(([id, a]) => [id, new ResilientAdapter(a, cfg.resilience)]));
const app = await buildParticipantServer({ cfg, pool, store, kms, audit, adapters: resilient, log, limiter, abuse, rateLimitRedis: store.redis });
await app.listen({ port: cfg.participantPort, host: process.env["TS_BIND"] ?? "0.0.0.0" });
log.info({ port: cfg.participantPort, telcos: [...adapters.keys()] }, SANDBOX_BANNER);

for (const sig of ["SIGTERM", "SIGINT"] as const) process.on(sig, () => {
  void (async () => { await app.close(); await pool.end(); await store.close(); process.exit(0); })();
});
