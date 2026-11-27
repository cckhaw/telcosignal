// Background worker: rollups, alert evaluation (SIEM-ready events), retention. Runs under its own least-privilege database role.
import { makeLogger } from "../common/log.js";
import { makePool } from "../db/pool.js";
import { refreshRollups } from "../ops/rollups.js";
import { evaluateAlerts } from "../ops/alerts.js";
import { runRetention } from "../ops/retention.js";
const url = process.env["TS_WORKER_URL"]; if (!url) throw new Error("missing required configuration TS_WORKER_URL");
const log = makeLogger(); const pool = makePool(url, { max: 3 });
let last = 0;
async function tick() {
  try {
    await refreshRollups(pool);
    for (const e of await evaluateAlerts(pool)) log.warn({ "event.category": "alert", "event.action": e.action, rule: e.ruleId, severity: e.severity, observed: e.observed, threshold: e.threshold, alert_id: e.alertId }, "security_event");
    if (Date.now() - last > 3_600_000) { last = Date.now(); log.info(await runRetention(pool), "retention_run"); }
  } catch { log.error("worker_tick_failed"); }
}
await tick();
const timer = setInterval(() => void tick(), Number(process.env["TS_WORKER_INTERVAL_MS"] ?? 30_000));
for (const sig of ["SIGTERM", "SIGINT"] as const) process.on(sig, () => { clearInterval(timer); void pool.end().then(() => process.exit(0)); });
