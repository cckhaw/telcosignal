import type { FastifyInstance } from "fastify";
import { buildAdminServer, type AdminDeps } from "./server.js";
import { registerPages } from "./pages.js";
import { registerOpsPages } from "./ops-pages.js";
import type { Pool } from "../db/pool.js";
import type { QueryPool } from "../adapters/registry.js";
export type { AdminConfig, AdminDeps } from "./server.js";
export async function buildAdmin(d: AdminDeps): Promise<FastifyInstance> {
  const { app, route } = await buildAdminServer(d);
  registerPages(d, route);
  registerOpsPages(d, route);
  return app;
}

/** The admin process reads telco configuration through ITS OWN restricted database role (never the participant role): each statement runs
 *  in a short transaction carrying the staff scope that row-level security requires. */
export function staffScopedPool(pool: Pool): QueryPool {
  return {
    async query(sql, params) {
      const c = await pool.connect();
      try {
        await c.query("BEGIN");
        await c.query("SELECT set_config('app.admin_scope', 'all', true)");
        const r = await c.query(sql, params as unknown[]);
        await c.query("COMMIT");
        return { rows: r.rows as Array<Record<string, unknown>> };
      } catch (e) { await c.query("ROLLBACK").catch(() => undefined); throw e; } finally { c.release(); }
    },
  };
}
