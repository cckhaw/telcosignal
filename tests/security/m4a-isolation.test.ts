import { describe, it, expect, beforeAll, afterAll } from "vitest";
import { startHarness, type Harness } from "../helpers/harness.js";
import { startAdmin, type Admin, type Session } from "../helpers/admin-harness.js";

let h: Harness, a: Admin;
const S: Record<string, Session> = {};
beforeAll(async () => {
  h = await startHarness(); a = await startAdmin(h);
  for (const u of ["alice", "bob", "olivia", "ian", "fiona", "sam", "banker-a", "banker-b"]) S[u] = await a.login(u);
  // give the two banks distinguishable content
  await h.migrator.query("UPDATE organisations SET name='Synthetic Bank A' WHERE id=$1", [h.orgA]);
  await h.migrator.query("INSERT INTO telcos(id, adapter, base_url, state, org_id) SELECT 'telco-own','camara','https://localhost:1','active', id FROM organisations WHERE id=$1", [h.orgB]);
});
afterAll(async () => { await a.stop(); await h.stop(); });
const s = (u: string) => S[u]!;

describe("role-based access: every route, every role, enforced server-side", () => {
  const ROUTES: Array<[string, string[]]> = [
    ["/", ["alice", "bob", "olivia", "ian", "fiona", "sam", "banker-a", "banker-b"]],
    ["/orgs", ["alice", "bob", "olivia", "ian", "fiona", "sam", "banker-a", "banker-b"]],
    ["/changes", ["alice", "bob", "olivia", "ian", "fiona", "sam", "banker-a", "banker-b"]],
    ["/credentials", ["alice", "bob", "olivia", "ian", "fiona", "sam", "banker-a", "banker-b"]],
    ["/config", ["alice", "bob", "olivia", "ian", "fiona", "sam"]],
    ["/history", ["alice", "bob", "olivia", "ian", "fiona", "sam"]],
    ["/killswitches", ["alice", "bob", "olivia", "sam"]],
    ["/integration", ["alice", "bob", "olivia", "ian", "sam"]],
  ];
  for (const [path, allowed] of ROUTES)
    it(`GET ${path}: allowed only for ${allowed.length} of 8 identities`, async () => {
      for (const u of Object.keys(S)) expect((await s(u).get(path)).status, `${u} ${path}`).toBe(allowed.includes(u) ? 200 : 403);
    });
  it("the read-only security/audit role can view but cannot change anything", async () => {
    const forms: Array<[string, Record<string, string>]> = [
      ["/orgs", { name: "x", kind: "bank" }], ["/changes/new", { kind: "RATE_LIMIT", orgId: h.orgA, signal: "SIM_SWAP", maxPerMinute: "5" }], ["/killswitches/engage", { scope: "signal", key: "SIM_SWAP" }],
      ["/integration/test", { telcoId: "telco-a", signal: "SIM_SWAP", msisdn: "+609990000001" }], ["/credentials/register", { orgId: h.orgA, clientId: "x-client" }], ["/credentials/revoke", { clientId: "bank-a", kid: "bank-a-k1" }],
      [`/orgs/${h.orgA}/suspend`, {}], [`/orgs/${h.orgA}/advance`, { to: "testing" }], [`/orgs/${h.orgA}/tests`, {}], ["/history/rollback", { version: "1" }], ["/integration/api-version", { version: "v2", status: "current" }],
    ];
    for (const [p, f] of forms) expect((await s("sam").post(p, f)).status, p).toBe(403);
    expect((await h.migrator.query("SELECT count(*)::int n FROM config_change WHERE requested_by='sam'")).rows[0].n).toBe(0);
  });
  it("finance can manage prices only; operations cannot manage prices or admin users; integration engineers cannot suspend or engage kill switches", async () => {
    expect((await s("fiona").post("/changes/new", { kind: "PRICE_PLAN", action: "assign", orgId: h.orgA, planId: "x-plan-1" })).status).toBe(302);
    expect((await s("fiona").post("/changes/new", { kind: "RATE_LIMIT", orgId: h.orgA, signal: "SIM_SWAP", maxPerMinute: "5" })).status).toBe(403);
    expect((await s("olivia").post("/changes/new", { kind: "PRICE_PLAN", action: "assign", orgId: h.orgA, planId: "x-plan-1" })).status).toBe(403);
    expect((await s("olivia").post("/changes/new", { kind: "ADMIN_USER", sub: "zed", displayName: "Zed", role: "operations" })).status).toBe(403);
    expect((await s("ian").post(`/orgs/${h.orgA}/suspend`, {})).status).toBe(403);
    expect((await s("ian").post("/killswitches/engage", { scope: "signal", key: "SIM_SWAP" })).status).toBe(403);
    expect((await s("fiona").post("/orgs", { name: "F", kind: "bank" })).status).toBe(403);
  });
  it("denied attempts are audited", async () => {
    const { rows } = await h.migrator.query("SELECT actor, outcome FROM audit_log WHERE action='admin.denied'");
    expect(rows.length).toBeGreaterThan(20); expect(rows.some((r) => r.actor === "sam")).toBe(true);
  });
});

describe("a restricted bank user sees only their own organisation", () => {
  it("lists only its own organisation; other organisations' ids are indistinguishable from nonexistent ones", async () => {
    const list = await s("banker-a").get("/orgs");
    expect(list.text).toContain("Synthetic Bank A"); expect(list.text).not.toContain("Synthetic Bank B"); expect(list.text).not.toContain("Synthetic Bank C");
    const own = await s("banker-a").get(`/orgs/${h.orgA}`); expect(own.status).toBe(200);
    const foreign = await s("banker-a").get(`/orgs/${h.orgB}`), none = await s("banker-a").get("/orgs/00000000-0000-4000-8000-000000000000");
    expect(foreign.status).toBe(404); expect(none.status).toBe(404); const norm = (t: string) => t.replace(/nonce="[^"]+"/g, "").replace(/\s+/g, "");      // the CSP nonce is (rightly) different on every response
    expect(norm(foreign.text)).toBe(norm(none.text));
    expect(own.text).not.toContain("Synthetic Bank B");
  });
  it("sees only its own clients, keys and change requests", async () => {
    const cred = await s("banker-a").get("/credentials"); expect(cred.text).toContain("bank-a"); expect(cred.text).not.toContain("bank-b"); expect(cred.text).not.toContain("bank-c");
    const id = (await s("banker-b").post("/credentials/register", { clientId: "bank-b", certSha256: h.bankB.thumb, expiresInDays: "30", jwk: JSON.stringify({ kty: "EC", crv: "P-256", x: "a".repeat(43), y: "b".repeat(43) }) })).location!;
    expect((await s("banker-b").get(id)).status).toBe(200);
    expect((await s("banker-a").get(id)).status).toBe(404);                                  // another organisation's change request
    expect((await s("banker-a").get("/changes")).text).not.toContain(id.split("/").pop()!);
    expect((await s("banker-a").post(`${id}/withdraw`, {})).status).toBe(302);                // not theirs: a silent no-op, and the request is untouched
    expect((await h.migrator.query("SELECT status FROM config_change WHERE id=$1", [id.split("/").pop()])).rows[0].status).toBe("pending");
  });
  it("cannot request or revoke anything for another organisation", async () => {
    const forged = await s("banker-a").post("/credentials/register", { orgId: h.orgB, clientId: "bank-b", certSha256: h.bankB.thumb, expiresInDays: "30", jwk: JSON.stringify({ kty: "EC", crv: "P-256", x: "a".repeat(43), y: "b".repeat(43) }) });
    // the organisation comes from the session, never the form: the request is for banker-a's own org, so approval cannot touch bank-b
    expect(forged.status).toBe(302);
    const res = await s("alice").post(`${forged.location}/approve`, {}); expect(res.status).toBe(409);
    expect((await h.migrator.query("SELECT count(*)::int n FROM client_keys WHERE client_id='bank-b' AND kid NOT LIKE 'bank-b-%'")).rows[0].n).toBeLessThanOrEqual(0);
    expect((await s("banker-a").post("/credentials/revoke", { clientId: "bank-b", kid: h.bankB.kid })).status).toBe(403);
    await expect(a.pool.query("SELECT cfg_request('KEY_REGISTER','client:bank-b','{}'::jsonb,'banker-a',$1,NULL)", [h.orgB])).rejects.toThrow(/own organisation/);
    expect((await h.migrator.query("SELECT revoked_at FROM client_keys WHERE client_id='bank-b' AND kid=$1", [h.bankB.kid])).rows[0].revoked_at).toBeNull();
  });
  it("restricted users cannot see configuration, routing, kill switches, other tenants' telcos or the audit trail", async () => {
    for (const p of ["/config", "/history", "/killswitches", "/integration"]) expect((await s("banker-a").get(p)).status).toBe(403);
    expect((await s("banker-a").post("/changes/new", { kind: "ROUTING", action: "set_prefix", prefix: "+1234567", telcoId: "telco-a" })).status).toBe(403);
    expect((await s("banker-a").post("/orgs", { name: "Sneaky", kind: "bank" })).status).toBe(403);
  });
});

describe("row-level security protects the portal's own database role", () => {
  const scoped = async <T>(scope: "all" | "org", org: string | null, fn: (q: (sql: string) => Promise<Record<string, unknown>[]>) => Promise<T>): Promise<T> => {
    const c = await a.pool.connect();
    try { await c.query("BEGIN"); await c.query("SELECT set_config('app.admin_scope',$1,true), set_config('app.org_id',$2,true)", [scope, org ?? ""]); const r = await fn(async (sql) => (await c.query(sql)).rows); await c.query("ROLLBACK"); return r; } finally { c.release(); }
  };
  it("with no scope at all, tenant data is invisible; with an organisation scope only that organisation's rows are visible", async () => {
    await h.consent(h.bankA, "+609990009001"); 
    const none = await scoped("org", null, async (q) => [(await q("SELECT count(*)::int n FROM organisations"))[0]!.n, (await q("SELECT count(*)::int n FROM clients"))[0]!.n, (await q("SELECT count(*)::int n FROM telcos"))[0]!.n, (await q("SELECT count(*)::int n FROM config_change"))[0]!.n]);
    expect(none).toEqual([0, 0, 0, 0]);
    const onlyA = await scoped("org", h.orgA, async (q) => ({ orgs: await q("SELECT id FROM organisations"), clients: await q("SELECT client_id, org_id FROM clients"), usage: await q("SELECT DISTINCT org_id FROM usage_record"), prices: await q("SELECT count(*)::int n FROM price_plan"), kill: await q("SELECT count(*)::int n FROM kill_switch"), routes: await q("SELECT count(*)::int n FROM route_prefix"), users: await q("SELECT count(*)::int n FROM admin_user"), hist: await q("SELECT count(*)::int n FROM config_history") }));
    expect(onlyA.orgs).toEqual([{ id: h.orgA }]); expect(onlyA.clients.every((r) => r.org_id === h.orgA)).toBe(true); expect(onlyA.clients.length).toBeGreaterThan(0);
    expect(onlyA.usage.every((r) => r.org_id === h.orgA)).toBe(true);
    for (const k of ["prices", "kill", "routes", "users", "hist"] as const) expect((onlyA[k][0] as { n: number }).n, k).toBe(0);           // staff-only tables are empty for a restricted scope
    const staff = await scoped("all", null, async (q) => (await q("SELECT count(*)::int n FROM organisations"))[0]!.n);
    expect(staff as number).toBeGreaterThan(2);
  });
  it("a restricted scope cannot be widened by the application's own queries", async () => {
    const r = await scoped("org", h.orgA, async (q) => (await q("SELECT count(*)::int n FROM organisations WHERE id <> current_setting('app.org_id')::uuid"))[0]!.n);
    expect(r).toBe(0);
  });
  it("the portal role cannot read the participant-plane tables at all (consents, audit log, statements of other tenants)", async () => {
    await expect(a.pool.query("SELECT * FROM consents")).rejects.toThrow(/permission denied/i);
    await expect(a.pool.query("SELECT * FROM audit_log")).rejects.toThrow(/permission denied/i);
    await expect(a.pool.query("SELECT * FROM porting")).rejects.toThrow(/permission denied/i);
    const st = await scoped("org", h.orgA, async (q) => (await q("SELECT count(*)::int n FROM statement WHERE org_id <> current_setting('app.org_id')::uuid"))[0]!.n);
    expect(st).toBe(0);
  });
});
