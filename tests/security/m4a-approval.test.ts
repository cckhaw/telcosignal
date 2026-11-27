import { describe, it, expect, beforeAll, afterAll } from "vitest";
import pg from "pg";
import { createHash } from "node:crypto";
import { startHarness, num, type Harness } from "../helpers/harness.js";
import { startAdmin, type Admin, type Session, type R } from "../helpers/admin-harness.js";

let h: Harness, a: Admin;
let alice: Session, bob: Session, olivia: Session, ian: Session, fiona: Session, sam: Session, bankerA: Session;
beforeAll(async () => {
  h = await startHarness(); a = await startAdmin(h);
  const ss = (await Promise.all(["alice", "bob", "olivia", "ian", "fiona", "sam", "banker-a"].map((u) => a.login(u)))) as Session[];
  [alice, bob, olivia, ian, fiona, sam, bankerA] = ss as [Session, Session, Session, Session, Session, Session, Session];
});
afterAll(async () => { await a.stop(); await h.stop(); });
const idOf = (r: R) => r.location!.split("/").pop()!;
const status = async (id: string) => (await h.migrator.query("SELECT status FROM config_change WHERE id=$1", [id])).rows[0].status as string;
const su = async <T>(fn: (c: pg.Client) => Promise<T>): Promise<T> => { const c = new pg.Client({ connectionString: h.adminUrl.replace(/\/[^/]*$/, `/${h.dbName}`) }); await c.connect(); try { return await fn(c); } finally { await c.end(); } };
const rate = (org: string, max: string, signal = "SIM_SWAP") => ({ kind: "RATE_LIMIT", orgId: org, signal, maxPerMinute: max });
const limitOf = async (org: string, signal = "SIM_SWAP") => (await h.migrator.query("SELECT max_per_minute m FROM rate_limit_override WHERE org_id=$1 AND signal=$2", [org, signal])).rows[0]?.m as number | undefined;
const decideSql = (id: string, who: string, approve = true, age = 10) => a.pool.query("SELECT cfg_decide($1,$2,$3,'t',$4)", [id, who, approve, age]);

describe("the two-person rule cannot be bypassed", () => {
  it("a requester can never approve (or reject) their own change: through the UI and directly in the database", async () => {
    const r = await alice.post("/changes/new", rate(h.orgA, "50")); expect(r.status).toBe(302); const id = idOf(r);
    const own = await alice.post(`/changes/${id}/approve`, {}); expect(own.status).toBe(403); expect(own.text).toMatch(/different person/);
    expect((await alice.post(`/changes/${id}/reject`, {})).status).toBe(403);
    await expect(decideSql(id, "alice")).rejects.toThrow(/different person/);
    await expect(decideSql(id, "alice", false)).rejects.toThrow(/different person/);
    expect(await status(id)).toBe("pending"); expect(await limitOf(h.orgA)).toBeUndefined();
    expect((await bob.post(`/changes/${id}/approve`, { note: "ok" })).status).toBe(302);       // a different person can
    expect(await status(id)).toBe("applied"); expect(await limitOf(h.orgA)).toBe(50);
  });
  it("the database constraint itself forbids requester == decider, even for the schema owner", async () => {
    const r = await olivia.post("/changes/new", rate(h.orgB, "7")); const id = idOf(r);
    await expect(h.migrator.query("UPDATE config_change SET status='applied', decided_by='olivia', decided_at=now() WHERE id=$1", [id])).rejects.toThrow(/check constraint|permission denied/i);
  });
  it("the portal's DB role has NO write access to any high-risk table (SQL injection or a bug cannot skip approval)", async () => {
    const stmts = [
      "INSERT INTO price_plan(id,currency,platform_fee_minor,signal_price_minor,tiers) VALUES ('x-plan','MYR',1,'{}','[{\"upTo\":null,\"pct\":100}]')", "UPDATE rate_limit_override SET max_per_minute = 1", "INSERT INTO route_prefix(prefix,telco_id) VALUES ('+999','telco-a')",
      "UPDATE kill_switch SET enabled=false", "INSERT INTO kill_switch(scope,key,enabled) VALUES ('signal','SIM_SWAP',true)", "UPDATE telcos SET base_url='https://evil.example'", "INSERT INTO client_keys(client_id,kid,jwk,cert_sha256,expires_at) VALUES ('bank-a','x','{}','" + "A".repeat(43) + "', now())",
      "UPDATE organisations SET state='active'", "INSERT INTO org_entitlement(org_id,signal,purposes) VALUES (gen_random_uuid(),'SIM_SWAP','{FRAUD_PREVENTION}')", "UPDATE config_change SET status='applied'", "DELETE FROM config_change",
      "INSERT INTO config_history(change_id,kind,target,requested_by,applied_by) VALUES (gen_random_uuid(),'x','y','a','b')", "UPDATE admin_user SET role='platform_admin'", "INSERT INTO admin_user(sub,display_name,role) VALUES ('evil','Evil','platform_admin')",
      "UPDATE platform_setting SET value='9999'", "INSERT INTO endpoint_allowlist(origin) VALUES ('https://evil.example')", "INSERT INTO porting(subject_hash,telco_id,effective_from) VALUES ('\\x00','telco-a',now())", "UPDATE client_keys SET expires_at = now() + interval '10 years'",
    ];
    for (const sql of stmts) await expect(a.pool.query(sql), sql).rejects.toThrow(/permission denied|row-level security/i);
  });
  it("only the designated approver roles may decide each kind; auditors and restricted users never can", async () => {
    const id = idOf(await olivia.post("/changes/new", rate(h.orgA, "61")));
    expect((await fiona.post(`/changes/${id}/approve`, {})).status).toBe(403);              // finance may not approve limits
    expect((await sam.post(`/changes/${id}/approve`, {})).status).toBe(403);                // read-only auditor
    expect((await bankerA.post(`/changes/${id}/approve`, {})).status).toBe(403);            // restricted user
    await expect(decideSql(id, "fiona")).rejects.toThrow(/may not decide/); await expect(decideSql(id, "sam")).rejects.toThrow(/may not decide/); await expect(decideSql(id, "banker-a")).rejects.toThrow(/may not decide/);
    expect((await sam.post("/changes/new", rate(h.orgA, "5"))).status).toBe(403);           // auditors cannot request either
    expect((await bankerA.post("/changes/new", rate(h.orgA, "5"))).status).toBe(403);
    expect(await status(id)).toBe("pending");
    await alice.post(`/changes/${id}/approve`, {});                                         // control
    expect(await limitOf(h.orgA)).toBe(61);
  });
  it("an approval replay, an approval after rejection and a double application are refused", async () => {
    const id = idOf(await alice.post("/changes/new", rate(h.orgA, "62")));
    expect((await bob.post(`/changes/${id}/approve`, {})).status).toBe(302);
    expect((await bob.post(`/changes/${id}/approve`, {})).status).toBe(409);
    await expect(decideSql(id, "olivia")).rejects.toThrow(/not pending/);
    const id2 = idOf(await alice.post("/changes/new", rate(h.orgA, "63")));
    await bob.post(`/changes/${id2}/reject`, { note: "no" });
    await expect(decideSql(id2, "olivia")).rejects.toThrow(/not pending/);
    expect(await limitOf(h.orgA)).toBe(62);
  });
  it("a request is immutable: payload, requester and target cannot be edited after submission, and a decided change is frozen", async () => {
    const id = idOf(await alice.post("/changes/new", rate(h.orgB, "11")));
    await expect(h.migrator.query("UPDATE config_change SET payload = '{\"orgId\":\"x\"}' WHERE id=$1", [id])).rejects.toThrow(/may not be edited|permission denied/i);
    await expect(h.migrator.query("UPDATE config_change SET requested_by='bob' WHERE id=$1", [id])).rejects.toThrow(/may not be edited|permission denied/i);
    await bob.post(`/changes/${id}/approve`, {});
    await expect(h.migrator.query("UPDATE config_change SET decision_note='x' WHERE id=$1", [id])).rejects.toThrow(/immutable|permission denied/i);
    await expect(h.migrator.query("DELETE FROM config_change WHERE id=$1", [id])).rejects.toThrow(/cannot be deleted|permission denied/i);
  });
  it("tampering with a pending payload behind the scenes (superuser) is caught by the integrity hash at approval time", async () => {
    const id = idOf(await alice.post("/changes/new", rate(h.orgB, "12")));
    await su(async (c) => { await c.query("ALTER TABLE config_change DISABLE TRIGGER config_change_guard"); await c.query("UPDATE config_change SET payload = jsonb_set(payload,'{maxPerMinute}','99999') WHERE id=$1", [id]); await c.query("ALTER TABLE config_change ENABLE TRIGGER config_change_guard"); });
    await expect(decideSql(id, "bob")).rejects.toThrow(/integrity/);
    expect(await limitOf(h.orgB)).not.toBe(99999);
  });
  it("requests expire after 24 hours", async () => {
    const id = idOf(await alice.post("/changes/new", rate(h.orgB, "13")));
    await su(async (c) => { await c.query("ALTER TABLE config_change DISABLE TRIGGER config_change_guard"); await c.query("UPDATE config_change SET requested_at = now() - interval '25 hours' WHERE id=$1", [id]); await c.query("ALTER TABLE config_change ENABLE TRIGGER config_change_guard"); });
    const r = await bob.post(`/changes/${id}/approve`, {}); expect(r.status).toBe(302);
    expect(await status(id)).toBe("expired"); expect(await limitOf(h.orgB)).not.toBe(13);
  });
  it("stale requests are refused: two competing changes cannot both apply on an old base", async () => {
    const id1 = idOf(await alice.post("/changes/new", rate(h.orgB, "21", "DEVICE_SWAP"))), id2 = idOf(await olivia.post("/changes/new", rate(h.orgB, "22", "DEVICE_SWAP")));
    expect((await bob.post(`/changes/${id1}/approve`, {})).status).toBe(302);
    const r = await bob.post(`/changes/${id2}/approve`, {}); expect(r.status).toBe(409); expect(r.text).toMatch(/stale/);
    expect(await limitOf(h.orgB, "DEVICE_SWAP")).toBe(21);
  });
  it("role changes take effect immediately: an approver who is disabled (or demoted) after the request cannot approve", async () => {
    const id = idOf(await alice.post("/changes/new", rate(h.orgA, "64", "CALL_FORWARDING")));
    await h.migrator.query("UPDATE admin_user SET role='security_auditor' WHERE sub='olivia'");
    await expect(decideSql(id, "olivia")).rejects.toThrow(/may not decide/);
    await h.migrator.query("UPDATE admin_user SET role='operations' WHERE sub='olivia'");
    await h.migrator.query("UPDATE admin_user SET state='disabled' WHERE sub='ian'");
    await expect(decideSql(id, "ian")).rejects.toThrow(/disabled|unknown/);
    await h.migrator.query("UPDATE admin_user SET state='active' WHERE sub='ian'");
  });
  it("approval needs a recent re-authentication (step-up): stale sign-ins are sent to re-authenticate; the database also refuses", async () => {
    const id = idOf(await alice.post("/changes/new", rate(h.orgA, "65", "KYC_MATCH")));
    const s = await a.login("bob");
    const idHash = createHash("sha256").update(s.cookie.split("=")[1]!).digest("hex");
    await h.migrator.query("UPDATE admin_session SET auth_time = now() - interval '10 minutes' WHERE id_hash = decode($1,'hex')", [idHash]);   // age ONLY this session
    const r = await s.post(`/changes/${id}/approve`, {}); expect(r.status).toBe(401); expect(r.text).toContain("stepup=1");
    await expect(decideSql(id, "bob", true, 301)).rejects.toThrow(/re-authentication/);
    expect(await status(id)).toBe("pending");
    const fresh = await a.login("bob", { stepup: "1", return: `/changes/${id}` });
    expect(fresh.ok).toBe(true); expect((await fresh.post(`/changes/${id}/approve`, {})).status).toBe(302);
    expect(await limitOf(h.orgA, "KYC_MATCH")).toBe(65);
    expect((await a.login("bob", { stepup: "1", mock_auth_age: "200" })).ok).toBe(false);   // an IdP that reuses an old authentication cannot satisfy step-up
  });
});

describe("versioned configuration: history, diff and gated rollback", () => {
  it("every applied change is recorded with before/after; the change page shows the diff; rollback is itself a gated change", async () => {
    const o = h.orgB;
    const v1 = idOf(await alice.post("/changes/new", rate(o, "30", "SIM_SWAP"))); await bob.post(`/changes/${v1}/approve`, {});
    const v2 = idOf(await alice.post("/changes/new", rate(o, "40", "SIM_SWAP")));
    const page = await bob.get(`/changes/${v2}`); expect(page.text).toContain("Difference from the last applied state");
    await bob.post(`/changes/${v2}/approve`, {}); expect(await limitOf(o)).toBe(40);
    const hist = (await h.migrator.query("SELECT version, before_state, after_state, restore FROM config_history WHERE kind='RATE_LIMIT' AND target=$1 ORDER BY version", [`org:${o}:SIM_SWAP`])).rows;
    expect(hist.length).toBeGreaterThanOrEqual(2); const last = hist[hist.length - 1]!;
    expect([last.before_state, last.after_state]).toEqual([30, 40]);
    const hp = await alice.get("/history"); expect(hp.text).toContain("30"); expect(hp.text).toContain("Request rollback");
    const rb = await alice.post("/history/rollback", { version: String(last.version) }); expect(rb.status).toBe(302);
    expect(await limitOf(o)).toBe(40);                                          // nothing changed yet: rollback is only a REQUEST
    expect((await alice.post(`${rb.location}/approve`, {})).status).toBe(403);   // and the requester cannot approve it
    expect((await bob.post(`${rb.location}/approve`, {})).status).toBe(302);
    expect(await limitOf(o)).toBe(30);
  });
  it("a forged rollback payload is refused by the database", async () => {
    const v = (await h.migrator.query("SELECT version FROM config_history WHERE kind='RATE_LIMIT' AND restore IS NOT NULL ORDER BY version DESC LIMIT 1")).rows[0].version;
    const t = (await h.migrator.query("SELECT target FROM config_history WHERE version=$1", [v])).rows[0].target;
    await expect(a.pool.query("SELECT cfg_request('RATE_LIMIT',$1,$2::jsonb,'alice',$3,$4)", [t, JSON.stringify({ orgId: h.orgB, signal: "SIM_SWAP", maxPerMinute: 100000 }), h.orgB, v])).rejects.toThrow(/restore state/);
  });
  it("history is append-only", async () => {
    await expect(h.migrator.query("UPDATE config_history SET applied_by='x'")).rejects.toThrow(/append-only|permission denied/i);
    await expect(a.pool.query("DELETE FROM config_history")).rejects.toThrow(/permission denied/i);
  });
});

describe("each kind of high-risk change applies correctly, with real effect", () => {
  it("rate limit: takes effect on the participant API; entitlement: removing it blocks the signal; policy: consent lifetime limit", async () => {
    const cons = async (days: number) => h.call(h.bankB, "POST", "/v1/consents", { body: { phoneNumber: num("0", "7700"), consentRef: `C-${Math.random().toString(36).slice(2, 10)}`, purposeCode: "FRAUD_PREVENTION", signals: ["SIM_SWAP"], expiresAt: new Date(Date.now() + days * 864e5).toISOString() } });
    expect((await cons(100)).status).toBe(201);
    const s1 = idOf(await alice.post("/changes/new", { kind: "SETTING", key: "consent.max_days", value: "30" })); await bob.post(`/changes/${s1}/approve`, {});
    expect((await cons(100)).status).toBe(400); expect((await cons(20)).status).toBe(201);
    const e1 = idOf(await ian.post("/changes/new", { kind: "ENTITLEMENT", orgId: h.orgB, signal: "SIM_SWAP", remove: "on" })); expect((await alice.post(`/changes/${e1}/approve`, {})).status).toBe(302);
    const c = await h.consent(h.bankB, num("0", "7701"), { signals: ["SIM_SWAP"] });
    const denied = await h.call(h.bankB, "POST", "/v1/signals/sim-swap/check", { body: { phoneNumber: num("0", "7701"), consentRef: c.ref, purposeCode: "FRAUD_PREVENTION" } });
    expect(denied.status).toBe(403); expect(denied.json.code).toBe("ACCESS_DENIED");
    const e2 = idOf(await ian.post("/changes/new", { kind: "ENTITLEMENT", orgId: h.orgB, signal: "SIM_SWAP", purposes: "FRAUD_PREVENTION" })); await alice.post(`/changes/${e2}/approve`, {});
    expect((await h.call(h.bankB, "POST", "/v1/signals/sim-swap/check", { body: { phoneNumber: num("0", "7701"), consentRef: c.ref, purposeCode: "FRAUD_PREVENTION" } })).json.result).toBe("FALSE");
    const lim = idOf(await olivia.post("/changes/new", rate(h.orgB, "2", "SIM_SWAP"))); await alice.post(`/changes/${lim}/approve`, {});
    const codes: number[] = []; for (let i = 0; i < 4; i++) codes.push((await h.call(h.bankB, "POST", "/v1/signals/sim-swap/check", { body: { phoneNumber: num("0", "7701"), consentRef: c.ref, purposeCode: "FRAUD_PREVENTION" } })).status);
    expect(codes.filter((x) => x === 429).length).toBeGreaterThanOrEqual(2);
  });
  it("price plans are immutable once created and applied by assignment; invalid pricing is refused before a request exists", async () => {
    const plan = { kind: "PRICE_PLAN", action: "create_plan", planId: "gold-v1", currency: "MYR", platformFeeMinor: "3", signalPrices: '{"SIM_SWAP":90,"KYC_MATCH":150}', tiers: '[{"upTo":10,"pct":100},{"upTo":null,"pct":70}]' };
    const p1 = idOf(await fiona.post("/changes/new", plan)); expect((await fiona.post(`/changes/${p1}/approve`, {})).status).toBe(403);
    expect((await alice.post(`/changes/${p1}/approve`, {})).status).toBe(302);
    expect((await h.migrator.query("SELECT platform_fee_minor f FROM price_plan WHERE id='gold-v1'")).rows[0].f).toBe(3);
    const dup = idOf(await fiona.post("/changes/new", plan)); expect((await alice.post(`/changes/${dup}/approve`, {})).status).toBeGreaterThanOrEqual(400);   // cannot overwrite an existing plan
    const asg = idOf(await fiona.post("/changes/new", { kind: "PRICE_PLAN", action: "assign", orgId: h.orgA, planId: "gold-v1" })); await alice.post(`/changes/${asg}/approve`, {});
    expect((await h.migrator.query("SELECT plan_id FROM org_price_plan WHERE org_id=$1", [h.orgA])).rows[0].plan_id).toBe("gold-v1");
    for (const bad of [{ ...plan, planId: "bad-1", tiers: "[]" }, { ...plan, planId: "bad-2", signalPrices: '{"SIM_SWAP":-5}' }, { ...plan, planId: "bad-3", signalPrices: '{"SIM_SWAP":1.5}' }, { ...plan, planId: "bad-4", tiers: '[{"upTo":null,"pct":150}]' }, { ...plan, planId: "Bad Id" }])
      expect((await fiona.post("/changes/new", bad)).status).toBe(400);
  });
  it("porting: the number is hashed in the portal and never stored; real (non-synthetic) numbers are refused", async () => {
    const n = "+609990088001";
    const r = await olivia.post("/changes/new", { kind: "PORTING", msisdn: n, telcoId: "telco-b" }); expect(r.status).toBe(302);
    const detail = await olivia.get(r.location!); expect(detail.text).not.toContain(n.slice(1));
    await alice.post(`${r.location}/approve`, {});
    const dump = JSON.stringify([(await h.migrator.query("SELECT payload FROM config_change WHERE kind='PORTING'")).rows, (await h.migrator.query("SELECT * FROM config_history WHERE kind='PORTING'")).rows, (await h.migrator.query("SELECT detail_text FROM audit_log")).rows]);
    expect(dump).not.toContain("60999008"); expect(a.logs.join("")).not.toContain("60999008");
    expect((await h.migrator.query("SELECT count(*)::int n FROM porting")).rows[0].n).toBe(1);
    expect((await olivia.post("/changes/new", { kind: "PORTING", msisdn: "+60123456789", telcoId: "telco-b" })).status).toBe(400);
  });
  it("kill switches: engaging is immediate for operations/admins and cuts traffic at once; lifting needs a second person", async () => {
    const n = num("0", "7710"); const c = await h.consent(h.bankA, n); const call = () => h.call(h.bankA, "POST", "/v1/signals/sim-swap/check", { body: { phoneNumber: n, consentRef: c.ref, purposeCode: "FRAUD_PREVENTION" } });
    expect((await call()).status).toBe(200);
    expect((await fiona.post("/killswitches/engage", { scope: "participant", key: "bank-a" })).status).toBe(403);      // finance cannot
    expect((await sam.post("/killswitches/engage", { scope: "participant", key: "bank-a" })).status).toBe(403);        // auditor cannot
    expect((await olivia.post("/killswitches/engage", { scope: "participant", key: "bank-a" })).status).toBe(302);
    expect((await call()).status).toBe(403);                                                                         // effective immediately
    expect((await olivia.post("/killswitches/engage", { scope: "participant", key: "no-such-client" })).status).toBeGreaterThanOrEqual(400);
    const lift = await olivia.post("/changes/new", { kind: "KILL_SWITCH_LIFT", scope: "participant", key: "bank-a" }); const id = idOf(lift);
    expect((await olivia.post(`/changes/${id}/approve`, {})).status).toBe(403); expect((await call()).status).toBe(403);   // requester cannot lift it alone
    expect((await alice.post(`/changes/${id}/approve`, {})).status).toBe(302); expect((await call()).status).toBe(200);
    expect(a.logs.join("")).toContain("admin.killswitch.engaged");
  });
  it("admin users: at least two active platform administrators must always remain (so two-person approval stays possible)", async () => {
    const dis = idOf(await alice.post("/changes/new", { kind: "ADMIN_USER", sub: "bob", displayName: "Bob Admin", role: "platform_admin", state: "disabled" }));
    expect((await olivia.post(`/changes/${dis}/approve`, {})).status).toBe(403);                       // only platform admins may approve user changes
    const res = await bob.post(`/changes/${dis}/approve`, {}); expect(res.status).toBe(409); expect(res.text).toMatch(/two active platform administrators/);
    expect((await h.migrator.query("SELECT count(*)::int n FROM admin_user WHERE role='platform_admin' AND state='active'")).rows[0].n).toBe(2);
    // with a third administrator in place, removing one is allowed
    const add = idOf(await alice.post("/changes/new", { kind: "ADMIN_USER", sub: "carol", displayName: "Carol Admin", role: "platform_admin" })); expect((await bob.post(`/changes/${add}/approve`, {})).status).toBe(302);
    const rm = idOf(await alice.post("/changes/new", { kind: "ADMIN_USER", sub: "carol", displayName: "Carol Admin", role: "platform_admin", state: "disabled" })); expect((await bob.post(`/changes/${rm}/approve`, {})).status).toBe(302);
    expect((await h.migrator.query("SELECT state FROM admin_user WHERE sub='carol'")).rows[0].state).toBe("disabled");
    expect((await h.migrator.query("SELECT count(*)::int n FROM admin_user WHERE role='platform_admin' AND state='active'")).rows[0].n).toBe(2);
    // a user who is created with a role the creator may not assign (restricted role without an organisation) is refused by the schema
    expect((await alice.post("/changes/new", { kind: "ADMIN_USER", sub: "dave", displayName: "Dave", role: "bank_user" })).status).toBe(302);
    const bad = (await h.migrator.query("SELECT id FROM config_change WHERE target='user:dave'")).rows[0].id as string;
    expect((await bob.post(`/changes/${bad}/approve`, {})).status).toBeGreaterThanOrEqual(400);
  });
});
