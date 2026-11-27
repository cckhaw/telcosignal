import { calculateJwkThumbprint, exportJWK, generateKeyPair, type JWK } from "jose";
import { randomBytes } from "node:crypto";
import { ALL_ROLES, HttpError, STAFF, type AdminDeps, type RouteCtx } from "./server.js";
import { field, form, h, select, table, type Raw } from "./ui.js";
import { jsonDiff } from "./diff.js";
import { buildChange, InputError } from "./payloads.js";
import { SIGNALS } from "../consent/consent.js";

type Route = (m: "GET" | "POST", path: string, roles: readonly string[], fn: (c: RouteCtx) => Promise<unknown>) => void;
const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$|^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/;
const STAFF_ALL = [...STAFF] as readonly string[];
const MAKERS = ["platform_admin", "operations", "integration_engineer", "finance", "bank_user", "telco_user"] as const;
const OPS = ["platform_admin", "operations", "integration_engineer"] as const;
const pre = (v: unknown) => h`<pre>${JSON.stringify(v, null, 2)}</pre>`;
const fmt = (t: unknown) => (t ? new Date(t as string).toISOString().slice(0, 19) + "Z" : "");
const id404 = (v: string | undefined) => { if (!v || !UUID.test(v)) throw new HttpError(404, "Not found."); return v; };
const bad = (c: RouteCtx, e: unknown) => { if (e instanceof InputError) return c.html("Invalid input", h`<p class="err">${e.message}</p>`, 400); throw e; };

export function registerPages(d: AdminDeps, route: Route) {
  const loopbackAllowed = async (c: RouteCtx) => (await c.tx((tx) => tx.query("SELECT value FROM platform_setting WHERE key='sandbox.allow_loopback'"))).rows[0]?.value === true;
  const ctxFor = async (c: RouteCtx) => ({ allowLoopback: await loopbackAllowed(c), syntheticPrefixes: d.cfg.syntheticPrefixes, hashNumber: async (n: string) => (await d.kms.hmac("msisdn-hmac", n)).toString("hex") });

  route("GET", "/", ALL_ROLES, async (c) => {
    const n = (await c.tx((tx) => tx.query("SELECT count(*)::int n FROM config_change WHERE status='pending'"))).rows[0].n;
    return c.html("Home", h`<p>Signed in as <b>${c.user.displayName}</b> (${c.user.role}). Last authentication ${c.authAgeSeconds}s ago.</p><p>Pending change requests visible to you: <a href="/changes">${n}</a></p>`);
  });

  // ---------- organisations and onboarding ----------
  route("GET", "/orgs", ALL_ROLES, async (c) => {
    const r = await c.tx((tx) => tx.query("SELECT id, name, kind, state FROM organisations ORDER BY name"));
    await c.audit("admin.view.orgs", "OK");
    const canCreate = (OPS as readonly string[]).includes(c.user.role);
    return c.html("Organisations", h`${table(["Name", "Kind", "State", ""], r.rows.map((o) => [o.name, o.kind, o.state, h`<a href="/orgs/${o.id}">open</a>`]))}
      ${canCreate ? h`<h2>Onboard an organisation</h2>${form("/orgs", c.user.csrf, h`${field("name", "Name")}${select("kind", "Kind", ["bank", "telco"])}<button>Create (draft)</button>`)}` : h``}`);
  });
  route("POST", "/orgs", OPS, async (c) => {
    const name = (c.form["name"] ?? "").trim(), kind = c.form["kind"] ?? "";
    if (!name || name.length > 100 || !["bank", "telco"].includes(kind)) return bad(c, new InputError("invalid organisation"));
    const id = (await c.tx((tx) => tx.query("SELECT onb_create_org($1,$2,$3) AS id", [name, kind, c.user.sub]))).rows[0].id as string;
    await c.audit("admin.org.create", "OK", id, { kind });
    return c.redirect(`/orgs/${id}`);
  });
  route("GET", "/orgs/:id", ALL_ROLES, async (c) => {
    const id = id404(c.params["id"]);
    const data = await c.tx(async (tx) => {
      const o = (await tx.query("SELECT id, name, kind, state FROM organisations WHERE id=$1", [id])).rows[0];
      if (!o) return null;
      const req = (await tx.query("SELECT cfg_required_tests($1) AS t, onb_missing_tests($1) AS m", [id])).rows[0];
      const tests = (await tx.query("SELECT DISTINCT ON (test_key) test_key, status, run_at FROM onboarding_test WHERE org_id=$1 ORDER BY test_key, id DESC", [id])).rows;
      const ent = (await tx.query("SELECT signal, purposes FROM org_entitlement WHERE org_id=$1 ORDER BY signal", [id])).rows;
      const clients = (await tx.query("SELECT c.client_id, c.state, c.scopes FROM clients c WHERE c.org_id=$1 ORDER BY 1", [id])).rows;
      const telcos = (await tx.query("SELECT id, adapter, base_url, state FROM telcos WHERE org_id=$1", [id])).rows;
      const pend = (await tx.query("SELECT id, kind, target, status FROM config_change WHERE org_id=$1 ORDER BY requested_at DESC LIMIT 20", [id])).rows;
      return { o, req, tests, ent, clients, telcos, pend };
    });
    if (!data) throw new HttpError(404, "Not found.");
    await c.audit("admin.view.org", "OK", id);
    const latest = new Map(data.tests.map((t: { test_key: string; status: string }) => [t.test_key, t.status]));
    const staff = (STAFF as readonly string[]).includes(c.user.role);
    const eng = ["platform_admin", "integration_engineer"].includes(c.user.role), ops = ["platform_admin", "operations"].includes(c.user.role);
    return c.html(`Organisation: ${data.o.name}`, h`<p>Kind: ${data.o.kind} &middot; State: <b>${data.o.state}</b></p>
      <h2>Required tests for activation</h2>${table(["Test", "Latest result"], (data.req.t as string[]).map((t) => [t, latest.get(t) ?? "not run"]))}
      <p>Missing: ${(data.req.m as string[]).join(", ") || "none"}</p>
      <h2>Entitlements</h2>${table(["Signal", "Purposes"], data.ent.map((e: { signal: string; purposes: string[] }) => [e.signal, e.purposes.join(", ")]))}
      <h2>Clients</h2>${table(["Client", "State", "Scopes"], data.clients.map((x: { client_id: string; state: string; scopes: string[] }) => [x.client_id, x.state, x.scopes.join(" ")]))}
      ${data.telcos.length ? h`<h2>Telco connection</h2>${table(["Id", "Adapter", "Endpoint", "State"], data.telcos.map((t: { id: string; adapter: string; base_url: string; state: string }) => [t.id, t.adapter, t.base_url, t.state]))}` : h``}
      <h2>Change requests</h2>${table(["Kind", "Target", "Status", ""], data.pend.map((p: { id: string; kind: string; target: string; status: string }) => [p.kind, p.target, p.status, h`<a href="/changes/${p.id}">view</a>`]))}
      ${eng ? h`<h2>Onboarding actions</h2>
        ${form(`/orgs/${id}/advance`, c.user.csrf, h`<input type="hidden" name="to" value="testing"><button>Move to testing</button>`)}
        ${form(`/orgs/${id}/tests`, c.user.csrf, h`<button>${data.o.kind === "telco" ? "Run health check and conformance tests" : "Evaluate certification from sandbox evidence"}</button>`)}
        ${form(`/orgs/${id}/advance`, c.user.csrf, h`<input type="hidden" name="to" value="pending_approval"><button>Submit for approval (requires all tests passed)</button>`)}` : h``}
      ${staff && ["platform_admin", "operations", "integration_engineer"].includes(c.user.role) ? h`<h2>Request activation or retirement (needs a second person)</h2>
        ${form("/changes/new", c.user.csrf, h`<input type="hidden" name="kind" value="ORG_STATE"><input type="hidden" name="orgId" value="${id}">${select("toState", "To", ["active", "retired"])}<button>Request</button>`)}` : h``}
      ${ops ? h`<h2>Suspend now</h2>${form(`/orgs/${id}/suspend`, c.user.csrf, h`<button>Suspend organisation immediately</button>`)}` : h``}`);
  });
  route("POST", "/orgs/:id/advance", ["platform_admin", "integration_engineer"], async (c) => {
    const id = id404(c.params["id"]);
    await c.tx((tx) => tx.query("SELECT onb_advance($1,$2,$3)", [id, c.form["to"] ?? "", c.user.sub]));
    await c.audit("admin.org.advance", "OK", id, { to: c.form["to"] ?? "" });
    return c.redirect(`/orgs/${id}`);
  });
  route("POST", "/orgs/:id/suspend", ["platform_admin", "operations"], async (c) => {
    const id = id404(c.params["id"]);
    await c.tx((tx) => tx.query("SELECT onb_suspend($1,$2)", [id, c.user.sub]));
    d.log.warn({ "event.category": "security", "event.action": "admin.org.suspended", actor: c.user.sub, org: id }, "security_event");
    await c.audit("admin.org.suspend", "OK", id);
    return c.redirect(`/orgs/${id}`);
  });
  route("POST", "/orgs/:id/tests", ["platform_admin", "integration_engineer"], async (c) => {
    const id = id404(c.params["id"]);
    const o = (await c.tx((tx) => tx.query("SELECT kind FROM organisations WHERE id=$1", [id]))).rows[0];
    if (!o) throw new HttpError(404, "Not found.");
    let summary: Record<string, boolean>;
    if (o.kind === "bank") {
      summary = (await c.tx((tx) => tx.query("SELECT onb_eval_bank_cert($1,$2) AS r", [id, c.user.sub]))).rows[0].r as Record<string, boolean>;   // computed by the database from real usage evidence
    } else {
      if (!d.registry) throw new HttpError(409, "Conformance runner is not available on this instance.");
      summary = await runTelcoConformance(c, id);
    }
    await c.audit("admin.org.tests", "OK", id, { passed: Object.values(summary).filter(Boolean).length, failed: Object.values(summary).filter((x) => !x).length });
    return c.redirect(`/orgs/${id}`);
  });
  async function runTelcoConformance(c: RouteCtx, orgId: string): Promise<Record<string, boolean>> {
    const t = (await c.tx((tx) => tx.query("SELECT t.id, array(SELECT signal FROM telco_signal_coverage WHERE telco_id = t.id ORDER BY signal) AS sg FROM telcos t WHERE t.org_id=$1", [orgId]))).rows[0] as { id: string; sg: string[] } | undefined;
    if (!t) throw new HttpError(409, "No telco connection is registered for this organisation.");
    const adapter = await d.registry!.getForTest(t.id);
    const base = `${d.cfg.syntheticPrefixes[0]}5000000`, out: Record<string, boolean> = {};
    const record = (key: string, ok: boolean, evidence: Record<string, unknown>) => c.tx((tx) => tx.query("SELECT onb_record_test($1,$2,$3,$4,$5)", [orgId, key, ok ? "pass" : "fail", JSON.stringify(evidence), c.user.sub]));
    for (const signal of t.sg) {
      let ok = false; const evidence: Record<string, unknown> = { signal };
      if (adapter) {
        const kyc = signal === "KYC_MATCH" ? { name: "Synthetic Person" } : undefined;
        const pos = await adapter.call({ signal: signal as (typeof SIGNALS)[number], msisdn: `${base}${signal === "KYC_MATCH" ? "0" : "1"}`, ...(kyc ? { kyc } : {}), correlationId: "conformance" });
        const neg = await adapter.call({ signal: signal as (typeof SIGNALS)[number], msisdn: `${base}${signal === "KYC_MATCH" ? "1" : "0"}`, ...(kyc ? { kyc } : {}), correlationId: "conformance" });
        ok = pos.status === "TRUE" && neg.status === "FALSE";      // UNAVAILABLE or anything unexpected is a failure
        evidence["positive"] = pos.status; evidence["negative"] = neg.status;
        if (signal === t.sg[0]) { const hc = pos.status !== "UNAVAILABLE" && neg.status !== "UNAVAILABLE"; out["health_check"] = hc; await record("health_check", hc, { positive: pos.status, negative: neg.status }); }
      } else evidence["error"] = "adapter unavailable (endpoint not allow-listed, retired or invalid)";
      out[`conformance:${signal}`] = ok; await record(`conformance:${signal}`, ok, evidence);
    }
    if (t.sg.length === 0) { out["health_check"] = false; await record("health_check", false, { error: "no signal coverage configured" }); }
    return out;
  }

  // ---------- change requests ----------
  const FORMS: Array<{ kind: string; action?: string; title: string; fields: Array<[string, string]> }> = [
    { kind: "PRICE_PLAN", action: "create_plan", title: "Create price plan (placeholder prices)", fields: [["planId", "Plan id"], ["currency", "Currency"], ["platformFeeMinor", "Platform fee per query (minor units)"], ["signalPrices", "Signal prices JSON"], ["tiers", "Tiers JSON"]] },
    { kind: "PRICE_PLAN", action: "assign", title: "Assign price plan to organisation", fields: [["orgId", "Organisation id"], ["planId", "Plan id"]] },
    { kind: "RATE_LIMIT", title: "Set per-participant rate limit (blank = remove)", fields: [["orgId", "Organisation id"], ["signal", "Signal"], ["maxPerMinute", "Max per minute"]] },
    { kind: "SETTING", title: "Platform policy setting", fields: [["key", "Key (consent.max_days, sandbox.allow_loopback)"], ["value", "Value (JSON)"]] },
    { kind: "ROUTING", action: "set_prefix", title: "Route a number prefix to a telco", fields: [["prefix", "Prefix"], ["telcoId", "Telco id"]] },
    { kind: "ROUTING", action: "allow_origin", title: "Allow-list an outbound endpoint origin", fields: [["origin", "Origin (https://host:port)"]] },
    { kind: "ROUTING", action: "create_telco", title: "Register a telco connection (draft)", fields: [["telcoId", "Telco id"], ["adapter", "Adapter (camara/proprietary/aggregator)"], ["baseUrl", "Base URL"], ["orgId", "Telco organisation id"]] },
    { kind: "ROUTING", action: "coverage_set", title: "Set signal coverage for a telco", fields: [["telcoId", "Telco id"], ["signals", "Signals (comma separated)"]] },
    { kind: "ROUTING", action: "telco_state", title: "Change a telco's state", fields: [["telcoId", "Telco id"], ["state", "State"]] },
    { kind: "PORTING", title: "Record a ported number (synthetic only; stored as a keyed hash)", fields: [["msisdn", "Number"], ["telcoId", "New telco id"]] },
    { kind: "ENTITLEMENT", title: "Entitle an organisation to a signal and purposes", fields: [["orgId", "Organisation id"], ["signal", "Signal"], ["purposes", "Purposes (comma separated)"]] },
    { kind: "KILL_SWITCH_LIFT", title: "Lift a kill switch", fields: [["scope", "Scope"], ["key", "Key"]] },
    { kind: "ADMIN_USER", title: "Create or change an admin user", fields: [["sub", "IdP subject"], ["displayName", "Display name"], ["role", "Role"], ["orgId", "Organisation id (telco/bank users)"], ["state", "State (active/disabled)"]] },
  ];
  route("GET", "/changes", ALL_ROLES, async (c) => {
    const { rows, pol } = await c.tx(async (tx) => ({
      rows: (await tx.query("SELECT id, kind, target, status, requested_by, requested_at, decided_by FROM config_change ORDER BY requested_at DESC LIMIT 100")).rows,
      pol: (await tx.query("SELECT kind, can_request FROM config_role_policy")).rows as Array<{ kind: string; can_request: string[] }>,
    }));
    await c.audit("admin.view.changes", "OK");
    const allowed = new Set(pol.filter((p) => p.can_request.includes(c.user.role)).map((p) => p.kind));
    const forms = FORMS.filter((f) => allowed.has(f.kind) && (STAFF_ALL.includes(c.user.role)));
    return c.html("Change requests", h`${table(["Kind", "Target", "Status", "Requested by", "At", "Decided by", ""], rows.map((r) => [r.kind, r.target, r.status, r.requested_by, fmt(r.requested_at), r.decided_by ?? "", h`<a href="/changes/${r.id}">review</a>`]))}
      ${forms.length ? h`<h2>New request (applies only after a different person approves)</h2>${forms.map((f) => h`<h3>${f.title}</h3>${form("/changes/new", c.user.csrf, h`<input type="hidden" name="kind" value="${f.kind}">${f.action ? h`<input type="hidden" name="action" value="${f.action}">` : h``}${f.fields.map(([n, l]) => field(n, l))}<button>Request</button>`)}`)}` : h``}`);
  });
  route("POST", "/changes/new", MAKERS, async (c) => {
    let b;
    try { b = await buildChange(c.form["kind"] ?? "", c.form, await ctxFor(c)); } catch (e) { return bad(c, e); }
    const id = (await c.tx((tx) => tx.query("SELECT cfg_request($1,$2,$3::jsonb,$4,$5,NULL) AS id", [b.kind, b.target, JSON.stringify(b.payload), c.user.sub, b.orgId]))).rows[0].id as string;
    await c.audit("admin.change.request", "OK", b.orgId ?? undefined, { kind: b.kind, target: /^(porting|prefix):/.test(b.target) ? b.target.split(":")[0]! : b.target, change: id });
    return c.redirect(`/changes/${id}`);
  });
  route("GET", "/changes/:id", ALL_ROLES, async (c) => {
    const id = id404(c.params["id"]);
    const r = await c.tx(async (tx) => {
      const ch = (await tx.query("SELECT * FROM config_change WHERE id=$1", [id])).rows[0];
      if (!ch) return null;
      const last = (await tx.query("SELECT after_state, version FROM config_history WHERE kind=$1 AND target=$2 ORDER BY version DESC LIMIT 1", [ch.kind, ch.target])).rows[0];
      return { ch, last };
    });
    if (!r) throw new HttpError(404, "Not found.");
    await c.audit("admin.view.change", "OK", r.ch.org_id ?? undefined, { change: id });
    const { ch } = r;
    const diff = jsonDiff(r.last?.after_state ?? null, ch.payload);
    const mine = ch.requested_by === c.user.sub;
    const canDecide = ch.status === "pending" && !mine && (STAFF_ALL.includes(c.user.role)) && c.user.role !== "security_auditor";
    return c.html(`Change ${ch.kind}`, h`<p>Status: <b>${ch.status}</b> &middot; requested by ${ch.requested_by} (${ch.requested_role}) at ${fmt(ch.requested_at)}${ch.decided_by ? h` &middot; decided by ${ch.decided_by} at ${fmt(ch.decided_at)}` : h``}</p>
      <p>Target: ${ch.target}</p><h2>Proposed payload</h2>${pre(ch.payload)}
      <h2>Difference from the last applied state</h2>${table(["Path", "Current", "Proposed"], diff.map((x) => [x.path, x.from, x.to]))}
      ${ch.status === "pending" && mine ? h`<p>You requested this change, so you cannot approve it. Another authorised person must.</p>${form(`/changes/${id}/withdraw`, c.user.csrf, h`<button>Withdraw</button>`)}` : h``}
      ${canDecide ? h`<h2>Decision</h2>${form(`/changes/${id}/approve`, c.user.csrf, h`${field("note", "Note")}<button>Approve and apply</button>`)}${form(`/changes/${id}/reject`, c.user.csrf, h`${field("note", "Reason")}<button>Reject</button>`)}` : h``}`);
  });
  route("POST", "/changes/:id/approve", STAFF_ALL, async (c) => {
    const id = id404(c.params["id"]);
    if (c.authAgeSeconds > 300) {
      return c.html("Re-authentication required", h`<p>Approvals need a fresh phishing-resistant sign-in (within 5 minutes).</p><p><a href="/login?stepup=1&amp;return=/changes/${id}">Re-authenticate</a></p>`, 401);
    }
    const res = (await c.tx((tx) => tx.query("SELECT cfg_decide($1,$2,true,$3,$4) AS r", [id, c.user.sub, (c.form["note"] ?? "").slice(0, 500), c.authAgeSeconds]))).rows[0].r as { status: string };
    await c.audit("admin.change.decide", res.status.toUpperCase(), undefined, { change: id, decision: "approve" });
    return c.redirect(`/changes/${id}`);
  });
  route("POST", "/changes/:id/reject", STAFF_ALL, async (c) => {
    const id = id404(c.params["id"]);
    const res = (await c.tx((tx) => tx.query("SELECT cfg_decide($1,$2,false,$3,$4) AS r", [id, c.user.sub, (c.form["note"] ?? "").slice(0, 500), c.authAgeSeconds]))).rows[0].r as { status: string };
    await c.audit("admin.change.decide", res.status.toUpperCase(), undefined, { change: id, decision: "reject" });
    return c.redirect(`/changes/${id}`);
  });
  route("POST", "/changes/:id/withdraw", MAKERS, async (c) => {
    const id = id404(c.params["id"]);
    await c.tx((tx) => tx.query("SELECT cfg_withdraw($1,$2)", [id, c.user.sub]));
    await c.audit("admin.change.withdraw", "OK", undefined, { change: id });
    return c.redirect("/changes");
  });

  // ---------- configuration (read-only view) and versioned history with gated rollback ----------
  route("GET", "/config", STAFF_ALL, async (c) => {
    const q = (sql: string) => c.tx((tx) => tx.query(sql)).then((r) => r.rows);
    const [plans, assigns, limits, settings, prefixes, allow, ent, pol] = await Promise.all([
      q("SELECT id, currency, platform_fee_minor, signal_price_minor, tiers FROM price_plan ORDER BY id"), q("SELECT org_id, plan_id, effective_from FROM org_price_plan ORDER BY effective_from DESC"),
      q("SELECT org_id, signal, max_per_minute FROM rate_limit_override ORDER BY 1,2"), q("SELECT key, value FROM platform_setting ORDER BY key"), q("SELECT prefix, telco_id FROM route_prefix ORDER BY prefix"),
      q("SELECT origin FROM endpoint_allowlist ORDER BY origin"), q("SELECT org_id, signal, purposes FROM org_entitlement ORDER BY 1,2"), q("SELECT kind, can_request, can_approve FROM config_role_policy ORDER BY kind"),
    ]);
    await c.audit("admin.view.config", "OK");
    return c.html("Configuration", h`<h2>Price plans (placeholders)</h2>${table(["Plan", "Currency", "Fee/query", "Prices", "Tiers"], plans.map((p) => [p.id, p.currency, p.platform_fee_minor, JSON.stringify(p.signal_price_minor), JSON.stringify(p.tiers)]))}
      <h2>Plan assignments</h2>${table(["Org", "Plan", "From"], assigns.map((a) => [a.org_id, a.plan_id, fmt(a.effective_from)]))}
      <h2>Rate-limit overrides</h2>${table(["Org", "Signal", "Per minute"], limits.map((l) => [l.org_id, l.signal, l.max_per_minute]))}
      <h2>Policy settings</h2>${table(["Key", "Value"], settings.map((s) => [s.key, JSON.stringify(s.value)]))}
      <h2>Routing prefixes</h2>${table(["Prefix", "Telco"], prefixes.map((p) => [p.prefix, p.telco_id]))}
      <h2>Allow-listed outbound origins</h2>${table(["Origin"], allow.map((a) => [a.origin]))}
      <h2>Entitlements</h2>${table(["Org", "Signal", "Purposes"], ent.map((e) => [e.org_id, e.signal, e.purposes.join(", ")]))}
      <h2>Who may request / approve</h2>${table(["Kind", "May request", "May approve"], pol.map((p) => [p.kind, p.can_request.join(", "), p.can_approve.join(", ")]))}`);
  });
  route("GET", "/history", STAFF_ALL, async (c) => {
    const rows = (await c.tx((tx) => tx.query("SELECT version, kind, target, before_state, after_state, restore IS NOT NULL AS can_restore, requested_by, applied_by, applied_at FROM config_history ORDER BY version DESC LIMIT 100"))).rows;
    await c.audit("admin.view.history", "OK");
    const canRoll = ["platform_admin", "operations", "integration_engineer", "finance"].includes(c.user.role);
    return c.html("Configuration history", table(["Version", "Kind", "Target", "Changes", "Requested by", "Applied by", "At", ""], rows.map((r) => [r.version, r.kind, r.target,
      h`${jsonDiff(r.before_state, r.after_state).map((x) => h`${x.path}: ${x.from} &rarr; ${x.to}<br>`)}`, r.requested_by, r.applied_by, fmt(r.applied_at),
      r.can_restore && canRoll ? form("/history/rollback", c.user.csrf, h`<input type="hidden" name="version" value="${r.version}"><button>Request rollback</button>`) : ""])));
  });
  route("POST", "/history/rollback", ["platform_admin", "operations", "integration_engineer", "finance"], async (c) => {
    const v = Number(c.form["version"]); if (!Number.isInteger(v) || v < 1) return bad(c, new InputError("invalid version"));
    const hrow = (await c.tx((tx) => tx.query("SELECT kind, target, restore FROM config_history WHERE version=$1", [v]))).rows[0];
    if (!hrow?.restore) throw new HttpError(409, "That version cannot be rolled back.");
    const org = (hrow.restore as { orgId?: string }).orgId ?? null;
    // Rollback is NOT a shortcut: it is an ordinary change request that another person must approve.
    const id = (await c.tx((tx) => tx.query("SELECT cfg_request($1,$2,$3::jsonb,$4,$5,$6) AS id", [hrow.kind, hrow.target, JSON.stringify(hrow.restore), c.user.sub, org, v]))).rows[0].id as string;
    await c.audit("admin.change.request", "OK", org ?? undefined, { kind: hrow.kind, target: /^(porting|prefix):/.test(hrow.target) ? hrow.target.split(":")[0]! : hrow.target, rollback_of: v, change: id });
    return c.redirect(`/changes/${id}`);
  });

  // ---------- kill switches ----------
  route("GET", "/killswitches", ["platform_admin", "operations", "security_auditor"], async (c) => {
    const rows = (await c.tx((tx) => tx.query("SELECT scope, key, enabled FROM kill_switch ORDER BY scope, key"))).rows;
    await c.audit("admin.view.killswitches", "OK");
    const can = ["platform_admin", "operations"].includes(c.user.role);
    return c.html("Kill switches", h`${table(["Scope", "Key", "Engaged", ""], rows.map((r) => [r.scope, r.key, r.enabled ? "YES" : "no", r.enabled && can ? form("/changes/new", c.user.csrf, h`<input type="hidden" name="kind" value="KILL_SWITCH_LIFT"><input type="hidden" name="scope" value="${r.scope}"><input type="hidden" name="key" value="${r.key}"><button>Request lift (second person)</button>`) : ""]))}
      ${can ? h`<h2>Engage (immediate, audited; lifting needs a second person)</h2>${form("/killswitches/engage", c.user.csrf, h`${select("scope", "Scope", ["participant", "telco", "signal"])}${field("key", "Key (client id, telco id or signal)")}<button>Engage now</button>`)}` : h``}`);
  });
  route("POST", "/killswitches/engage", ["platform_admin", "operations"], async (c) => {
    const scope = c.form["scope"] ?? "", key = (c.form["key"] ?? "").trim();
    if (!["participant", "telco", "signal"].includes(scope) || !/^[A-Za-z0-9_-]{1,64}$/.test(key)) return bad(c, new InputError("invalid kill switch"));
    await c.tx((tx) => tx.query("SELECT admin_kill_switch_engage($1,$2,$3)", [scope, key, c.user.sub]));
    d.log.warn({ "event.category": "security", "event.action": "admin.killswitch.engaged", actor: c.user.sub, scope, key }, "security_event");
    await c.audit("admin.killswitch.engage", "OK", undefined, { scope, key });
    return c.redirect("/killswitches");
  });

  // ---------- integration: connections, test console (synthetic numbers only), API versions ----------
  route("GET", "/integration", ["platform_admin", "operations", "integration_engineer", "security_auditor"], async (c) => {
    const { telcos, versions } = await c.tx(async (tx) => ({
      telcos: (await tx.query("SELECT t.id, t.adapter, t.base_url, t.state, array(SELECT signal FROM telco_signal_coverage WHERE telco_id=t.id ORDER BY 1) AS coverage FROM telcos t ORDER BY 1")).rows,
      versions: (await tx.query("SELECT version, status, sunset_date, note FROM api_version ORDER BY version")).rows,
    }));
    await c.audit("admin.view.integration", "OK");
    const br = new Map((d.registry?.breakerStates() ?? []).map((b) => [b.telcoId, b]));
    const may = ["platform_admin", "operations", "integration_engineer"].includes(c.user.role);
    return c.html("Integration", h`<h2>Adapters and connections</h2>${table(["Telco", "Adapter", "Endpoint", "State", "Coverage", "Circuit breaker (this instance)"], telcos.map((t) => [t.id, t.adapter, t.base_url, t.state, t.coverage.join(", "), br.get(t.id) ? `${br.get(t.id)!.state}, ${br.get(t.id)!.recentFaults}/${br.get(t.id)!.recentTotal} recent faults` : "no traffic yet"]))}
      <h2>API versions and deprecation</h2>${table(["Version", "Status", "Sunset", "Note"], versions.map((v) => [v.version, v.status, v.sunset_date ? String(v.sunset_date).slice(0, 10) : "", v.note]))}
      ${may ? h`${form("/integration/api-version", c.user.csrf, h`${field("version", "Version (v1, v2...)")}${select("status", "Status", ["current", "deprecated", "sunset"])}${field("sunsetDate", "Sunset date (YYYY-MM-DD)")}${field("note", "Note")}<button>Save version status</button>`)}
        <h2>Test console (synthetic numbers only; results are not stored with the number)</h2>
        ${form("/integration/test", c.user.csrf, h`${field("telcoId", "Telco id")}${select("signal", "Signal", [...SIGNALS])}${field("msisdn", "Synthetic number")}<button>Run</button>`)}` : h``}`);
  });
  route("POST", "/integration/api-version", OPS, async (c) => {
    const v = c.form["version"] ?? "", s = c.form["status"] ?? "", sd = (c.form["sunsetDate"] ?? "").trim();
    if (!/^v[0-9]{1,3}$/.test(v) || !["current", "deprecated", "sunset"].includes(s) || (sd && !/^\d{4}-\d{2}-\d{2}$/.test(sd))) return bad(c, new InputError("invalid API version data"));
    await c.tx((tx) => tx.query("INSERT INTO api_version(version,status,sunset_date,note) VALUES ($1,$2,$3,$4) ON CONFLICT (version) DO UPDATE SET status=EXCLUDED.status, sunset_date=EXCLUDED.sunset_date, note=EXCLUDED.note", [v, s, sd || null, (c.form["note"] ?? "").slice(0, 200)]));
    await c.audit("admin.api_version.set", "OK", undefined, { version: v, status: s });
    return c.redirect("/integration");
  });
  route("POST", "/integration/test", OPS, async (c) => {
    const n = (c.form["msisdn"] ?? "").trim(), telcoId = c.form["telcoId"] ?? "", signal = c.form["signal"] ?? "";
    if (!/^\+[1-9][0-9]{4,14}$/.test(n) || !d.cfg.syntheticPrefixes.some((p) => n.startsWith(p))) return bad(c, new InputError("only synthetic numbers may be used in the test console"));     // no real numbers, no replay of real requests
    if (!(SIGNALS as readonly string[]).includes(signal) || !/^[a-z0-9-]{1,30}$/.test(telcoId)) return bad(c, new InputError("invalid telco or signal"));
    if (!d.registry) throw new HttpError(409, "Test console is not available on this instance.");
    const a = await d.registry.getForTest(telcoId);
    const r = a ? await a.call({ signal: signal as (typeof SIGNALS)[number], msisdn: n, correlationId: "console", ...(signal === "KYC_MATCH" ? { kyc: { name: "Synthetic Person" } } : {}) }) : { status: "UNAVAILABLE", reason: "no adapter", telcoMs: 0 };
    await c.audit("admin.console.test", r.status, undefined, { telco: telcoId, signal, ms: r.telcoMs });
    return c.html("Test console result", h`<p>Result: <b>${r.status}</b> (${r.reason}, ${r.telcoMs} ms)</p><p><a href="/integration">Back</a></p>`);
  });

  // ---------- credentials: public-key registration (+ optional show-once generated key), rotation, revocation ----------
  route("GET", "/credentials", ALL_ROLES, async (c) => {
    const rows = (await c.tx((tx) => tx.query(`SELECT k.client_id, k.kid, k.expires_at, k.revoked_at, c.org_id, c.state AS cstate, (k.expires_at < now() + interval '30 days' AND k.revoked_at IS NULL) AS expiring
      FROM client_keys k JOIN clients c ON c.client_id = k.client_id ORDER BY k.client_id, k.expires_at DESC`))).rows;
    await c.audit("admin.view.credentials", "OK");
    const staffOrg = c.user.orgId ?? "";
    return c.html("Credentials", h`<p>The platform stores public keys only. Certificate thumbprints bind each key to the client's mTLS certificate.</p>
      ${table(["Client", "Key id", "Expires", "Status", ""], rows.map((r) => [r.client_id, r.kid, fmt(r.expires_at), r.revoked_at ? "revoked" : r.expiring ? "EXPIRING SOON" : "active",
        !r.revoked_at ? form("/credentials/revoke", c.user.csrf, h`<input type="hidden" name="clientId" value="${r.client_id}"><input type="hidden" name="kid" value="${r.kid}"><button>Revoke now</button>`) : ""]))}
      <h2>Register a public key (needs a second person's approval)</h2>
      ${form("/credentials/register", c.user.csrf, h`${c.user.orgId ? h`<input type="hidden" name="orgId" value="${staffOrg}">` : field("orgId", "Organisation id")}
        ${field("clientId", "Client id")}${field("certSha256", "Client certificate SHA-256 thumbprint (base64url)")}${field("expiresInDays", "Valid for (days, max 365)", "90")}
        ${field("rotateOutKid", "Rotate out key id (optional)")}${field("scopes", "Scopes for a NEW client (space separated)")}
        <label>Public JWK (EC P-256) <textarea name="jwk" rows="4" cols="60" maxlength="2000"></textarea></label>
        <label><input type="checkbox" name="generate"> Generate a key pair for me (sandbox convenience: the private key is shown once and never stored)</label><button>Request registration</button>`)}`);
  });
  route("POST", "/credentials/register", ["platform_admin", "integration_engineer", "bank_user", "telco_user"], async (c) => {
    try {
      const f = c.form; const orgId = c.user.orgId ?? (f["orgId"] ?? "").trim();
      if (!UUID.test(orgId)) throw new InputError("invalid organisation");
      if (c.user.orgId && orgId !== c.user.orgId) throw new HttpError(403, "You may only request credentials for your own organisation.");
      const clientId = (f["clientId"] ?? "").trim(); if (!/^[a-z0-9][a-z0-9_-]{2,62}$/.test(clientId)) throw new InputError("invalid client id");
      const thumb = (f["certSha256"] ?? "").trim(); if (!/^[A-Za-z0-9_-]{43}$/.test(thumb)) throw new InputError("invalid certificate thumbprint");
      const days = Number(f["expiresInDays"] ?? "90"); if (!Number.isInteger(days) || days < 1 || days > 365) throw new InputError("validity must be 1..365 days");
      let jwk: JWK; let privateOnce: JWK | null = null;
      if (f["generate"] === "on") {
        const { publicKey, privateKey } = await generateKeyPair("ES256", { extractable: true });
        jwk = await exportJWK(publicKey); privateOnce = await exportJWK(privateKey);
      } else {
        try { jwk = JSON.parse(f["jwk"] ?? "") as JWK; } catch { throw new InputError("the public key must be valid JSON"); }
        if (jwk.kty !== "EC" || jwk.crv !== "P-256" || typeof jwk.x !== "string" || typeof jwk.y !== "string") throw new InputError("an EC P-256 public key is required");
        if (["d", "p", "q", "dp", "dq", "qi", "k"].some((k) => k in jwk)) throw new InputError("private key material must never be submitted");
        jwk = { kty: jwk.kty, crv: jwk.crv, x: jwk.x, y: jwk.y };
      }
      const kid = (f["kid"] ?? "").trim() || (await calculateJwkThumbprint(jwk)).slice(0, 24);
      const pub = { ...jwk, kid, alg: "ES256", use: "sig" };
      const scopes = (f["scopes"] ?? "").split(/[ ,]+/).filter(Boolean);
      const payload: Record<string, unknown> = { clientId, kid, jwk: pub, certSha256: thumb, expiresAt: new Date(Date.now() + days * 864e5).toISOString(), ...(f["rotateOutKid"] ? { rotateOutKid: f["rotateOutKid"].trim(), overlapMinutes: 60 } : {}), ...(scopes.length ? { createClient: { orgId, scopes } } : {}) };
      const id = (await c.tx((tx) => tx.query("SELECT cfg_request('KEY_REGISTER',$1,$2::jsonb,$3,$4,NULL) AS id", [`client:${clientId}`, JSON.stringify(payload), c.user.sub, orgId]))).rows[0].id as string;
      await c.audit("admin.change.request", "OK", orgId, { kind: "KEY_REGISTER", target: `client:${clientId}`, change: id, generated: !!privateOnce });
      if (privateOnce) {
        // SHOW ONCE: rendered in this response only. It is not stored, not logged, not audited and cannot be retrieved again.
        return c.html("Your private key (shown once)", h`<p class="err"><b>Copy this private key now. It is not stored anywhere and cannot be shown again.</b></p>${pre(privateOnce)}<p>The public key was submitted for approval as <a href="/changes/${id}">change ${id}</a>. Bind it to your client certificate thumbprint before use.</p>`);
      }
      return c.redirect(`/changes/${id}`);
    } catch (e) { return bad(c, e); }
  });
  route("POST", "/credentials/revoke", ["platform_admin", "operations", "integration_engineer", "bank_user", "telco_user"], async (c) => {
    const clientId = c.form["clientId"] ?? "", kid = c.form["kid"] ?? "";
    if (!/^[a-z0-9][a-z0-9_-]{2,62}$/.test(clientId) || !/^[A-Za-z0-9_.:-]{1,64}$/.test(kid)) return bad(c, new InputError("invalid key"));
    const ok = (await c.tx((tx) => tx.query("SELECT admin_revoke_key($1,$2,$3) AS ok", [clientId, kid, c.user.sub]))).rows[0].ok as boolean;
    d.log.warn({ "event.category": "security", "event.action": "admin.credential.revoked", actor: c.user.sub, client: clientId }, "security_event");
    await c.audit("admin.credential.revoke", ok ? "OK" : "NOOP", undefined, { client: clientId, kid });
    return c.redirect("/credentials");
  });
  void randomBytes;
}
export type { Raw };
