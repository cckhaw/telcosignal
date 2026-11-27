import { ALL_ROLES, HttpError, STAFF, type AdminDeps, type RouteCtx } from "./server.js";
import { field, form, h, select, table, type Raw } from "./ui.js";
import { csvLine, dashboardCsv, loadDashboard, type Dashboard, type Filters } from "./dashboard.js";
import { CATALOGUE, REASON_CLASSES, RESULT_CATALOGUE } from "../common/errors.js";
import { SIGNALS } from "../consent/consent.js";

type Route = (m: "GET" | "POST", path: string, roles: readonly string[], fn: (c: RouteCtx) => Promise<unknown>) => void;
const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/;
const STAFF_VIEW = [...STAFF] as readonly string[];
const AUDITORS = ["platform_admin", "security_auditor"] as const;
const ALERT_ROLES = ["platform_admin", "operations", "security_auditor"] as const;
const HEALTH_ROLES = ["platform_admin", "operations", "integration_engineer", "security_auditor"] as const;
const EXPORT_LOGS = ["platform_admin", "security_auditor", "operations"] as const;
const NOTE_ROLES = ["platform_admin", "operations", "security_auditor", "integration_engineer"] as const;
const fmt = (t: unknown) => (t ? new Date(t as string).toISOString().slice(0, 19) + "Z" : "");
const ms = (v: number | null) => (v === null ? "n/a" : v === Infinity ? ">=2000 ms" : `<= ${v} ms`);
const pc = (v: number | null) => (v === null ? "n/a" : `${(v * 100).toFixed(2)}%`);
const bad = (c: RouteCtx, msg: string) => c.html("Invalid input", h`<p class="err">${msg}</p>`, 400);
const bars = (items: Array<[string, number]>): Raw => {
  const max = Math.max(1, ...items.map(([, v]) => v));
  return h`<svg width="520" height="${Math.max(18, items.length * 18)}" role="img" aria-label="bar chart">${items.map(([k, v], i) => h`<text x="0" y="${i * 18 + 12}" font-size="11">${k}</text><rect x="170" y="${i * 18 + 2}" width="${Math.round((v / max) * 250)}" height="12" fill="#3b6fb6"></rect><text x="${175 + Math.round((v / max) * 250)}" y="${i * 18 + 12}" font-size="11">${v}</text>`)}</svg>`;
};

/** Parse and VALIDATE filter input; nothing from the query string reaches SQL except as a bound parameter. */
function parseFilters(q: Record<string, string | undefined>, user: RouteCtx["user"]): { f: Filters; err?: string } {
  const now = Date.now(); const P: Record<string, number> = { "1h": 3600e3, "24h": 86400e3, "7d": 7 * 86400e3, "30d": 30 * 86400e3 };
  let from: Date, to: Date;
  if (q["from"] || q["to"]) { from = new Date(q["from"] ?? ""); to = new Date(q["to"] ?? ""); }
  else { const span = P[q["period"] ?? "24h"]; if (!span) return { f: { from: new Date(), to: new Date() }, err: "invalid period" }; to = new Date(now + 60_000); from = new Date(now - span); }
  if (Number.isNaN(from.getTime()) || Number.isNaN(to.getTime()) || to <= from || to.getTime() - from.getTime() > 400 * 86400e3) return { f: { from, to }, err: "invalid time range" };
  const org = (q["org"] ?? "").trim(), telco = (q["telco"] ?? "").trim(), signal = (q["signal"] ?? "").trim(), ver = (q["version"] ?? "").trim();
  if (org && !UUID.test(org)) return { f: { from, to }, err: "invalid organisation" };
  if (telco && !/^[a-z0-9-]{1,30}$/.test(telco)) return { f: { from, to }, err: "invalid telco" };
  if (signal && !(SIGNALS as readonly string[]).includes(signal)) return { f: { from, to }, err: "invalid signal" };
  if (ver && !/^v[0-9]{1,3}$/.test(ver)) return { f: { from, to }, err: "invalid version" };
  const staff = STAFF_VIEW.includes(user.role);
  return { f: { from, to, orgId: staff ? org || undefined : user.orgId ?? undefined, telcoId: telco || undefined, signal: signal || undefined, version: ver || undefined } };
}
const filterForm = (c: RouteCtx, path: string, q: Record<string, string | undefined>): Raw => h`<form method="get" action="${path}">
  ${select("period", "Period", ["24h", "1h", "7d", "30d"])}${STAFF_VIEW.includes(c.user.role) ? field("org", "Participant (organisation id)", q["org"] ?? "") : h``}${field("telco", "Telco", q["telco"] ?? "")}${select("signal", "Signal", ["", ...SIGNALS])}${field("version", "API version", q["version"] ?? "")}<button>Apply</button></form>`;
const qs = (q: Record<string, string | undefined>) => new URLSearchParams(Object.entries(q).filter(([, v]) => v) as [string, string][]).toString();

export function registerOpsPages(d: AdminDeps, route: Route) {
  const staffOf = (c: RouteCtx) => STAFF_VIEW.includes(c.user.role);
  const exportAudit = (c: RouteCtx, kind: string, rows: number, f: Record<string, string | number>) => c.audit("admin.export", "OK", undefined, { kind, rows, ...f });

  // ---------- dashboards ----------
  const renderDash = (c: RouteCtx, dash: Dashboard, title: string, q: Record<string, string | undefined>, extra: Raw = h``) => {
    const fr = dash.freshness;
    return c.html(title, h`${filterForm(c, "/dashboard", q)}
      <p>Data as of <b>${fr.watermark ? fmt(fr.watermark) : "never"}</b>${fr.ageSeconds !== null ? ` (${fr.ageSeconds}s ago)` : ""}. ${fr.stale ? h`<span class="err">Rollups are stale: figures may lag the request path.</span>` : h`<span class="ok">Fresh.</span>`} Window ${fmt(dash.filters.from)} to ${fmt(dash.filters.to)}. Percentiles are bucket upper bounds.</p>
      <p><a href="/dashboard.csv?${qs(q)}">CSV export</a> &middot; <a href="/reports/monthly">Monthly report</a></p>
      <h2>Traffic</h2>${table(["Requests", "Billable", "Avg req/s", "Peak req/s"], [[dash.traffic.requests, dash.traffic.billable, dash.traffic.avgRps.toFixed(3), dash.traffic.peakRps.toFixed(3)]])}
      <h3>Trend (per hour)</h3>${bars(dash.traffic.trend.map((t) => [fmt(t.hour).slice(5, 16), t.requests]))}
      ${staffOf(c) ? h`<h3>Share by participant</h3>${table(["Participant", "Requests", "Share"], dash.traffic.byOrg.map((r) => [r.org, r.requests, pc(r.share)]))}` : h``}
      <h3>Share by telco</h3>${table(["Telco", "Requests", "Share"], dash.traffic.byTelco.map((r) => [r.telco, r.requests, pc(r.share)]))}
      <h2>Response time</h2>${table(["", "p50", "p95", "p99"], [["Total", ms(dash.latency.total.p50), ms(dash.latency.total.p95), ms(dash.latency.total.p99)], ["Platform overhead (total minus telco)", ms(dash.latency.overhead.p50), ms(dash.latency.overhead.p95), ms(dash.latency.overhead.p99)], ["Telco time", ms(dash.latency.telco.p50), ms(dash.latency.telco.p95), ms(dash.latency.telco.p99)]])}
      <h2>Reliability</h2>${table(["Success rate", "UNAVAILABLE rate", "NOT_SUPPORTED rate", "Timeout rate", "SLA attainment", "SLA breaches (minutes)"], [[pc(dash.reliability.successRate), pc(dash.reliability.unavailableRate), pc(dash.reliability.notSupportedRate), pc(dash.reliability.timeoutRate), pc(dash.reliability.sla.attainment), dash.reliability.sla.breaches]])}
      <h3>Outcomes</h3>${bars(Object.entries(dash.reliability.outcomes))}<h3>Errors and non-answers by type</h3>${bars(Object.entries(dash.reliability.byReason).filter(([k]) => k !== "ok"))}
      <h2>Security</h2>${table(["Signal", "Count"], [...Object.entries(dash.security.byCode), ["Suspected enumeration flags", dash.security.abuseFlags ?? "(staff only)"], ["Credentials expiring within 30 days", dash.security.credsNearExpiry]])}
      <h2>Business</h2>${table(["Active participants", "Billable volume", "Charges (minor units, from statements)", "Telco cost (minor units, from statements)"], [[dash.business.activeParticipants, dash.business.billableVolume, dash.business.charges ?? "no statements in window", staffOf(c) ? dash.business.telcoCost ?? "no statements in window" : "(staff only)"]])}
      ${dash.business.onboarding ? h`<h3>Onboarding progress</h3>${table(["State", "Organisations"], Object.entries(dash.business.onboarding))}<p>Signal coverage: ${dash.business.coverage?.covered ?? 0} of ${dash.business.coverage?.possible ?? 0} (telco, signal) pairs on active telcos.</p>` : h``}${extra}`);
  };
  route("GET", "/dashboard", ALL_ROLES, async (c) => {
    const q = c.req.query as Record<string, string | undefined>; const { f, err } = parseFilters(q, c.user); if (err) return bad(c, err);
    const dash = await c.tx((tx) => loadDashboard(tx, f, { staff: staffOf(c) }));
    await c.audit("admin.view.dashboard", "OK");
    return renderDash(c, dash, "Performance dashboard", q);
  });
  route("GET", "/dashboard.csv", ALL_ROLES, async (c) => {
    const q = c.req.query as Record<string, string | undefined>; const { f, err } = parseFilters(q, c.user); if (err) return bad(c, err);
    const dash = await c.tx((tx) => loadDashboard(tx, f, { staff: staffOf(c) }));
    const csv = dashboardCsv(dash); await exportAudit(c, "dashboard", csv.split("\n").length - 1, { scope: staffOf(c) ? "all" : "own" });
    return c.reply.header("content-disposition", 'attachment; filename="dashboard.csv"').type("text/csv; charset=utf-8").send(csv);
  });
  const monthRange = (m: string | undefined): { from: Date; to: Date; label: string } | null => {
    const mm = /^(\d{4})-(\d{2})$/.exec(m ?? ""); if (!mm) { const n = new Date(); const y = n.getUTCFullYear(), mo = n.getUTCMonth(); return { from: new Date(Date.UTC(y, mo, 1)), to: new Date(Date.UTC(y, mo + 1, 1)), label: `${y}-${String(mo + 1).padStart(2, "0")}` }; }
    const y = Number(mm[1]), mo = Number(mm[2]) - 1; if (mo < 0 || mo > 11) return null;
    return { from: new Date(Date.UTC(y, mo, 1)), to: new Date(Date.UTC(y, mo + 1, 1)), label: m! };
  };
  route("GET", "/reports/monthly", ALL_ROLES, async (c) => {
    const q = c.req.query as Record<string, string | undefined>; const mr = monthRange(q["month"]); if (!mr) return bad(c, "invalid month");
    const f: Filters = { from: mr.from, to: mr.to, orgId: staffOf(c) ? undefined : c.user.orgId ?? undefined };
    const dash = await c.tx((tx) => loadDashboard(tx, f, { staff: staffOf(c) }));
    await c.audit("admin.view.report", "OK", undefined, { month: mr.label });
    return renderDash(c, dash, `Monthly report ${mr.label}`, { period: "30d" }, h`<p><a href="/reports/monthly.csv?month=${mr.label}">Download this report (CSV)</a></p>`);
  });
  route("GET", "/reports/monthly.csv", ALL_ROLES, async (c) => {
    const q = c.req.query as Record<string, string | undefined>; const mr = monthRange(q["month"]); if (!mr) return bad(c, "invalid month");
    const dash = await c.tx((tx) => loadDashboard(tx, { from: mr.from, to: mr.to, orgId: staffOf(c) ? undefined : c.user.orgId ?? undefined }, { staff: staffOf(c) }));
    const csv = dashboardCsv(dash); await exportAudit(c, "monthly_report", csv.split("\n").length - 1, { month: mr.label });
    return c.reply.header("content-disposition", `attachment; filename="report-${mr.label}.csv"`).type("text/csv; charset=utf-8").send(csv);
  });

  // ---------- logs, request trace, audit ----------
  const LOG_COLS = "l.ts, l.correlation_id, o.name AS org_name, l.client_id, l.signal, l.telco_id, l.outcome, l.error_code, l.http_status, l.total_ms, l.telco_ms, l.reason_class, l.subject_ref";
  const logQuery = async (c: RouteCtx, q: Record<string, string | undefined>, limit: number) => {
    const { f, err } = parseFilters(q, c.user); if (err) return { err } as const;
    const outcome = (q["outcome"] ?? "").trim(), code = (q["error_code"] ?? "").trim(), corr = (q["correlation_id"] ?? "").trim(), client = (q["client"] ?? "").trim();
    if (outcome && !/^(TRUE|FALSE|UNAVAILABLE|NOT_SUPPORTED|REJECTED|ERROR|OK)$/.test(outcome)) return { err: "invalid outcome" } as const;
    if (code && !/^[A-Z_]{3,40}$/.test(code)) return { err: "invalid error code" } as const;
    if (corr && !/^[A-Za-z0-9-]{8,64}$/.test(corr)) return { err: "invalid correlation id" } as const;
    if (client && !/^[a-z0-9][a-z0-9_-]{2,62}$/.test(client)) return { err: "invalid participant client id" } as const;
    const rows = await c.tx((tx) => tx.query(`SELECT ${LOG_COLS} FROM request_log l LEFT JOIN organisations o ON o.id = l.org_id
      WHERE l.ts >= $1 AND l.ts < $2 AND ($3::uuid IS NULL OR l.org_id = $3) AND ($4::text IS NULL OR l.telco_id = $4) AND ($5::text IS NULL OR l.signal = $5) AND ($6::text IS NULL OR l.api_version = $6)
        AND ($7::text IS NULL OR l.outcome = $7) AND ($8::text IS NULL OR l.error_code = $8) AND ($9::text IS NULL OR l.correlation_id = $9) AND ($10::text IS NULL OR l.client_id = $10)
      ORDER BY l.ts DESC LIMIT ${limit}`, [f.from, f.to, f.orgId ?? null, f.telcoId ?? null, f.signal ?? null, f.version ?? null, outcome || null, code || null, corr || null, client || null]));
    return { rows: rows.rows, f } as const;
  };
  route("GET", "/logs", ALL_ROLES, async (c) => {
    const q = c.req.query as Record<string, string | undefined>; const r = await logQuery(c, q, 200); if ("err" in r) return bad(c, r.err!);
    await c.audit("admin.view.logs", "OK", undefined, { rows: r.rows.length });
    const canExport = (EXPORT_LOGS as readonly string[]).includes(c.user.role);
    return c.html("Request logs (values are masked; there is no unmask function)", h`${filterForm(c, "/logs", q)}
      <form method="get" action="/logs">${field("correlation_id", "Correlation id", q["correlation_id"] ?? "")}${field("client", "Participant client id", q["client"] ?? "")}${select("outcome", "Outcome", ["", "TRUE", "FALSE", "UNAVAILABLE", "NOT_SUPPORTED", "REJECTED", "ERROR", "OK"])}${field("error_code", "Error code", q["error_code"] ?? "")}<button>Search</button></form>
      ${canExport ? h`<p><a href="/logs.csv?${qs(q)}">CSV export (audited)</a></p>` : h``}
      ${table(["Time", "Correlation id", "Participant", "Signal", "Telco", "Outcome", "Error", "HTTP", "Total ms", "Telco ms", "Class", "Masked subject"], r.rows.map((x) => [fmt(x.ts), h`<a href="/logs/${x.correlation_id}">${x.correlation_id}</a>`, x.org_name ?? x.client_id ?? "(unidentified)", x.signal ?? "", x.telco_id ?? "", x.outcome, x.error_code ?? "", x.http_status, x.total_ms, x.telco_ms, x.reason_class, x.subject_ref ? `subject:${x.subject_ref}` : ""]))}
      <p>Showing up to 200 rows. Subjects are shown only as a prefix of a keyed hash; phone numbers are never stored.</p>`);
  });
  route("GET", "/logs.csv", EXPORT_LOGS, async (c) => {
    const q = c.req.query as Record<string, string | undefined>; const r = await logQuery(c, q, 5000); if ("err" in r) return bad(c, r.err!);
    let csv = csvLine(["time", "correlation_id", "participant", "signal", "telco", "outcome", "error_code", "http_status", "total_ms", "telco_ms", "reason_class", "masked_subject"]);
    for (const x of r.rows) csv += csvLine([new Date(x.ts as string).toISOString(), x.correlation_id, x.org_name ?? x.client_id ?? "", x.signal ?? "", x.telco_id ?? "", x.outcome, x.error_code ?? "", x.http_status, x.total_ms, x.telco_ms, x.reason_class, x.subject_ref ?? ""]);
    await exportAudit(c, "logs", r.rows.length, { from: r.f.from.toISOString(), to: r.f.to.toISOString() });
    return c.reply.header("content-disposition", 'attachment; filename="logs.csv"').type("text/csv; charset=utf-8").send(csv);
  });
  route("GET", "/logs/:cid", ALL_ROLES, async (c) => {
    const cid = c.params["cid"] ?? ""; if (!/^[A-Za-z0-9-]{8,64}$/.test(cid)) throw new HttpError(404, "Not found.");
    const data = await c.tx(async (tx) => ({
      rows: (await tx.query("SELECT l.*, o.name AS org_name FROM request_log l LEFT JOIN organisations o ON o.id=l.org_id WHERE l.correlation_id=$1 ORDER BY l.ts", [cid])).rows,
      notes: STAFF_VIEW.includes(c.user.role) ? (await tx.query("SELECT ts, author, body FROM incident_note WHERE correlation_id=$1 ORDER BY ts", [cid])).rows : [],
    }));
    if (data.rows.length === 0) throw new HttpError(404, "Not found.");
    await c.audit("admin.view.trace", "OK", undefined, { correlation: cid });
    let related: Array<Record<string, unknown>> = [];
    if ((AUDITORS as readonly string[]).includes(c.user.role)) related = (await c.tx((tx) => tx.query("SELECT * FROM audit_search($1,$2,NULL,NULL,$3,50,$4)", [new Date(0), new Date(Date.now() + 86400e3), cid, c.user.sub]))).rows;
    const canNote = (NOTE_ROLES as readonly string[]).includes(c.user.role);
    return c.html(`Trace ${cid}`, h`<p>One request, end to end. Real requests can never be replayed here; use the test console with synthetic numbers.</p>${data.rows.map((x) => {
      const steps = (x.steps as Array<{ s: string; ms: number }>) ?? []; const total = Math.max(1, x.total_ms as number);
      const cat = CATALOGUE.find((e) => e.code === x.error_code), rc = REASON_CLASSES.find((e) => e.cls === x.reason_class);
      let acc = 0;
      return h`<h2>${fmt(x.ts)} &middot; ${x.method} ${x.route} &middot; HTTP ${x.http_status} &middot; ${x.outcome}</h2>
      ${table(["Field", "Value"], [["Participant", x.org_name ?? x.client_id ?? "(unidentified)"], ["Signal", x.signal ?? ""], ["Telco (router decision)", x.telco_id ?? "none"], ["Reason class", x.reason_class], ["Reason", x.reason], ["Error code", x.error_code ?? ""], ["Masked subject", x.subject_ref ? `subject:${x.subject_ref}` : ""], ["API version", x.api_version]])}
      <h3>Timing by step (total ${x.total_ms} ms: platform overhead ${Math.max(0, (x.total_ms as number) - (x.telco_ms as number))} ms, telco ${x.telco_ms} ms)</h3>
      <svg width="640" height="${(steps.length + 1) * 20 + 6}" role="img" aria-label="timing by step">
        <text x="0" y="14" font-size="11">gateway / WAF</text><text x="170" y="14" font-size="11">not instrumented in the sandbox (sits in front of the platform)</text>
        ${steps.map((st, i) => { const x0 = 170 + Math.round((acc / total) * 420); acc += st.ms; return h`<text x="0" y="${(i + 1) * 20 + 14}" font-size="11">${st.s}${st.s === "adapter" ? " (telco call)" : st.s === "route" ? " (router)" : ""}</text><rect x="${x0}" y="${(i + 1) * 20 + 4}" width="${Math.max(2, Math.round((st.ms / total) * 420))}" height="12" fill="${st.s === "adapter" ? "#b0561b" : "#3b6fb6"}"></rect><text x="${x0 + Math.max(2, Math.round((st.ms / total) * 420)) + 4}" y="${(i + 1) * 20 + 14}" font-size="11">${st.ms} ms</text>`; })}
      </svg>
      ${table(["Step", "ms"], steps.map((st) => [st.s, st.ms]))}
      <h3>What this means and what to do</h3>${table(["", "Meaning", "Suggested action"], [...(cat ? [[`Error ${cat.code}`, cat.meaning, cat.operatorAction]] : []), ...(rc ? [[`Class ${rc.cls}`, rc.meaning, rc.operatorAction]] : [])])}`;
    })}
    ${related.length ? h`<h3>Audit events with this correlation id</h3>${table(["Seq", "Time", "Actor", "Action", "Outcome", "Detail"], related.map((a) => [String(a["seq"]), fmt(a["ts"]), String(a["actor"]), String(a["action"]), String(a["outcome"]), String(a["detail_text"])]))}` : h``}
    <h3>Incident notes</h3>${table(["Time", "Author", "Note"], data.notes.map((n) => [fmt(n.ts), n.author, n.body]))}
    ${canNote ? form("/notes", c.user.csrf, h`<input type="hidden" name="correlationId" value="${cid}">${field("body", "Add a note (no phone numbers)")}<button>Add note</button>`) : h``}`);
  });
  route("GET", "/audit", AUDITORS, async (c) => {
    const q = c.req.query as Record<string, string | undefined>;
    const actor = (q["actor"] ?? "").trim() || null, action = (q["action"] ?? "").trim() || null, corr = (q["correlation_id"] ?? "").trim() || null;
    if ((actor && !/^[A-Za-z0-9._:@-]{1,128}$/.test(actor)) || (action && !/^[a-z0-9._]{1,80}$/.test(action)) || (corr && !/^[A-Za-z0-9-]{8,64}$/.test(corr))) return bad(c, "invalid filter");
    const rows = (await c.tx((tx) => tx.query("SELECT * FROM audit_search($1,$2,$3,$4,$5,200,$6)", [new Date(Date.now() - 7 * 86400e3), new Date(Date.now() + 86400e3), actor, action, corr, c.user.sub]))).rows;
    const v = (await c.tx((tx) => tx.query("SELECT * FROM audit_verify()"))).rows[0];
    await c.audit("admin.view.audit", "OK", undefined, { rows: rows.length });
    return c.html("Audit trail (append-only, hash-chained; read-only here)", h`<p>Chain verification: ${v.ok ? h`<span class="ok">intact (${v.rows} records)</span>` : h`<span class="err">BROKEN: ${v.problem}</span>`}. The audit log cannot be edited or deleted from this portal.</p>
      <form method="get" action="/audit">${field("actor", "Actor", actor ?? "")}${field("action", "Action", action ?? "")}${field("correlation_id", "Correlation id", corr ?? "")}<button>Search (last 7 days)</button></form>
      ${table(["Seq", "Time", "Actor", "Action", "Outcome", "Correlation", "Detail"], rows.map((a) => [String(a.seq), fmt(a.ts), a.actor, a.action, a.outcome, a.correlation_id, a.detail_text]))}`);
  });

  // ---------- alerts, incident notes ----------
  route("GET", "/alerts", ALERT_ROLES, async (c) => {
    const data = await c.tx(async (tx) => ({
      alerts: (await tx.query("SELECT a.*, r.metric FROM alert a JOIN alert_rule r ON r.id=a.rule_id ORDER BY (a.status IN ('open','escalated')) DESC, a.opened_at DESC LIMIT 100")).rows,
      rules: (await tx.query("SELECT * FROM alert_rule ORDER BY id")).rows, notes: (await tx.query("SELECT ts, author, alert_id, body FROM incident_note ORDER BY ts DESC LIMIT 30")).rows,
    }));
    await c.audit("admin.view.alerts", "OK");
    const can = ["platform_admin", "operations"].includes(c.user.role), canAck = (ALERT_ROLES as readonly string[]).includes(c.user.role);
    return c.html("Alerts", h`${table(["Id", "Rule", "Severity", "Status", "Observed", "Threshold", "Opened", "Acknowledged by", "Escalated", ""], data.alerts.map((a) => [a.id, a.rule_id, a.severity, a.status, Number(a.observed), Number(a.threshold), fmt(a.opened_at), a.acknowledged_by ?? "", fmt(a.escalated_at),
        canAck && (a.status === "open" || a.status === "escalated") ? form(`/alerts/${a.id}/ack`, c.user.csrf, h`<button>Acknowledge</button>`) : ""]))}
      <h2>Rules (thresholds are configurable and every change is versioned and audited)</h2>${table(["Id", "Metric", "Cmp", "Threshold", "Window (min)", "Severity", "Escalate after (min)", "Enabled", "Updated by"], data.rules.map((r) => [r.id, r.metric, r.comparator, Number(r.threshold), r.window_minutes, r.severity, r.escalate_after_minutes, r.enabled ? "yes" : "NO", r.updated_by]))}
      ${can ? h`<h3>Set a rule</h3>${form("/alerts/rules", c.user.csrf, h`${field("id", "Rule id")}${select("metric", "Metric", ["auth_failures", "rate_limit_hits", "replay_rejections", "abuse_flags", "unavailable_rate", "success_rate_min", "timeout_rate", "circuit_open", "overhead_p95_ms", "creds_expiring", "consent_denials"])}${select("comparator", "Comparator", ["gt", "lt"])}${field("threshold", "Threshold")}${field("windowMinutes", "Window (minutes)", "10")}${select("severity", "Severity", ["warning", "critical", "info"])}${field("escalateAfter", "Escalate after (minutes)", "30")}<label>Enabled <input type="checkbox" name="enabled" checked></label><button>Save</button>`)}` : h``}
      <h2>Incident notes</h2>${table(["Time", "Author", "Alert", "Note"], data.notes.map((n) => [fmt(n.ts), n.author, n.alert_id ?? "", n.body]))}
      ${form("/notes", c.user.csrf, h`${field("alertId", "Alert id (optional)")}${field("body", "Add a note (no phone numbers)")}<button>Add note</button>`)}`);
  });
  route("POST", "/alerts/:id/ack", ALERT_ROLES, async (c) => {
    const id = Number(c.params["id"]); if (!Number.isInteger(id) || id < 1) throw new HttpError(404, "Not found.");
    const ok = (await c.tx((tx) => tx.query("SELECT alert_ack($1,$2) AS ok", [id, c.user.sub]))).rows[0].ok as boolean;
    await c.audit("admin.alert.ack", ok ? "OK" : "NOOP", undefined, { alert: id });
    return c.redirect("/alerts");
  });
  route("POST", "/alerts/rules", ["platform_admin", "operations"], async (c) => {
    const f = c.form; const th = Number(f["threshold"]), wm = Number(f["windowMinutes"]), es = Number(f["escalateAfter"]);
    if (!/^[a-z0-9_-]{3,40}$/.test(f["id"] ?? "") || !Number.isFinite(th) || !Number.isInteger(wm) || !Number.isInteger(es)) return bad(c, "invalid rule");
    await c.tx((tx) => tx.query("SELECT alert_rule_set($1,$2,$3,$4,$5,$6,$7,$8,$9)", [f["id"], f["metric"], f["comparator"], th, wm, f["severity"], es, f["enabled"] === "on", c.user.sub]));
    await c.audit("admin.alert.rule", "OK", undefined, { rule: f["id"] ?? "", enabled: f["enabled"] === "on" });
    return c.redirect("/alerts");
  });
  route("POST", "/notes", NOTE_ROLES, async (c) => {
    const body = (c.form["body"] ?? "").trim(), alert = (c.form["alertId"] ?? "").trim(), corr = (c.form["correlationId"] ?? "").trim();
    if (!body || body.length > 2000 || /\+[1-9][0-9]{4,14}/.test(body)) return bad(c, "Notes must be 1 to 2000 characters and must not contain phone numbers.");
    if ((alert && !/^\d{1,12}$/.test(alert)) || (corr && !/^[A-Za-z0-9-]{8,64}$/.test(corr))) return bad(c, "invalid reference");
    await c.tx((tx) => tx.query("SELECT incident_note_add($1,$2,$3,$4)", [alert ? Number(alert) : null, corr || null, body, c.user.sub]));
    await c.audit("admin.note.add", "OK");
    return c.redirect(corr ? `/logs/${corr}` : "/alerts");
  });

  // ---------- dependency health, error catalogue ----------
  route("GET", "/health", HEALTH_ROLES, async (c) => {
    const t0 = performance.now();
    const data = await c.tx(async (tx) => {
      await tx.query("SELECT 1");
      return {
        rs: (await tx.query("SELECT watermark, updated_at FROM rollup_state WHERE name='main'")).rows[0],
        telcos: (await tx.query("SELECT t.id, t.state, t.adapter, (SELECT status FROM onboarding_test x WHERE x.org_id=t.org_id AND x.test_key='health_check' ORDER BY id DESC LIMIT 1) AS hc FROM telcos t ORDER BY 1")).rows,
        open: Number((await tx.query("SELECT count(*) n FROM alert WHERE status IN ('open','escalated')")).rows[0].n),
        chain: (await tx.query("SELECT * FROM audit_verify()")).rows[0],
        ret: (await tx.query("SELECT key, value FROM platform_setting WHERE key IN ('logs.retention_days','consent.retention_days')")).rows,
      };
    });
    const dbMs = Math.round(performance.now() - t0);
    const br = new Map((d.registry?.breakerStates() ?? []).map((b) => [b.telcoId, b]));
    const age = data.rs ? Math.round((Date.now() - new Date(data.rs.updated_at as string).getTime()) / 1000) : null;
    await c.audit("admin.view.health", "OK");
    return c.html("Dependency health", h`${table(["Dependency", "Status"], [["Database (this portal's role)", `ok, ${dbMs} ms`], ["Rollup worker", age === null ? "never ran" : age > 180 ? `STALE (${age}s ago)` : `ok (${age}s ago)`], ["Audit chain", data.chain.ok ? `intact (${data.chain.rows} records)` : `BROKEN: ${data.chain.problem}`], ["Open or escalated alerts", data.open], ["Retention", data.ret.map((r) => `${r.key}=${JSON.stringify(r.value)}`).join(", ")]])}
      <h2>Telco connections</h2>${table(["Telco", "State", "Adapter", "Last health check", "Circuit breaker (this instance)"], data.telcos.map((t) => [t.id, t.state, t.adapter, t.hc ?? "not run", br.get(t.id) ? `${br.get(t.id)!.state} (${br.get(t.id)!.recentFaults}/${br.get(t.id)!.recentTotal} recent faults)` : "no traffic seen by this instance"]))}`);
  });
  route("GET", "/errors", ALL_ROLES, async (c) => c.html("Error catalogue", h`<h2>HTTP errors</h2>${table(["Code", "HTTP", "Meaning", "What a participant should do", "What an operator should do"], CATALOGUE.map((e) => [e.code, e.status, e.meaning, e.participantAction, e.operatorAction]))}
    <h2>Signal results</h2>${table(["Result", "Meaning", "What to do"], RESULT_CATALOGUE.map((r) => [r.result, r.meaning, r.action]))}
    <h2>Reason classes (logs and dashboards)</h2>${table(["Class", "Meaning", "Operator action"], REASON_CLASSES.map((r) => [r.cls, r.meaning, r.operatorAction]))}`));
}
