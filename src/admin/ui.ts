// Server-rendered HTML with AUTO-ESCAPING: every interpolated value is escaped unless explicitly wrapped in raw().
// No client-side script exists; the CSP forbids it (script-src 'none').
const ESC: Record<string, string> = { "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;", "`": "&#96;" };
export const esc = (v: unknown): string => String(v ?? "").replace(/[&<>"'`]/g, (c) => ESC[c] as string);
export class Raw { constructor(readonly v: string) {} toString() { return this.v; } }
export const raw = (s: string) => new Raw(s);
const part = (v: unknown): string => (v instanceof Raw ? v.v : Array.isArray(v) ? v.map(part).join("") : esc(v));
export function h(strings: TemplateStringsArray, ...vals: unknown[]): Raw {
  return new Raw(strings.reduce((acc, s, i) => acc + s + (i < vals.length ? part(vals[i]) : ""), ""));
}
export const table = (head: string[], rows: unknown[][]): Raw =>
  h`<table><thead><tr>${head.map((x) => h`<th>${x}</th>`)}</tr></thead><tbody>${rows.map((r) => h`<tr>${r.map((c) => h`<td>${c}</td>`)}</tr>`)}</tbody></table>`;
export const form = (action: string, csrf: string, inner: Raw, method = "post"): Raw =>
  h`<form method="${method}" action="${action}" autocomplete="off"><input type="hidden" name="_csrf" value="${csrf}">${inner}</form>`;
export const field = (name: string, label: string, value = "", type = "text"): Raw => h`<label>${label} <input type="${type}" name="${name}" value="${value}" maxlength="2000"></label>`;
export const select = (name: string, label: string, options: string[]): Raw => h`<label>${label} <select name="${name}">${options.map((o) => h`<option value="${o}">${o}</option>`)}</select></label>`;

export interface PageUser { sub: string; displayName: string; role: string; orgId: string | null }
const NAV: Array<[string, string, string[]]> = [
  ["/", "Home", []], ["/orgs", "Organisations", []], ["/changes", "Changes", []], ["/config", "Configuration", ["platform_admin", "operations", "integration_engineer", "security_auditor", "finance"]],
  ["/history", "History", ["platform_admin", "operations", "integration_engineer", "security_auditor", "finance"]], ["/credentials", "Credentials", []],
  ["/killswitches", "Kill switches", ["platform_admin", "operations", "security_auditor"]], ["/integration", "Integration", ["platform_admin", "operations", "integration_engineer", "security_auditor"]],
];
export function page(o: { title: string; nonce: string; user?: PageUser; csrf?: string; body: Raw }): string {
  const nav = o.user ? h`<nav>${NAV.filter(([, , roles]) => roles.length === 0 || roles.includes(o.user!.role)).map(([href, label]) => h`<a href="${href}">${label}</a> `)}
    ${form("/logout", o.csrf ?? "", h`<button>Sign out (${o.user.displayName}, ${o.user.role})</button>`)}</nav>` : h``;
  return h`<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>${o.title} - Telco Signal admin (sandbox)</title>
<style nonce="${o.nonce}">body{font-family:system-ui,sans-serif;margin:1rem 2rem}table{border-collapse:collapse}td,th{border:1px solid #999;padding:.25rem .5rem;text-align:left}
.banner{border:2px solid #b00020;padding:.5rem;font-weight:600}nav a{margin-right:1rem}label{display:block;margin:.25rem 0}pre{background:#f4f4f4;padding:.5rem;overflow:auto}.err{color:#b00020}.ok{color:#0a6b2d}</style></head>
<body><p class="banner">SANDBOX: synthetic data only. NOT approved for live data.</p>${nav}<h1>${o.title}</h1>${o.body}</body></html>`.v;
}
