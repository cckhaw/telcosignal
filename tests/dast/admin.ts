// Black-box DAST of the RUNNING admin interface + mock IdP (own sandbox only). Exit 1 on any failed check.
// Usage: npx tsx tests/dast/admin.ts [.sandbox]
import { readFileSync, writeFileSync } from "node:fs";
import { Agent, request } from "undici";

const dir = process.argv[2] ?? ".sandbox";
const part = JSON.parse(readFileSync(`${dir}/participants.json`, "utf8")) as { caFile: string; admin: { origin: string; bootstrap: string[] } };
const origin = part.admin.origin, [adminA, adminB] = part.admin.bootstrap as [string, string];
const agent = new Agent({ connect: { ca: readFileSync(part.caFile, "utf8") } });
const results: Array<{ category: string; check: string; ok: boolean; detail?: string }> = [];
const check = (category: string, name: string, ok: boolean, detail?: string) => { results.push({ category, check: name, ok, ...(detail ? { detail } : {}) }); if (!ok) console.error(`FAIL [${category}] ${name} ${detail ?? ""}`); };
interface R { status: number; text: string; headers: Record<string, string | string[] | undefined>; location?: string }
const raw = async (method: string, url: string, headers: Record<string, string> = {}, body?: string): Promise<R> => {
  try {
    const r = await request(url, { method: method as "GET", dispatcher: agent, headers, body: body ?? null, maxRedirections: 0 } as never);
    const loc = r.headers["location"];
    return { status: r.statusCode, text: await r.body.text(), headers: r.headers as R["headers"], ...(typeof loc === "string" ? { location: loc } : {}) };
  } catch (e) { return { status: 0, text: String((e as Error).message), headers: {} }; }
};
async function login(sub: string, params: Record<string, string> = {}): Promise<{ ok: boolean; status: number; cookie: string; csrf: string; setCookie: string[] }> {
  const a = await raw("GET", `${origin}/login?${new URLSearchParams({ login_hint: sub, ...params })}`);
  const lc = ([] as string[]).concat(a.headers["set-cookie"] ?? []).map((c) => c.split(";")[0]).join("; ");
  const b = await raw("GET", a.location ?? "");
  if (!b.location?.startsWith(origin)) return { ok: false, status: b.status, cookie: "", csrf: "", setCookie: [] };
  const c = await raw("GET", b.location, { cookie: lc });
  const sc = ([] as string[]).concat(c.headers["set-cookie"] ?? []);
  const cookie = sc.find((x) => x.startsWith("__Host-ts_admin=") && !x.startsWith("__Host-ts_admin=;"))?.split(";")[0] ?? "";
  const home = cookie ? await raw("GET", `${origin}/`, { cookie }) : { text: "" };
  return { ok: c.status === 302 && !!cookie, status: c.status, cookie, csrf: /name="_csrf" value="([^"]+)"/.exec(home.text)?.[1] ?? "", setCookie: sc };
}
const LEAK = /(at\s+[\w.<>]+\s+\(.*:\d+:\d+\)|node_modules|\.ts:\d+|postgres|ECONN|stack|syntax error|SELECT |pg_|ERROR:)/i;
const sleep = (ms: number) => new Promise((r) => setTimeout(r, ms));

// ---- unauthenticated surface ----
for (const p of ["/", "/orgs", "/changes", "/config", "/history", "/credentials", "/killswitches", "/integration", "/orgs/00000000-0000-4000-8000-000000000000", "/changes/00000000-0000-4000-8000-000000000000"]) {
  const r = await raw("GET", `${origin}${p}`);
  check("authn", `GET ${p} without a session redirects to sign-in and leaks nothing`, r.status === 302 && r.location === "/login" && !/organisation|credential|price/i.test(r.text), `status ${r.status}`);
}
for (const p of ["/orgs", "/changes/new", "/killswitches/engage", "/credentials/revoke"]) {
  const r = await raw("POST", `${origin}${p}`, { "content-type": "application/x-www-form-urlencoded", origin }, "name=x&kind=bank");
  check("authn", `POST ${p} without a session is not processed`, r.status === 302 && r.location === "/login", `status ${r.status}`);
}
const hdrs = await raw("GET", `${origin}/login`);
check("headers", "login redirect carries security headers", String(hdrs.headers["strict-transport-security"] ?? "").includes("max-age") && hdrs.headers["x-content-type-options"] === "nosniff");

// ---- authentication strength and hostile ID tokens ----
for (const [mode, why] of [["none", "password only"], ["totp", "one-time code (phishable)"]] as const) check("authn", `${why} sign-in is refused`, !(await login(adminA, { mock_mfa: mode })).ok);
for (const t of ["aud", "iss", "nonce", "expired", "unsigned", "hs256", "wrongkey"]) check("authn", `ID token with tampered ${t} is refused`, !(await login(adminA, { mock_tamper: t })).ok);
check("authn", "a stale authentication is refused", !(await login(adminA, { mock_auth_age: "3600" })).ok);
check("authn", "an unprovisioned identity is refused even with a hardware key (no default/JIT accounts)", !(await login("not-an-admin")).ok);
const s1 = await login(adminA), s2 = await login(adminB);
check("authn", "provisioned administrators can sign in with a hardware key", s1.ok && s2.ok);
if (!s1.ok || !s2.ok) { console.error("cannot continue without sessions"); process.exit(1); }
const sc = s1.setCookie.find((x) => x.startsWith("__Host-ts_admin="))!;
check("session", "session cookie is __Host-, HttpOnly, Secure, SameSite=Strict", /; Secure/.test(sc) && /; HttpOnly/.test(sc) && /SameSite=Strict/.test(sc) && /Path=\//.test(sc) && !/Domain=/i.test(sc));

const get = (s: { cookie: string }, p: string) => raw("GET", `${origin}${p}`, { cookie: s.cookie });
const post = (s: { cookie: string; csrf: string }, p: string, f: Record<string, string>, o: { csrf?: string | null; origin?: string | null } = {}) => {
  const form = { ...f }; const t = o.csrf === undefined ? s.csrf : o.csrf; if (t !== null) form["_csrf"] = t;
  return raw("POST", `${origin}${p}`, { cookie: s.cookie, "content-type": "application/x-www-form-urlencoded", ...(o.origin === null ? {} : { origin: o.origin ?? origin }) }, new URLSearchParams(form).toString());
};

// ---- page hardening ----
const home = await get(s1, "/orgs");
const csp = String(home.headers["content-security-policy"] ?? "");
check("headers", "CSP forbids all script, framing and cross-origin forms", csp.includes("default-src 'none'") && !/script-src/.test(csp) && csp.includes("frame-ancestors 'none'") && csp.includes("form-action 'self'") && !/unsafe-/.test(csp));
check("headers", "no caching, no framing, nosniff, no server banner", home.headers["cache-control"] === "no-store" && home.headers["x-frame-options"] === "DENY" && home.headers["x-content-type-options"] === "nosniff" && !home.headers["server"] && !home.headers["x-powered-by"]);
check("xss", "pages contain no script elements", !/<script/i.test(home.text));

// ---- CSRF ----
const probe = { name: "DAST CSRF probe", kind: "bank" };
check("csrf", "missing token is refused", (await post(s1, "/orgs", probe, { csrf: null })).status === 403);
check("csrf", "another session's token is refused", (await post(s1, "/orgs", probe, { csrf: s2.csrf })).status === 403);
check("csrf", "foreign Origin is refused", (await post(s1, "/orgs", probe, { origin: "https://evil.example" })).status === 403);
check("csrf", "missing Origin is refused", (await post(s1, "/orgs", probe, { origin: null })).status === 403);
check("csrf", "JSON bodies are refused (form encoding only)", (await raw("POST", `${origin}/orgs`, { cookie: s1.cookie, "content-type": "application/json", origin }, JSON.stringify({ ...probe, _csrf: s1.csrf }))).status === 415);

// ---- XSS and injection through form fields ----
const evil = `<script>alert(1)</script><img src=x onerror=alert(2)>`;
const created = await post(s1, "/orgs", { name: evil, kind: "bank" });
const shown = created.location ? await get(s1, created.location) : { text: "" };
check("xss", "hostile organisation name is rendered escaped", created.status === 302 && !shown.text.includes("<script>alert(1)") && !shown.text.includes("<img src=x") && shown.text.includes("&lt;script&gt;"));
const PAY = ["' OR '1'='1", "'; DROP TABLE organisations;--", "\" OR 1=1 --", "${7*7}", "{{7*7}}", "../../etc/passwd", "\u0000", "A".repeat(5000), "\r\nX-Injected: 1", "%00", "__proto__", "{\"$ne\":null}"];
let bad5 = 0, leaks = 0, n = 0;
for (const [path, fields] of [["/orgs", ["name", "kind"]], ["/changes/new", ["kind", "action", "orgId", "signal", "maxPerMinute", "key", "value", "prefix", "telcoId", "baseUrl", "msisdn"]], ["/credentials/register", ["orgId", "clientId", "certSha256", "jwk", "expiresInDays"]], ["/killswitches/engage", ["scope", "key"]], ["/integration/test", ["telcoId", "signal", "msisdn"]]] as Array<[string, string[]]>) {
  for (const f of fields) for (const p of PAY) {
    const form: Record<string, string> = { kind: "RATE_LIMIT", name: "x" }; form[f] = p;
    const r = await post(s1, path, form); n++;
    if (r.status === 0 || r.status >= 500) bad5++;
    if (LEAK.test(r.text)) leaks++;
    if (n % 40 === 0) await sleep(10);
  }
}
check("injection", `form-field fuzz (${n} requests): no 5xx / dropped connections`, bad5 === 0, `${bad5} bad`);
check("injection", "form-field fuzz: no stack, SQL or internal detail in any response", leaks === 0, `${leaks} leaks`);
for (const p of ["/orgs/%27%20OR%201=1", "/orgs/../../etc/passwd", "/changes/%00", "/orgs/" + "a".repeat(500)]) { const r = await get(s1, p); check("injection", `odd path ${p.slice(0, 24)} is a clean 4xx`, r.status >= 400 && r.status < 500 && !LEAK.test(r.text), `status ${r.status}`); }

// ---- two-person rule over the real interface ----
const mk = await post(s1, "/changes/new", { kind: "RATE_LIMIT", orgId: (/orgs\/([0-9a-f-]{36})/.exec(created.location ?? "") ?? [])[1] ?? "00000000-0000-4000-8000-000000000000", signal: "SIM_SWAP", maxPerMinute: "9" });
const chg = mk.location ?? "/changes/none";
check("approval", "a change request can be created", mk.status === 302 && chg.startsWith("/changes/"));
const own = await post(s1, `${chg}/approve`, { note: "self" });
check("approval", "the requester cannot approve their own change", own.status === 403, `status ${own.status}`);
const other = await post(s2, `${chg}/approve`, { note: "peer" });
check("approval", "a different administrator can approve it", other.status === 302, `status ${other.status}`);
const again = await post(s2, `${chg}/approve`, { note: "replay" });
check("approval", "approving twice is refused", again.status === 409, `status ${again.status}`);

// ---- session lifecycle ----
const out = await post(s2, "/logout", {});
check("session", "logout redirects to sign-in", out.status === 302);
check("session", "the old session cookie is dead after logout", (await get(s2, "/orgs")).status === 302);
for (const c of ["x", "A".repeat(43), "' OR 1=1 --", "A".repeat(5000)]) check("session", `forged cookie ${c.slice(0, 10)} never authenticates`, (await raw("GET", `${origin}/orgs`, { cookie: `__Host-ts_admin=${c}` })).status === 302);

const failed = results.filter((r) => !r.ok);
writeFileSync(process.env["DAST_REPORT"] ?? "dast-admin-report.json", JSON.stringify({ target: origin, finished: new Date().toISOString(), total: results.length, failed: failed.length, results }, null, 1));
console.log(`ADMIN DAST: ${results.length - failed.length}/${results.length} checks passed`);
process.exit(failed.length ? 1 : 0);
