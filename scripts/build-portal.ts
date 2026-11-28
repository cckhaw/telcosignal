// Builds the static developer portal (served by Vercel from ./portal) from the OpenAPI definition and the error catalogue.
// Output is plain HTML + one stylesheet + one icon: no script, no inline style, no external resources (matches the CSP in vercel.json).
// Navigation works without JavaScript: a sticky header with section links, a grouped sidebar (a CSS-only drawer on phones and tablets),
// breadcrumbs, an "on this page" list generated from the headings, and previous/next links.
import { mkdirSync, readFileSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import { parse } from "yaml";
import { CATALOGUE, RESULT_CATALOGUE } from "../src/common/errors.js";
import { esc } from "../src/admin/ui.js";
import { buildOpenApi } from "./gen-openapi.js";
import { stringify } from "yaml";

const BANNER = "SANDBOX: synthetic data only. NOT approved for live data. No certification or compliance is claimed.";
/** Navigation tree: level 1 = the header links (one per section), level 2 = the pages inside a section (the sidebar), level 3 = the headings of a page ("on this page"). */
const SECTIONS: Array<{ title: string; items: Array<[string, string]> }> = [
  { title: "Get started", items: [["index.html", "Overview"], ["authentication.html", "Authentication"], ["sandbox.html", "Sandbox"]] },
  { title: "API reference", items: [["signals.html", "Signals"], ["errors.html", "Errors and results"]] },
  { title: "Resources", items: [["versions.html", "Versions and deprecation"], ["openapi.yaml", "OpenAPI definition"]] },
];
const ORDER = ["index.html", "authentication.html", "sandbox.html", "signals.html", "errors.html", "versions.html"];
const LABEL = Object.fromEntries(SECTIONS.flatMap((s) => s.items));
const href = (f: string) => (f === "index.html" ? "/" : `/${f.endsWith(".html") ? f.slice(0, -5) : f}`);
const sectionOf = (f: string) => SECTIONS.find((s) => s.items.some(([x]) => x === f));
const slug = (t: string) => t.replace(/<[^>]+>/g, "").replace(/&[a-z#0-9]+;/g, " ").toLowerCase().replace(/[^a-z0-9]+/g, "-").replace(/^-+|-+$/g, "") || "section";

/** Adds a stable id and a "link to this section" anchor to every h2/h3 and returns the table of contents. */
function withAnchors(html: string): { html: string; toc: Array<{ level: number; id: string; text: string }> } {
  const used = new Set<string>(); const toc: Array<{ level: number; id: string; text: string }> = [];
  const out = html.replace(/<h([23])>([\s\S]*?)<\/h\1>/g, (_m, lvl: string, inner: string) => {
    let id = slug(inner); for (let i = 2; used.has(id); i++) id = `${slug(inner)}-${i}`; used.add(id);
    toc.push({ level: Number(lvl), id, text: inner.replace(/<[^>]+>/g, "") });
    return `<h${lvl} id="${id}">${inner}<a class="anchor" href="#${id}" aria-label="Link to this section">#</a></h${lvl}>`;
  });
  return { html: out, toc };
}
const tocList = (toc: Array<{ level: number; id: string; text: string }>) => `<ul>${toc.map((t) => `<li class="l${t.level}"><a href="#${t.id}">${esc(t.text)}</a></li>`).join("")}</ul>`;

interface PageOpts { lead?: string; hero?: string }
const page = (file: string, title: string, body: string, o: PageOpts = {}) => {
  const { html, toc } = withAnchors(body);
  const sec = sectionOf(file); const idx = ORDER.indexOf(file);
  const prev = idx > 0 ? ORDER[idx - 1]! : undefined, next = idx >= 0 && idx < ORDER.length - 1 ? ORDER[idx + 1]! : undefined;
  const desc = o.lead ?? "Developer documentation for the Telco Signal API sandbox reference implementation.";
  const nav = SECTIONS.map((s) => `<details class="group" open><summary>${esc(s.title)}</summary><ul>${s.items.map(([f, l]) => `<li><a href="${href(f)}"${f === file ? ' aria-current="page"' : ""}>${esc(l)}</a></li>`).join("")}</ul></details>`).join("");
  const top = SECTIONS.map((s) => `<a href="${href(s.items[0]![0])}"${s === sec ? ' aria-current="true"' : ""}>${esc(s.title)}</a>`).join("");
  const crumbs = `<li><a href="/">Home</a></li>${sec && file !== "index.html" ? `<li>${esc(sec.title)}</li>` : ""}${file !== "index.html" ? `<li aria-current="page">${esc(title)}</li>` : ""}`;
  const hasToc = toc.length >= 2;
  return `<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><meta name="color-scheme" content="light dark"><meta name="description" content="${esc(desc)}"><title>${esc(title)} - Telco Signal API developer portal (sandbox)</title><link rel="icon" href="/favicon.svg" type="image/svg+xml"><link rel="stylesheet" href="/style.css"></head>
<body><input type="checkbox" id="nav-toggle" class="nav-toggle" aria-label="Show or hide the navigation menu">
<a class="skip" href="#main">Skip to content</a>
<div class="sandbox-bar" role="note">${esc(BANNER)}</div>
<header class="site-header"><div class="bar"><label for="nav-toggle" class="menu-button"><span class="sr">Menu</span><span class="bars" aria-hidden="true"></span></label>
<a class="brand" href="/"><span class="logo" aria-hidden="true"></span><span class="brand-name">Telco Signal API</span><span class="brand-sub">Developer portal</span></a>
<nav class="topnav" aria-label="Sections">${top}</nav><span class="badges"><span class="badge env">Sandbox</span><span class="badge">API v1</span></span></div></header>
<div class="layout"><label for="nav-toggle" class="scrim" aria-hidden="true"></label>
<aside class="sidebar" aria-label="Documentation menu"><nav aria-label="Documentation">${nav}</nav></aside>
<main id="main" class="content"><nav class="breadcrumbs" aria-label="Breadcrumb"><ol>${crumbs}</ol></nav>
<article>${o.hero ?? `<h1>${esc(title)}</h1>${o.lead ? `<p class="lead">${esc(o.lead)}</p>` : ""}`}
${hasToc ? `<details class="toc-inline"><summary>On this page</summary>${tocList(toc)}</details>` : ""}
${html}
<nav class="pager" aria-label="Previous and next pages">${prev ? `<a class="prev" href="${href(prev)}"><span>Previous</span>${esc(LABEL[prev]!)}</a>` : "<span></span>"}${next ? `<a class="next" href="${href(next)}"><span>Next</span>${esc(LABEL[next]!)}</a>` : "<span></span>"}</nav></article></main>
<aside class="toc" aria-label="On this page">${hasToc ? `<p class="toc-title">On this page</p>${tocList(toc)}` : ""}</aside></div>
<footer class="site-footer"><p><strong>Sandbox reference implementation.</strong> ${esc(BANNER)}</p><p class="links"><a href="/">Overview</a><a href="/authentication">Authentication</a><a href="/signals">Signals</a><a href="/errors">Errors and results</a><a href="/sandbox">Sandbox</a><a href="/versions">Versions</a><a href="/openapi.yaml">OpenAPI definition</a></p><p class="muted">This portal is generated from the OpenAPI definition and the platform's error catalogue.</p></footer></body></html>\n`;
};
const code = (s: string) => `<pre><code>${esc(s)}</code></pre>`;
type Cell = string | { html: string };
const cell = (c: Cell) => (typeof c === "string" ? esc(c) : c.html);
/** A responsive table: scrolls sideways inside its wrapper on mid-size screens and becomes a stack of labelled cards on phones (each cell carries its column name). */
const tbl = (head: string[], rows: Cell[][]) => `<div class="table-wrap" role="region" aria-label="Table, scrolls sideways if needed" tabindex="0"><table><thead><tr>${head.map((x) => `<th scope="col">${esc(x)}</th>`).join("")}</tr></thead><tbody>${rows.map((r) => `<tr>${r.map((c, i) => `<td data-label="${esc(head[i] ?? "")}">${cell(c)}</td>`).join("")}</tr>`).join("")}</tbody></table></div>`;
const method = (m: string) => ({ html: `<span class="method ${esc(m.toLowerCase())}">${esc(m)}</span>` });
const pill = (r: string) => ({ html: `<span class="pill r-${esc(r.toLowerCase().replace(/_/g, "-"))}">${esc(r)}</span>` });
const callout = (kind: "info" | "warn" | "danger", title: string, body: string) => `<div class="callout ${kind}" role="note"><p class="callout-title">${esc(title)}</p>${body}</div>`;

export function buildPortal(outDir: string, specYaml?: string): string[] {
  mkdirSync(outDir, { recursive: true });
  const spec = (specYaml ? parse(specYaml) : buildOpenApi()) as { paths: Record<string, Record<string, { operationId: string; summary: string; description?: string; requestBody?: { content: Record<string, { schema: { $ref?: string } }> } }>>; components: { schemas: Record<string, { required?: string[]; properties?: Record<string, { enum?: string[]; type?: string; pattern?: string }> }> } };
  const files: Record<string, string> = {};
  const sigOps = Object.entries(spec.paths).filter(([p]) => p.startsWith("/v1/signals/")).map(([p, item]) => ({ path: p, op: item["post"]! }));
  const SIGNAL_NAME: Record<string, string> = { "sim-swap": "SIM swap", "device-swap": "Device swap", "call-forwarding": "Call forwarding", "kyc-match": "KYC match" };
  const cards = sigOps.map(({ path, op }) => `<a class="card" href="/signals#${slug(op.summary)}"><span class="method post">POST</span><p class="card-title">${esc(SIGNAL_NAME[path.split("/")[3] ?? ""] ?? op.summary)}</p><p><code>${esc(path)}</code></p><p>${esc(op.summary)}</p><span class="more">Reference</span></a>`).join("");
  const hero = `<section class="hero"><p class="eyebrow">Sandbox reference implementation</p><h1>Telco Signal API</h1><p class="lead">One API through which banks and other participants request mobile-network signals for fraud prevention from several telcos with different interfaces. This portal documents the sandbox reference implementation.</p><p class="actions"><a class="btn primary" href="/authentication">Get started</a><a class="btn" href="/signals">API reference</a><a class="btn" href="/openapi.yaml">OpenAPI definition</a></p></section>`;
  files["index.html"] = page("index.html", "Telco Signal API", `<h2>Signals at a glance</h2><div class="cards">${cards}</div>
    <h2>How a request works</h2><ol class="steps"><li>Connect with <b>mutual TLS</b> using your registered client certificate (TLS 1.3 preferred, 1.2 minimum).</li><li>Obtain a short-lived <b>access token</b> with <code>private_key_jwt</code>; it is bound to your certificate.</li><li>Register a <b>consent or lawful-basis reference</b> for the subject, purpose and signal.</li><li>Call a signal endpoint with a <b>signed request</b>, the purpose code and the consent reference.</li></ol>
    <h2>Signal safety</h2>${callout("warn", "Unknown is not safe", `<p>Answers are four-state. <b>FALSE</b> is only ever returned when the telco gave an explicit, valid negative. A timeout, an error, an invalid response, an unrouted number or an unsupported signal is returned as <b>UNAVAILABLE</b> or <b>NOT_SUPPORTED</b>, never as "no swap", "no forwarding" or "match". Treat these as unknown, not as safe. They are not charged.</p>`)}
    <h2>Privacy</h2>${callout("info", "Numbers are never stored", `<p>Phone numbers are never logged or stored by the platform (only keyed hashes). Identity attributes sent for KYC match are processed in memory only. Every request needs a purpose code and a consent reference.</p>`)}
    <h2>Where to next</h2><div class="cards two"><a class="card" href="/authentication"><p class="card-title">Authentication</p><p>Mutual TLS, certificate-bound tokens and signed requests, with code.</p><span class="more">Read the guide</span></a><a class="card" href="/sandbox"><p class="card-title">Sandbox</p><p>Synthetic number ranges, mock behaviour by last digit and default limits.</p><span class="more">Try it</span></a><a class="card" href="/errors"><p class="card-title">Errors and results</p><p>What every error code and signal result means and what to do.</p><span class="more">See the catalogue</span></a><a class="card" href="/versions"><p class="card-title">Versions</p><p>Versioning, deprecation and alignment with the CAMARA definitions.</p><span class="more">Read the policy</span></a></div>`, { hero, lead: "One API through which banks and other participants request mobile-network signals for fraud prevention." });
  files["authentication.html"] = page("authentication.html", "Authentication and request signing", `<h2>1. Mutual TLS</h2><p>Every connection must present a client certificate that is registered for your client. Connections without one are refused during the TLS handshake. Weak or non-AEAD cipher suites and TLS 1.1 and below are refused.</p>
    <h2>2. Token (client credentials, private_key_jwt)</h2><p>POST <code>/oauth/token</code> as <code>application/x-www-form-urlencoded</code> with <code>grant_type=client_credentials</code>, your <code>client_id</code>, <code>client_assertion_type=urn:ietf:params:oauth:client-assertion-type:jwt-bearer</code> and a <code>client_assertion</code>: a JWT signed with your registered private key (ES256 or PS256) with <code>iss</code> = <code>sub</code> = your client id, <code>aud</code> = the token endpoint, <code>iat</code>/<code>exp</code> at most 60 seconds apart, and a unique <code>jti</code>. Client secrets are not supported. The platform never holds your private key.</p>
    ${code(`import { SignJWT } from "jose";\nconst assertion = await new SignJWT({})\n  .setProtectedHeader({ alg: "ES256", kid: MY_KID })\n  .setIssuer(CLIENT_ID).setSubject(CLIENT_ID).setAudience(TOKEN_ENDPOINT)\n  .setIssuedAt().setExpirationTime("30s").setJti(crypto.randomUUID())\n  .sign(MY_PRIVATE_KEY);`)}
    <p>The access token lifetime is at most 5 minutes and it carries <code>cnf.x5t#S256</code>, the thumbprint of your certificate: it is rejected on any other connection.</p>
    <h2>3. Signed requests</h2><p>Every state-changing request and every signal request carries <code>X-Request-Signature</code>: a compact JWS (your registered key) over a JSON payload with <code>htm</code> (HTTP method), <code>htu</code> (path), <code>dig</code> (base64url SHA-256 of the exact body bytes), <code>iat</code> (within 60 seconds of the server clock) and <code>jti</code> (16 to 64 URL-safe characters, never reused).</p>
    ${code(`import { CompactSign } from "jose";\nimport { createHash, randomBytes } from "node:crypto";\nconst payload = JSON.stringify({\n  htm: "POST", htu: "/v1/signals/sim-swap/check",\n  dig: createHash("sha256").update(body).digest("base64url"),\n  iat: Math.floor(Date.now() / 1000), jti: randomBytes(18).toString("base64url"),\n});\nconst jws = await new CompactSign(new TextEncoder().encode(payload))\n  .setProtectedHeader({ alg: "ES256", kid: MY_KID }).sign(MY_PRIVATE_KEY);`)}
    <p>An identical signed request cannot be replayed: the second use of a <code>jti</code>, or a timestamp outside the window, is rejected.</p>`, { lead: "Every request is authenticated three ways: a client certificate, a certificate-bound access token and a signed request." });
  const ops: Cell[][] = [];
  for (const [path, item] of Object.entries(spec.paths)) for (const [method0, op] of Object.entries(item)) ops.push([method(method0.toUpperCase()), { html: `<code>${esc(path)}</code>` }, op.operationId, op.summary]);
  const sigRows = Object.entries(spec.paths).filter(([p]) => p.startsWith("/v1/signals/")).map(([p, item]) => {
    const op = item["post"]!; const ref = op.requestBody?.content["application/json"]?.schema.$ref?.split("/").pop() ?? ""; const sch = spec.components.schemas[ref]!;
    return `<h3>${esc(op.summary)}</h3><p>${method("POST").html} <code>${esc(p)}</code></p><p>${esc(op.description ?? "")}</p>${tbl(["Field", "Required", "Rules"], Object.entries(sch.properties ?? {}).map(([k, v]) => [k, (sch.required ?? []).includes(k) ? "yes" : "no", v.enum ? `one of ${v.enum.join(", ")}` : v.pattern ? `pattern ${v.pattern}` : v.type ?? ""]))}<p>Unknown fields are rejected. Maximum body size 4 KB.</p>`;
  });
  files["signals.html"] = page("signals.html", "Signals", `<p>All operations. The machine-readable definition is <a href="/openapi.yaml">openapi.yaml</a>.</p>${tbl(["Method", "Path", "Operation", "Summary"], ops)}${sigRows.join("")}
    <h2>Response</h2>${code(`{ "signal": "SIM_SWAP", "result": "TRUE | FALSE | UNAVAILABLE | NOT_SUPPORTED", "correlationId": "…" }`)}<p>Quote the <code>correlationId</code> when contacting support.</p>`, { lead: "Every operation, the fields each signal accepts and the response shape." });
  files["errors.html"] = page("errors.html", "Errors and results", `<h2>HTTP errors</h2>${tbl(["Code", "HTTP", "Meaning", "What to do"], CATALOGUE.map((e) => [{ html: `<code>${esc(e.code)}</code>` }, String(e.status), e.meaning, e.participantAction]))}
    <h2>Signal results</h2>${tbl(["Result", "Meaning", "What to do"], RESULT_CATALOGUE.map((r) => [pill(r.result), r.meaning, r.action]))}<p>Error responses never reveal internals and never disclose whether a number exists.</p>`, { lead: "What each error code and signal result means, and what to do about it." });
  files["sandbox.html"] = page("sandbox.html", "Sandbox", `<p>The sandbox contains <b>synthetic data only</b>. Use only the reserved synthetic number ranges below; do not send real subscriber numbers.</p>
    ${tbl(["Range", "Served by", "Protocol"], [["+6099900…", "Telco A (mock)", "CAMARA-style"], ["+6099901…", "Telco B (mock)", "Proprietary text protocol"], ["+6099902…", "Telco C (mock, via aggregator)", "Aggregator JSON"]])}
    <h2>Mock behaviour by last digit</h2>${tbl(["Last digit", "Telco A", "Telco B", "Telco C"], [["1", "positive", "positive", "positive"], ["0", "negative", "negative", "negative"], ["2", "no answer (timeout)", "no answer (timeout)", "no answer (timeout)"], ["3", "HTTP 500", "HTTP 500", "HTTP 500"], ["4", "malformed response", "garbage", "wrong request id echoed"], ["5", "unknown subscriber", "unknown subscriber", "wrong carrier echoed"], ["other", "see source", "see source", "see source"]])}
    <p>Every failure row above is answered with <b>UNAVAILABLE</b>, never FALSE.</p>
    <h2>Limits (defaults, configurable per participant)</h2>${tbl(["Limit", "Default"], [["Requests per client certificate", "100 per second"], ["Token endpoint", "10 per second"], ["Per signal per organisation", "600 per minute"], ["Same subject repeated", "20 per hour"], ["Request body", "4 KB"], ["Overall time budget", "2 seconds"]])}`, { lead: "Synthetic data only: reserved number ranges, mock telco behaviour and default limits." });
  files["versions.html"] = page("versions.html", "Versions and deprecation", `<p>The current API version is <b>v1</b>. Breaking changes are introduced as a new major version; a version is marked <b>deprecated</b> with a published sunset date before it is withdrawn. Version status is managed in the admin portal and shown in the dashboards.</p>${tbl(["Version", "Status"], [["v1", "current"]])}
    <h2>CAMARA alignment</h2><p>The telco-facing interfaces follow pinned CAMARA releases (SimSwap r4.3, DeviceSwap r4.3, CallForwardingSignal r4.3, KnowYourCustomer r2.2). The participant-facing API deliberately differs: four-state results, no 404 for unknown numbers, mandatory purpose and consent references, sender-constrained tokens.</p>`, { lead: "How the API is versioned and how it relates to the CAMARA definitions." });
  files["404.html"] = page("404.html", "Page not found", `<p>The page you asked for does not exist. Use the menu, or start from the <a href="/">overview</a>.</p>`, { lead: "That page does not exist." });
  files["favicon.svg"] = `<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 32 32"><rect width="32" height="32" rx="7" fill="#0b5fff"/><path d="M8.5 15.5a10.5 10.5 0 0 1 15 0M12 19a5.5 5.5 0 0 1 8 0" fill="none" stroke="#fff" stroke-width="2.4" stroke-linecap="round"/><circle cx="16" cy="23.5" r="2" fill="#fff"/></svg>\n`;
  files["style.css"] = readFileSync("scripts/portal.css", "utf8");
  files["openapi.yaml"] = specYaml ?? stringify(buildOpenApi(), { lineWidth: 0 });
  for (const [f, c] of Object.entries(files)) writeFileSync(join(outDir, f), c);
  return Object.keys(files);
}
if (process.argv[1]?.endsWith("build-portal.ts")) console.log("built", buildPortal("portal").join(", "));
