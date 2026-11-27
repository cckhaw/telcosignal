// Builds the static developer portal (served by Vercel from ./portal) from the OpenAPI definition and the error catalogue.
// Output is plain HTML + one stylesheet: no script, no inline style, no external resources (matches the CSP in vercel.json).
import { mkdirSync, readFileSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import { parse } from "yaml";
import { CATALOGUE, RESULT_CATALOGUE } from "../src/common/errors.js";
import { esc } from "../src/admin/ui.js";
import { buildOpenApi } from "./gen-openapi.js";
import { stringify } from "yaml";

const NAV: Array<[string, string]> = [["index.html", "Overview"], ["authentication.html", "Authentication"], ["signals.html", "Signals"], ["errors.html", "Errors and results"], ["sandbox.html", "Sandbox"], ["versions.html", "Versions"], ["openapi.yaml", "OpenAPI"]];
const page = (file: string, title: string, body: string) => `<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>${esc(title)} - Telco Signal API developer portal (sandbox)</title><link rel="stylesheet" href="/style.css"></head>
<body><p class="banner">SANDBOX: synthetic data only. NOT approved for live data. No certification or compliance is claimed.</p>
<nav>${NAV.map(([f, l]) => `<a href="/${f === "index.html" ? "" : f.replace(/\.html$/, "")}"${f === file ? ' aria-current="page"' : ""}>${esc(l)}</a>`).join(" ")}</nav><main><h1>${esc(title)}</h1>${body}</main></body></html>\n`;
const code = (s: string) => `<pre><code>${esc(s)}</code></pre>`;
const tbl = (head: string[], rows: string[][]) => `<table><thead><tr>${head.map((x) => `<th>${esc(x)}</th>`).join("")}</tr></thead><tbody>${rows.map((r) => `<tr>${r.map((c) => `<td>${esc(c)}</td>`).join("")}</tr>`).join("")}</tbody></table>`;

export function buildPortal(outDir: string, specYaml?: string): string[] {
  mkdirSync(outDir, { recursive: true });
  const spec = (specYaml ? parse(specYaml) : buildOpenApi()) as { paths: Record<string, Record<string, { operationId: string; summary: string; description?: string; requestBody?: { content: Record<string, { schema: { $ref?: string } }> } }>>; components: { schemas: Record<string, { required?: string[]; properties?: Record<string, { enum?: string[]; type?: string; pattern?: string }> }> } };
  const files: Record<string, string> = {};
  files["index.html"] = page("index.html", "Telco Signal API", `<p>One API through which banks and other participants request mobile-network signals for fraud prevention from several telcos with different interfaces. This portal documents the sandbox reference implementation.</p>
    <h2>How a request works</h2><ol><li>Connect with <b>mutual TLS</b> using your registered client certificate (TLS 1.3 preferred, 1.2 minimum).</li><li>Obtain a short-lived <b>access token</b> with <code>private_key_jwt</code>; it is bound to your certificate.</li><li>Register a <b>consent or lawful-basis reference</b> for the subject, purpose and signal.</li><li>Call a signal endpoint with a <b>signed request</b>, the purpose code and the consent reference.</li></ol>
    <h2>Signal safety</h2><p>Answers are four-state. <b>FALSE</b> is only ever returned when the telco gave an explicit, valid negative. A timeout, an error, an invalid response, an unrouted number or an unsupported signal is returned as <b>UNAVAILABLE</b> or <b>NOT_SUPPORTED</b>, never as "no swap", "no forwarding" or "match". Treat these as unknown, not as safe. They are not charged.</p>
    <h2>Privacy</h2><p>Phone numbers are never logged or stored by the platform (only keyed hashes). Identity attributes sent for KYC match are processed in memory only. Every request needs a purpose code and a consent reference.</p>`);
  files["authentication.html"] = page("authentication.html", "Authentication and request signing", `<h2>1. Mutual TLS</h2><p>Every connection must present a client certificate that is registered for your client. Connections without one are refused during the TLS handshake. Weak or non-AEAD cipher suites and TLS 1.1 and below are refused.</p>
    <h2>2. Token (client credentials, private_key_jwt)</h2><p>POST <code>/oauth/token</code> as <code>application/x-www-form-urlencoded</code> with <code>grant_type=client_credentials</code>, your <code>client_id</code>, <code>client_assertion_type=urn:ietf:params:oauth:client-assertion-type:jwt-bearer</code> and a <code>client_assertion</code>: a JWT signed with your registered private key (ES256 or PS256) with <code>iss</code> = <code>sub</code> = your client id, <code>aud</code> = the token endpoint, <code>iat</code>/<code>exp</code> at most 60 seconds apart, and a unique <code>jti</code>. Client secrets are not supported. The platform never holds your private key.</p>
    ${code(`import { SignJWT } from "jose";\nconst assertion = await new SignJWT({})\n  .setProtectedHeader({ alg: "ES256", kid: MY_KID })\n  .setIssuer(CLIENT_ID).setSubject(CLIENT_ID).setAudience(TOKEN_ENDPOINT)\n  .setIssuedAt().setExpirationTime("30s").setJti(crypto.randomUUID())\n  .sign(MY_PRIVATE_KEY);`)}
    <p>The access token lifetime is at most 5 minutes and it carries <code>cnf.x5t#S256</code>, the thumbprint of your certificate: it is rejected on any other connection.</p>
    <h2>3. Signed requests</h2><p>Every state-changing request and every signal request carries <code>X-Request-Signature</code>: a compact JWS (your registered key) over a JSON payload with <code>htm</code> (HTTP method), <code>htu</code> (path), <code>dig</code> (base64url SHA-256 of the exact body bytes), <code>iat</code> (within 60 seconds of the server clock) and <code>jti</code> (16 to 64 URL-safe characters, never reused).</p>
    ${code(`import { CompactSign } from "jose";\nimport { createHash, randomBytes } from "node:crypto";\nconst payload = JSON.stringify({\n  htm: "POST", htu: "/v1/signals/sim-swap/check",\n  dig: createHash("sha256").update(body).digest("base64url"),\n  iat: Math.floor(Date.now() / 1000), jti: randomBytes(18).toString("base64url"),\n});\nconst jws = await new CompactSign(new TextEncoder().encode(payload))\n  .setProtectedHeader({ alg: "ES256", kid: MY_KID }).sign(MY_PRIVATE_KEY);`)}
    <p>An identical signed request cannot be replayed: the second use of a <code>jti</code>, or a timestamp outside the window, is rejected.</p>`);
  const ops: string[][] = [];
  for (const [path, item] of Object.entries(spec.paths)) for (const [method, op] of Object.entries(item)) ops.push([method.toUpperCase(), path, op.operationId, op.summary]);
  const sigRows = Object.entries(spec.paths).filter(([p]) => p.startsWith("/v1/signals/")).map(([p, item]) => {
    const op = item["post"]!; const ref = op.requestBody?.content["application/json"]?.schema.$ref?.split("/").pop() ?? ""; const sch = spec.components.schemas[ref]!;
    return `<h3>${esc(op.summary)}</h3><p><code>POST ${esc(p)}</code></p><p>${esc(op.description ?? "")}</p>${tbl(["Field", "Required", "Rules"], Object.entries(sch.properties ?? {}).map(([k, v]) => [k, (sch.required ?? []).includes(k) ? "yes" : "no", v.enum ? `one of ${v.enum.join(", ")}` : v.pattern ? `pattern ${v.pattern}` : v.type ?? ""]))}<p>Unknown fields are rejected. Maximum body size 4 KB.</p>`;
  });
  files["signals.html"] = page("signals.html", "Signals", `<p>All operations. The machine-readable definition is <a href="/openapi.yaml">openapi.yaml</a>.</p>${tbl(["Method", "Path", "Operation", "Summary"], ops)}${sigRows.join("")}
    <h2>Response</h2>${code(`{ "signal": "SIM_SWAP", "result": "TRUE | FALSE | UNAVAILABLE | NOT_SUPPORTED", "correlationId": "…" }`)}<p>Quote the <code>correlationId</code> when contacting support.</p>`);
  files["errors.html"] = page("errors.html", "Errors and results", `<h2>HTTP errors</h2>${tbl(["Code", "HTTP", "Meaning", "What to do"], CATALOGUE.map((e) => [e.code, String(e.status), e.meaning, e.participantAction]))}
    <h2>Signal results</h2>${tbl(["Result", "Meaning", "What to do"], RESULT_CATALOGUE.map((r) => [r.result, r.meaning, r.action]))}<p>Error responses never reveal internals and never disclose whether a number exists.</p>`);
  files["sandbox.html"] = page("sandbox.html", "Sandbox", `<p>The sandbox contains <b>synthetic data only</b>. Use only the reserved synthetic number ranges below; do not send real subscriber numbers.</p>
    ${tbl(["Range", "Served by", "Protocol"], [["+6099900…", "Telco A (mock)", "CAMARA-style"], ["+6099901…", "Telco B (mock)", "Proprietary text protocol"], ["+6099902…", "Telco C (mock, via aggregator)", "Aggregator JSON"]])}
    <h2>Mock behaviour by last digit</h2>${tbl(["Last digit", "Telco A", "Telco B", "Telco C"], [["1", "positive", "positive", "positive"], ["0", "negative", "negative", "negative"], ["2", "no answer (timeout)", "no answer (timeout)", "no answer (timeout)"], ["3", "HTTP 500", "HTTP 500", "HTTP 500"], ["4", "malformed response", "garbage", "wrong request id echoed"], ["5", "unknown subscriber", "unknown subscriber", "wrong carrier echoed"], ["other", "see source", "see source", "see source"]])}
    <p>Every failure row above is answered with <b>UNAVAILABLE</b>, never FALSE.</p>
    <h2>Limits (defaults, configurable per participant)</h2>${tbl(["Limit", "Default"], [["Requests per client certificate", "100 per second"], ["Token endpoint", "10 per second"], ["Per signal per organisation", "600 per minute"], ["Same subject repeated", "20 per hour"], ["Request body", "4 KB"], ["Overall time budget", "2 seconds"]])}`);
  files["versions.html"] = page("versions.html", "Versions and deprecation", `<p>The current API version is <b>v1</b>. Breaking changes are introduced as a new major version; a version is marked <b>deprecated</b> with a published sunset date before it is withdrawn. Version status is managed in the admin portal and shown in the dashboards.</p>${tbl(["Version", "Status"], [["v1", "current"]])}
    <h2>CAMARA alignment</h2><p>The telco-facing interfaces follow pinned CAMARA releases (SimSwap r4.3, DeviceSwap r4.3, CallForwardingSignal r4.3, KnowYourCustomer r2.2). The participant-facing API deliberately differs: four-state results, no 404 for unknown numbers, mandatory purpose and consent references, sender-constrained tokens.</p>`);
  files["style.css"] = readFileSync("portal/style.css", "utf8");
  files["openapi.yaml"] = specYaml ?? stringify(buildOpenApi(), { lineWidth: 0 });
  for (const [f, c] of Object.entries(files)) writeFileSync(join(outDir, f), c);
  return Object.keys(files);
}
if (process.argv[1]?.endsWith("build-portal.ts")) console.log("built", buildPortal("portal").join(", "));
