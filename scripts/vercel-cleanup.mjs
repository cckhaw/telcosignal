// Waits for the new production deployment to be READY, then deletes every other deployment
// of the project. Fails closed: if the new deployment is not READY or cannot be identified,
// NOTHING is deleted.
const { VERCEL_TOKEN, VERCEL_PROJECT_ID, VERCEL_TEAM_ID, DEPLOY_URL } = process.env;
if (!VERCEL_TOKEN || !VERCEL_PROJECT_ID || !DEPLOY_URL) throw new Error("missing env");
const base = "https://api.vercel.com";
const q = VERCEL_TEAM_ID ? `teamId=${encodeURIComponent(VERCEL_TEAM_ID)}` : "";
const api = async (method, path, extra = "") => {
  const sep = path.includes("?") ? "&" : "?";
  const r = await fetch(`${base}${path}${sep}${[q, extra].filter(Boolean).join("&")}`, {
    method, headers: { Authorization: `Bearer ${VERCEL_TOKEN}` }, redirect: "error",
    signal: AbortSignal.timeout(30000),
  });
  if (!r.ok) throw new Error(`${method} ${path} -> ${r.status}`);
  return r.json();
};
const host = new URL(DEPLOY_URL.trim()).host;
const latest = await api("GET", `/v13/deployments/${encodeURIComponent(host)}`);
const id = latest.id ?? latest.uid;
if (!id) throw new Error("cannot identify latest deployment");
let state = latest.readyState;
for (let i = 0; i < 60 && state !== "READY"; i++) {
  if (state === "ERROR" || state === "CANCELED") throw new Error(`latest deployment ${state}; nothing deleted`);
  await new Promise((r) => setTimeout(r, 5000));
  state = (await api("GET", `/v13/deployments/${id}`)).readyState;
}
if (state !== "READY") throw new Error("latest deployment never became READY; nothing deleted");
console.log(`latest production deployment ${id} is READY`);

let until, victims = [];
for (;;) {
  const page = await api("GET", `/v6/deployments?projectId=${encodeURIComponent(VERCEL_PROJECT_ID)}&limit=100`, until ? `until=${until}` : "");
  for (const d of page.deployments ?? []) if ((d.uid ?? d.id) !== id) victims.push(d.uid ?? d.id);
  until = page.pagination?.next;
  if (!until) break;
}
for (const v of victims) { await api("DELETE", `/v13/deployments/${v}`); console.log(`deleted ${v}`); }
console.log(`kept ${id}; deleted ${victims.length} older deployment(s)`);
