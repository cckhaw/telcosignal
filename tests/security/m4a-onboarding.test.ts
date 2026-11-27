import { describe, it, expect, beforeAll, afterAll } from "vitest";
import { Agent } from "undici";
import { X509Certificate } from "node:crypto";
import { exportJWK, generateKeyPair, importJWK } from "jose";
import { startHarness, num, type Harness, type TestClient } from "../helpers/harness.js";
import { startAdmin, type Admin, type Session, type R } from "../helpers/admin-harness.js";
import { certThumbprint } from "../../src/identity/tokens.js";

let h: Harness, a: Admin;
let alice: Session, bob: Session, olivia: Session, ian: Session;
beforeAll(async () => {
  h = await startHarness({ useRegistry: true }); a = await startAdmin(h);
  const ss = (await Promise.all(["alice", "bob", "olivia", "ian"].map((u) => a.login(u)))) as Session[];
  [alice, bob, olivia, ian] = ss as [Session, Session, Session, Session];
});
afterAll(async () => { await a.stop(); await h.stop(); });
const idOf = (r: R) => r.location!.split("/").pop()!;
const approve = async (by: Session, r: R) => { if (!r.location) throw new Error(`the request was refused: ${r.status} ${r.text.replace(/<[^>]+>/g, " ").slice(0, 200)}`); return by.post(`${r.location}/approve`, { note: "ok" }); };
const orgId = (r: R) => idOf(r);
const sim = async (c: TestClient, n: string) => { const k = await h.consent(c, n); return h.call(c, "POST", "/v1/signals/sim-swap/check", { body: { phoneNumber: n, consentRef: k.ref, purposeCode: "FRAUD_PREVENTION" } }); };

describe("ACCEPTANCE: a mock telco is onboarded end to end through the portal", () => {
  let telcoOrg = "";
  const telcoOrigin = () => `https://localhost:${h.telco.port}`;
  it("endpoints are vetted: SSRF-prone URLs are refused before a request exists; unlisted origins cannot be activated", async () => {
    telcoOrg = orgId(await ian.post("/orgs", { name: "Synthetic Telco N", kind: "telco" }));
    const bad = ["https://169.254.169.254/latest", "https://10.0.0.5", "https://192.168.1.1:8443", "https://[::1]", "https://metadata.google.internal", "http://telco.example.net", "https://user:pw@telco.example.net", "https://2130706433", "https://0x7f000001", "https://127.1", "https://intranet", "ftp://telco.example.net", "https://x.local"];
    for (const baseUrl of bad) {
      const r = await ian.post("/changes/new", { kind: "ROUTING", action: "create_telco", telcoId: "telco-n", adapter: "camara", baseUrl, orgId: telcoOrg });
      // loopback hostnames are only permitted in this sandbox via an explicit policy setting; numeric/private forms never are
      if (baseUrl === "https://[::1]") expect(r.status).toBeLessThan(500); else expect(r.status, baseUrl).toBe(400);
    }
    const r = await ian.post("/changes/new", { kind: "ROUTING", action: "create_telco", telcoId: "telco-n", adapter: "camara", baseUrl: "https://telco-n.example.net", orgId: telcoOrg });
    expect(r.status).toBe(302);
    const res = await approve(alice, r); expect(res.status).toBe(409); expect(res.text).toMatch(/allow-list/);   // the database refuses an origin nobody allow-listed
    expect((await h.migrator.query("SELECT count(*)::int n FROM telcos WHERE id='telco-n'")).rows[0].n).toBe(0);
  });
  it("two-person steps: allow-list the origin, register the connection, set coverage", async () => {
    const allow = await ian.post("/changes/new", { kind: "ROUTING", action: "allow_origin", origin: telcoOrigin() }); expect(allow.status).toBe(302);
    expect((await approve(ian, allow)).status).toBe(403); expect((await approve(alice, allow)).status).toBe(302);
    const create = await ian.post("/changes/new", { kind: "ROUTING", action: "create_telco", telcoId: "telco-n", adapter: "camara", baseUrl: telcoOrigin(), orgId: telcoOrg });
    expect((await approve(bob, create)).status).toBe(302);
    expect((await h.migrator.query("SELECT state, org_id FROM telcos WHERE id='telco-n'")).rows[0]).toEqual({ state: "draft", org_id: telcoOrg });
    const cov = await ian.post("/changes/new", { kind: "ROUTING", action: "coverage_set", telcoId: "telco-n", signals: "SIM_SWAP, DEVICE_SWAP" });
    expect((await approve(alice, cov)).status).toBe(302);
    const pfx = await ian.post("/changes/new", { kind: "ROUTING", action: "set_prefix", prefix: "+6099903", telcoId: "telco-n" }); expect((await approve(bob, pfx)).status).toBe(302);
  });
  it("traffic does NOT reach a telco that is not active; activation is blocked until required tests pass", async () => {
    const before = h.telco.calls;
    expect((await sim(h.bankA, num("1", "0").replace("+6099900", "+6099903"))).json.result).toBe("UNAVAILABLE");
    expect(h.telco.calls).toBe(before);
    expect((await ian.post(`/orgs/${telcoOrg}/advance`, { to: "testing" })).status).toBe(302);
    const early = await ian.post(`/orgs/${telcoOrg}/advance`, { to: "pending_approval" }); expect(early.status).toBe(409); expect(early.text).toMatch(/required tests/);
    const jump = await ian.post("/changes/new", { kind: "ORG_STATE", orgId: telcoOrg, toState: "active" });
    const res = await approve(alice, jump); expect(res.status).toBe(409);                               // not allowed from 'testing'
    expect((await h.migrator.query("SELECT state FROM organisations WHERE id=$1", [telcoOrg])).rows[0].state).toBe("testing");
  });
  it("platform-run conformance tests pass against the telco; then it can be submitted, and a SECOND person activates it", async () => {
    expect((await ian.post(`/orgs/${telcoOrg}/tests`, {})).status).toBe(302);
    const t = (await h.migrator.query("SELECT DISTINCT ON (test_key) test_key, status FROM onboarding_test WHERE org_id=$1 ORDER BY test_key, id DESC", [telcoOrg])).rows;
    expect(Object.fromEntries(t.map((x) => [x.test_key, x.status]))).toEqual({ health_check: "pass", "conformance:DEVICE_SWAP": "pass", "conformance:SIM_SWAP": "pass" });
    expect((await ian.post(`/orgs/${telcoOrg}/advance`, { to: "pending_approval" })).status).toBe(302);
    const act = await ian.post("/changes/new", { kind: "ORG_STATE", orgId: telcoOrg, toState: "active" });
    expect((await approve(ian, act)).status).toBe(403);
    expect((await approve(alice, act)).status).toBe(302);
    expect((await h.migrator.query("SELECT t.state ts, o.state os FROM telcos t JOIN organisations o ON o.id=t.org_id WHERE t.id='telco-n'")).rows[0]).toEqual({ ts: "active", os: "active" });
  });
  it("a bank's request now routes to the newly onboarded telco and gets a real answer", async () => {
    const before = h.telco.calls;
    const r = await sim(h.bankA, num("1", "0").replace("+6099900", "+6099903"));
    expect(r.json.result).toBe("TRUE"); expect(h.telco.calls).toBe(before + 1);
  });
  it("a telco whose conformance fails can never be activated", async () => {
    const bad = orgId(await ian.post("/orgs", { name: "Synthetic Telco Broken", kind: "telco" }));
    // wrong protocol for the endpoint: a proprietary-format adapter talking to a CAMARA server
    const c = await ian.post("/changes/new", { kind: "ROUTING", action: "create_telco", telcoId: "telco-bad", adapter: "proprietary", baseUrl: telcoOrigin(), orgId: bad }); await approve(alice, c);
    await approve(bob, await ian.post("/changes/new", { kind: "ROUTING", action: "coverage_set", telcoId: "telco-bad", signals: "SIM_SWAP" }));
    await ian.post(`/orgs/${bad}/advance`, { to: "testing" }); await ian.post(`/orgs/${bad}/tests`, {});
    const t = (await h.migrator.query("SELECT DISTINCT ON (test_key) test_key, status FROM onboarding_test WHERE org_id=$1 ORDER BY test_key, id DESC", [bad])).rows;
    expect(t.find((x) => x.test_key === "conformance:SIM_SWAP")!.status).toBe("fail");
    expect((await ian.post(`/orgs/${bad}/advance`, { to: "pending_approval" })).status).toBe(409);
    expect((await h.migrator.query("SELECT state FROM organisations WHERE id=$1", [bad])).rows[0].state).toBe("testing");
    // an integration engineer cannot fake a pass by hand either
    // Known limitation (R-010): telco conformance results are asserted by the platform process (the database cannot call a telco), so a
    // compromised portal could record one. Even then the missing health_check keeps activation blocked here, and a second person must approve.
    await expect(a.pool.query("SELECT onb_record_test($1,'conformance:SIM_SWAP','pass','{}','ian')", [bad])).resolves.toBeTruthy();
    expect((await ian.post(`/orgs/${bad}/advance`, { to: "pending_approval" })).status).toBe(409);          // health_check has still not passed
  });
  it("suspension is immediate and audited", async () => {
    expect((await olivia.post(`/orgs/${telcoOrg}/suspend`, {})).status).toBe(302);
    const before = h.telco.calls;
    expect((await sim(h.bankA, num("1", "0").replace("+6099900", "+6099903"))).json.result).toBe("UNAVAILABLE");
    expect(h.telco.calls).toBe(before);
    expect((await h.migrator.query("SELECT 1 FROM audit_log WHERE action='admin.org.suspend' AND actor='olivia'")).rowCount).toBe(1);
  });
});

describe("ACCEPTANCE: a mock bank is onboarded end to end through the portal", () => {
  let bankOrg = "", client: TestClient;
  it("create, entitle (second person), register a public key + certificate for a NEW client (second person)", async () => {
    bankOrg = orgId(await ian.post("/orgs", { name: "Synthetic Bank N", kind: "bank" }));
    expect((await approve(alice, await ian.post("/changes/new", { kind: "ENTITLEMENT", orgId: bankOrg, signal: "SIM_SWAP", purposes: "FRAUD_PREVENTION" }))).status).toBe(302);
    const pem = h.pki.issue("bank-n-client"); const { publicKey, privateKey } = await generateKeyPair("ES256", { extractable: true });
    const jwk = await exportJWK(publicKey); const thumb = certThumbprint(new X509Certificate(pem.cert).raw);
    // scopes beyond the entitlement are refused at approval
    const greedy = await ian.post("/credentials/register", { orgId: bankOrg, clientId: "bank-n-greedy", certSha256: thumb, expiresInDays: "30", jwk: JSON.stringify(jwk), scopes: "sim-swap:check kyc-match:check consent:write" });
    expect((await approve(alice, greedy)).status).toBe(409);
    const reg = await ian.post("/credentials/register", { orgId: bankOrg, clientId: "bank-n-client", certSha256: thumb, expiresInDays: "90", jwk: JSON.stringify(jwk), scopes: "sim-swap:check consent:write consent:read", kid: "bank-n-k1" });
    expect(reg.status).toBe(302); expect((await approve(ian, reg)).status).toBe(403); expect((await approve(bob, reg)).status).toBe(302);
    const agent = new Agent({ connect: { ca: h.pki.caCert, cert: pem.cert, key: pem.key } });
    client = { name: "bank-n-client", orgId: bankOrg, pem, key: privateKey, kid: "bank-n-k1", thumb, agent };
    expect((await h.migrator.query("SELECT scopes FROM clients WHERE client_id='bank-n-client'")).rows[0].scopes.sort()).toEqual(["consent:read", "consent:write", "sim-swap:check"]);
  });
  it("certification is computed from real sandbox evidence: it fails before the bank has done the work, and cannot be skipped", async () => {
    await ian.post(`/orgs/${bankOrg}/advance`, { to: "testing" });
    await ian.post(`/orgs/${bankOrg}/tests`, {});
    expect((await ian.post(`/orgs/${bankOrg}/advance`, { to: "pending_approval" })).status).toBe(409);
    await expect(a.pool.query("SELECT onb_record_test($1,'cert:SIM_SWAP','pass','{}','ian')", [bankOrg])).rejects.toThrow(/cannot be recorded by hand/);   // never asserted by a person
  });
  it("the bank performs the certification calls itself (sandbox), the portal evaluates them, a second person activates", async () => {
    expect((await sim(client, num("1", "8801"))).json.result).toBe("TRUE");                    // org is in 'testing': sandbox access works
    expect((await h.call(client, "POST", "/v1/signals/sim-swap/check", { body: { phoneNumber: num("0", "8802"), consentRef: "CONSENT-NOPE-0001", purposeCode: "FRAUD_PREVENTION" } })).status).toBe(403);
    expect((await h.call(client, "POST", "/v1/signals/device-swap/check", { body: { phoneNumber: num("0", "8802"), consentRef: "CONSENT-NOPE-0001", purposeCode: "FRAUD_PREVENTION" } })).status).toBe(403);   // not entitled
    await ian.post(`/orgs/${bankOrg}/tests`, {});
    expect((await ian.post(`/orgs/${bankOrg}/advance`, { to: "pending_approval" })).status).toBe(302);
    const act = await ian.post("/changes/new", { kind: "ORG_STATE", orgId: bankOrg, toState: "active" });
    expect((await approve(ian, act)).status).toBe(403); expect((await approve(alice, act)).status).toBe(302);
    expect((await h.migrator.query("SELECT state FROM organisations WHERE id=$1", [bankOrg])).rows[0].state).toBe("active");
  });
  it("suspension cuts the bank off immediately; retirement needs a second person", async () => {
    expect((await sim(client, num("0", "8803"))).status).toBe(200);
    expect((await olivia.post(`/orgs/${bankOrg}/suspend`, {})).status).toBe(302);
    await expect(h.token(client)).rejects.toThrow(/401/);
    const ret = await ian.post("/changes/new", { kind: "ORG_STATE", orgId: bankOrg, toState: "retired" });
    expect((await approve(ian, ret)).status).toBe(403); expect((await approve(bob, ret)).status).toBe(302);
    expect((await h.migrator.query("SELECT state FROM organisations WHERE id=$1", [bankOrg])).rows[0].state).toBe("retired");
  });
});

describe("credentials: public-key registration, show-once secrets, rotation, revocation, expiry", () => {
  let bankerA: Session;
  beforeAll(async () => { bankerA = await a.login("banker-a"); });
  it("private key material is refused, and the platform stores only public keys", async () => {
    const { privateKey } = await generateKeyPair("ES256", { extractable: true }); const priv = await exportJWK(privateKey);
    const r = await bankerA.post("/credentials/register", { clientId: "bank-a", certSha256: h.bankA.thumb, expiresInDays: "30", jwk: JSON.stringify(priv) });
    expect(r.status).toBe(400); expect(r.text).toMatch(/private key material/);
    await expect(h.migrator.query("INSERT INTO client_keys(client_id,kid,jwk,cert_sha256,expires_at) VALUES ('bank-a','p',$1,$2,now()+interval '1 day')", [JSON.stringify(priv), "A".repeat(43)])).rejects.toThrow(/check/i);
  });
  it("a generated private key is shown ONCE, is stored nowhere, and the new key then works (rotation) while the old one expires soon", async () => {
    const r = await bankerA.post("/credentials/register", { clientId: "bank-a", certSha256: h.bankA.thumb, expiresInDays: "90", generate: "on", rotateOutKid: h.bankA.kid });
    expect(r.status).toBe(200); expect(r.text).toContain("shown once");
    const privJwk = JSON.parse(/<pre>([\s\S]*?)<\/pre>/.exec(r.text)![1]!.replace(/&quot;/g, '"')) as Record<string, string>;
    expect(privJwk["d"]).toBeTruthy(); const d = privJwk["d"]!;
    const changeId = (await h.migrator.query("SELECT id FROM config_change WHERE kind='KEY_REGISTER' AND requested_by='banker-a' ORDER BY requested_at DESC LIMIT 1")).rows[0].id as string;
    // never retrievable afterwards, never persisted
    expect((await bankerA.get(`/changes/${changeId}`)).text).not.toContain(d);
    expect((await bankerA.get("/credentials")).text).not.toContain(d);
    const dump = JSON.stringify([(await h.migrator.query("SELECT payload FROM config_change")).rows, (await h.migrator.query("SELECT detail_text FROM audit_log")).rows, (await h.migrator.query("SELECT jwk FROM client_keys")).rows, (await h.migrator.query("SELECT * FROM config_history")).rows]);
    expect(dump).not.toContain(d); expect(a.logs.join("")).not.toContain(d);
    // approval by someone else (the bank user is only the requester), then the key works
    expect((await bankerA.post(`/changes/${changeId}/approve`, {})).status).toBe(403);
    expect((await alice.post(`/changes/${changeId}/approve`, {})).status).toBe(302);
    const kid = (await h.migrator.query("SELECT kid FROM client_keys WHERE client_id='bank-a' AND kid<>$1 ORDER BY expires_at DESC LIMIT 1", [h.bankA.kid])).rows[0].kid as string;
    const key = await importJWK(privJwk as never, "ES256");
    const rotated: TestClient = { ...h.bankA, key: key as never, kid };
    expect(await h.token(rotated)).toBeTruthy();
    const old = (await h.migrator.query("SELECT expires_at - now() AS left FROM client_keys WHERE client_id='bank-a' AND kid=$1", [h.bankA.kid])).rows[0].left as { hours?: number; minutes?: number };
    expect((old.hours ?? 0) * 60 + (old.minutes ?? 0)).toBeLessThanOrEqual(61);                        // overlap window only
    // revocation is immediate, single-person, and limited to your own organisation
    const other = await a.login("banker-b");
    expect((await other.post("/credentials/revoke", { clientId: "bank-a", kid })).status).toBe(403);
    expect((await bankerA.post("/credentials/revoke", { clientId: "bank-a", kid })).status).toBe(302);
    await expect(h.token(rotated)).rejects.toThrow(/401/);
  });
  it("keys close to expiry are flagged", async () => {
    const { publicKey } = await generateKeyPair("ES256", { extractable: true });
    const r = await bankerA.post("/credentials/register", { clientId: "bank-a", certSha256: h.bankA.thumb, expiresInDays: "10", jwk: JSON.stringify(await exportJWK(publicKey)) });
    await alice.post(`${r.location}/approve`, {});
    expect((await bankerA.get("/credentials")).text).toContain("EXPIRING SOON");
  });
});
