import { describe, it, expect } from "vitest";
import { existsSync, readFileSync, readdirSync } from "node:fs";

const read = (f: string) => readFileSync(f, "utf8");
describe("runbooks and privacy documents exist, are complete and are tied to the actual configuration", () => {
  const RUNBOOKS = ["incident-response", "alerts-response", "kill-switch", "breach-notification", "backup-restore", "disaster-recovery", "key-rotation", "retention-deletion", "onboarding-operations"];
  it("every runbook exists, names an owner and says what it covers; no runbook claims a test, certification or compliance it does not have", () => {
    for (const r of RUNBOOKS) { const t = read(`docs/runbooks/${r}.md`); expect(t, r).toMatch(/Owner/); expect(t.length, r).toBeGreaterThan(600); expect(t, r).not.toMatch(/\b(is|are) (certified|compliant)\b/i); expect(read("docs/runbooks/README.md")).toContain(`${r}.md`); }
    expect(readdirSync("docs/runbooks").filter((f) => f !== "README.md" && f !== "sandbox.md").map((f) => f.replace(".md", "")).sort()).toEqual([...RUNBOOKS].sort());
  });
  it("alerts-response has a section for every seeded alert rule (documentation cannot silently fall behind the configuration)", () => {
    const migration = read("migrations/005_observability.sql");
    const ids = [...migration.matchAll(/\('([a-z0-9-]+)','(?:auth_failures|rate_limit_hits|replay_rejections|abuse_flags|unavailable_rate|success_rate_min|timeout_rate|circuit_open|overhead_p95_ms|creds_expiring|consent_denials)'/g)].map((m) => m[1]!);
    expect(ids.length).toBe(8); const doc = read("docs/runbooks/alerts-response.md");
    for (const id of ids) expect(doc, id).toContain(`## ${id}`);
  });
  it("the kill-switch runbook covers every scope; the retention runbook covers every setting the worker uses", () => {
    for (const s of ["participant", "telco", "signal"]) expect(read("docs/runbooks/kill-switch.md")).toContain(`**${s}**`);
    for (const k of ["logs.retention_days", "consent.retention_days"]) expect(read("docs/runbooks/retention-deletion.md")).toContain(k);
  });
  it("breach, residency and backup documents state the open risks honestly", () => {
    expect(read("docs/runbooks/breach-notification.md")).toMatch(/not been verified/); expect(read("docs/runbooks/backup-restore.md")).toMatch(/blocked on D-002/);
    expect(read("docs/privacy/residency-map.md")).toMatch(/R-001/); expect(read("docs/privacy/pia-inputs.md")).toMatch(/NOT a completed PIA/);
    for (const f of ["data-inventory", "residency-map", "pia-inputs"]) expect(existsSync(`docs/privacy/${f}.md`)).toBe(true);
  });
  it("the data inventory lists every table that could hold personal data, and the code agrees that numbers are never columns", () => {
    const inv = read("docs/privacy/data-inventory.md"); for (const t of ["consents", "porting", "request_log", "audit_log", "usage_record", "admin_user", "client_keys"]) expect(inv).toContain(t);
    const mig = readdirSync("migrations").map((f) => read(`migrations/${f}`)).join("\n");
    expect(mig).not.toMatch(/\b(msisdn|phone_number|phonenumber|mobile)\s+(text|varchar)/i);          // no column that could hold a raw number
  });
});
