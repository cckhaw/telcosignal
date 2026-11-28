import { describe, it, expect } from "vitest";
import { readFileSync, readdirSync } from "node:fs";
import { parse } from "yaml";

// Workflow security rules (found by the M6 audit): secrets only on main, only where needed, never during package installation.
const wfs = readdirSync(".github/workflows").filter((f) => f.endsWith(".yml")).map((f) => ({ f, text: readFileSync(`.github/workflows/${f}`, "utf8"), doc: parse(readFileSync(`.github/workflows/${f}`, "utf8")) as { on: unknown; permissions?: unknown; jobs: Record<string, { if?: string; env?: Record<string, string>; steps: Array<{ uses?: string; run?: string; env?: Record<string, string>; name?: string }> }> } }));
describe("GitHub Actions workflows", () => {
  it("no workflow uses pull_request_target, none puts untrusted event data in a shell script, all declare least-privilege permissions", () => {
    for (const w of wfs) {
      expect(w.text, w.f).not.toMatch(/pull_request_target/); expect(w.text, w.f).not.toMatch(/run:[^\n]*\$\{\{\s*(github\.(event|head_ref)|inputs)/);
      expect(w.doc.permissions, w.f).toBeDefined();
    }
  });
  it("every third-party action is pinned to a full commit SHA", () => {
    for (const w of wfs) for (const j of Object.values(w.doc.jobs)) for (const s of j.steps) if (s.uses && !s.uses.startsWith("./")) expect(s.uses, `${w.f}: ${s.uses}`).toMatch(/@[0-9a-f]{40}$/);
  });
  it("a workflow that reads a secret is limited to main, and a secret is never set at job level (it would be visible to every step, including package installation)", () => {
    for (const w of wfs) {
      const usesSecret = /secrets\.(?!GITHUB_TOKEN)/.test(w.text); if (!usesSecret) continue;
      for (const [name, j] of Object.entries(w.doc.jobs)) {
        const touches = /secrets\./.test(JSON.stringify(j));
        if (!touches) continue;
        expect(j.if ?? "", `${w.f}/${name} must be limited to main`).toContain("github.ref == 'refs/heads/main'");
        expect(JSON.stringify(j.env ?? {}), `${w.f}/${name}: no secret at job level`).not.toMatch(/secrets\./);
      }
    }
  });
  it("global npm installs happen before any secret is exposed and without lifecycle scripts", () => {
    const d = wfs.find((w) => w.f === "deploy-production.yml")!;
    const steps = d.doc.jobs["deploy"]!.steps; const install = steps.findIndex((s) => /npm i(nstall)? -g/.test(s.run ?? "")); const firstSecret = steps.findIndex((s) => /secrets\./.test(JSON.stringify(s.env ?? {})));
    expect(install).toBeGreaterThanOrEqual(0); expect(install).toBeLessThan(firstSecret); expect(steps[install]!.run).toContain("--ignore-scripts"); expect(JSON.stringify(steps[install]!.env ?? {})).not.toMatch(/secrets\./);
  });
  it("R-026: every external base image in the Dockerfile is pinned by digest (the tag stays for readability and for Dependabot)", () => {
    const froms = readFileSync("docker/Dockerfile", "utf8").split("\n").filter((l) => /^FROM\s/.test(l));
    const external = froms.filter((l) => !/^FROM\s+(base|build)\b/i.test(l));
    expect(external.length).toBeGreaterThan(0);
    for (const l of external) expect(l, l).toMatch(/^FROM\s+\S+:[\w.-]+@sha256:[0-9a-f]{64}(\s+AS\s+\w+)?$/i);
  });
});
