import { describe, it, expect } from "vitest";
import { existsSync, readFileSync, readdirSync } from "node:fs";
import { resolve } from "node:path";

const read = (f: string) => readFileSync(f, "utf8");
describe("release-gate package is complete and honest", () => {
  it("the not-approved statement is unmissable and no document claims certification or compliance", () => {
    const g = read("docs/release/human-gates.md");
    expect(g).toMatch(/NOT APPROVED FOR LIVE DATA/); expect(g).toMatch(/not a certification|NOT approved to process live/i);
    for (const f of ["README.md", "docs/release/README.md", "docs/release/residual-risks.md", "docs/release/load-results.md"]) expect(read(f), f).not.toMatch(/\b(is|are|we are|platform is) (certified|compliant|approved for live)\b/i);
    expect(read("README.md")).toMatch(/NOT APPROVED FOR LIVE DATA/);
    for (const gate of ["G1", "G2", "G3", "G4", "G5", "G8", "G10"]) expect(g).toContain(`| ${gate} |`);
  });
  it("every deliverable named in the release index exists", () => {
    const idx = read("docs/release/README.md");
    for (const m of idx.matchAll(/\]\(([^)#]+)\)/g)) { const t = m[1]!; if (/^https?:/.test(t)) continue; expect(existsSync(resolve("docs/release", t)), t).toBe(true); }
  });
  it("the residual-risk register has every risk the threat model mentions, each with a proposed owner and a status", () => {
    const reg = read("docs/release/residual-risks.md");
    const rows = [...reg.matchAll(/^\| (R-\d+) \| .* \| ([HML]) \| ([^|]+) \| ([^|]+) \|$/gm)];
    const ids = rows.map((r) => r[1]!);
    expect(ids).toEqual(Array.from({ length: ids.length }, (_, i) => `R-${String(i + 1).padStart(3, "0")}`));
    const mentioned = new Set([...read("docs/threat-model.md").matchAll(/\bR-\d{3}\b/g)].map((m) => m[0]));
    for (const id of mentioned) if (id !== "R-0xx") expect(ids, id).toContain(id);
    for (const r of rows) { expect(r[3]!.trim().length, r[1]).toBeGreaterThan(2); expect(r[4]!.trim().length, r[1]).toBeGreaterThan(2); }
  });
  it("the committed load results meet the stated targets and the document quotes the same numbers", () => {
    const files = readdirSync("docs/release/load").filter((f) => f.endsWith(".json"));
    expect(files.length).toBeGreaterThanOrEqual(2);
    const doc = read("docs/release/load-results.md");
    for (const f of files) {
      const r = JSON.parse(read(`docs/release/load/${f}`)) as { offered_rps: number; achieved_rps: number; synthetic: boolean; completed: number; sent: number; status: Record<string, number>; server_overhead_ms: { p95: number }; result: Record<string, number> };
      expect(r.synthetic).toBe(true); expect(r.offered_rps).toBeGreaterThanOrEqual(200); expect(r.achieved_rps).toBeGreaterThanOrEqual(190);
      expect(r.completed).toBe(r.sent); expect(Object.keys(r.status)).toEqual(["200"]);
      expect(r.server_overhead_ms.p95, f).toBeLessThan(100);
      expect(doc, f).toContain(String(Math.round(r.server_overhead_ms.p95)));
    }
  });
  it("the SBOM is CycloneDX and lists every direct dependency at its pinned version (npm sbom --omit dev silently dropped one, so the SBOM includes dev dependencies as a superset)", () => {
    const sbom = JSON.parse(read("docs/release/sbom.cdx.json")) as { bomFormat: string; components: Array<{ name: string; version: string }> };
    expect(sbom.bomFormat).toBe("CycloneDX");
    const pkg = JSON.parse(read("package.json")) as { dependencies: Record<string, string>; devDependencies: Record<string, string> };
    const names = new Set(sbom.components.map((c) => c.name));
    for (const [n, v] of Object.entries(pkg.dependencies)) { expect(names.has(n), n).toBe(true); expect(sbom.components.find((c) => c.name === n)!.version).toBe(v); }
    for (const [n, v] of Object.entries(pkg.devDependencies)) { expect(names.has(n), n).toBe(true); expect(sbom.components.find((c) => c.name === n)!.version).toBe(v); }
  });
});
