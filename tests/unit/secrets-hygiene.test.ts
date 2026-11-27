import { describe, it, expect } from "vitest";
import { readFileSync, readdirSync, statSync } from "node:fs";
import { join } from "node:path";

// A database URL contains a password. Passing it as a command-line argument put it into an error message, then into a test report that a
// workflow uploaded as an artifact on a PUBLIC repository. It travels in the environment only; argv shows "-".
const walk = (d: string): string[] => readdirSync(d).flatMap((n) => { const p = join(d, n); return n === "node_modules" || n === ".sandbox" ? [] : statSync(p).isDirectory() ? walk(p) : [p]; });
describe("connection strings never go on a command line", () => {
  it("every spawn of scripts/db-setup.mjs passes '-' and the URL through the environment", () => {
    const files = [...walk("scripts"), ...walk("tests"), ...walk("src")].filter((f) => /\.(ts|mjs|js)$/.test(f) && !f.endsWith("secrets-hygiene.test.ts"));
    let calls = 0;
    for (const f of files) for (const m of readFileSync(f, "utf8").matchAll(/db-setup\.mjs",\s*([^,\]]+),/g)) { calls++; expect(m[1]!.trim(), `${f}`).toBe('"-"'); }
    expect(calls).toBeGreaterThanOrEqual(2);
    expect(readFileSync("scripts/db-setup.mjs", "utf8")).toContain("TS_DB_SETUP_ADMIN_URL");
  });
  it("the Neon workflow uploads only the redacted summary, never the raw test report", () => {
    const w = readFileSync(".github/workflows/neon-verify.yml", "utf8");
    expect(w).toContain("path: neon-verify.json"); expect(w).not.toMatch(/neon-vitest|neon-probe/);
    expect(readFileSync("scripts/neon-verify.mjs", "utf8")).toContain("/tmp/neon-vitest.json");
  });
});
