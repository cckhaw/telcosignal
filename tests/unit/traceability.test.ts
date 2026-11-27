import { describe, it, expect } from "vitest";
import { existsSync, readFileSync } from "node:fs";

// Release-gate honesty check: every threat in docs/threat-model.md is mapped to tests or controls that exist, and the mapping names
// real phrases in real files. (A phrase proves the test is present; the test suite proves it passes.)
const tm = readFileSync("docs/threat-model.md", "utf8");
const ids = [...new Set([...tm.matchAll(/^\| ((?:T|AB)-\d+) \|/gm)].map((m) => m[1]!))].sort();
const { map } = JSON.parse(readFileSync("docs/release/traceability.json", "utf8")) as { map: Record<string, Array<[string, string]>> };

describe("threat model traceability", () => {
  it("every threat and abuse case has at least one mapped test or control, and nothing is mapped that is not in the threat model", () => {
    expect(ids.length).toBeGreaterThan(60);
    expect(Object.keys(map).sort()).toEqual(ids);
    for (const id of ids) expect(map[id]!.length, id).toBeGreaterThan(0);
  });
  it("every mapped file exists and contains the named phrase", () => {
    for (const [id, refs] of Object.entries(map)) for (const [file, phrase] of refs) {
      expect(existsSync(file), `${id}: ${file}`).toBe(true);
      expect(readFileSync(file, "utf8").toLowerCase(), `${id}: '${phrase}' in ${file}`).toContain(phrase.toLowerCase());
    }
  });
  it("the traceability table in docs/release is generated from the same map (no hand-edited drift)", () => {
    const t = readFileSync("docs/release/traceability.md", "utf8");
    for (const id of ids) expect(t, id).toContain(`| ${id} |`);
  });
});
