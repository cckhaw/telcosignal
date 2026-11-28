import { describe, it, expect } from "vitest";
import { execFileSync } from "node:child_process";

// The platform is deliberately generic: no operator or brand name may appear in any tracked file (code, docs, generated portal, workflows).
describe("generic naming", () => {
  it("no tracked file contains a payment-network brand name", () => {
    const word = new RegExp("pay" + "net", "i");
    const files = execFileSync("git", ["ls-files", "-z"], { encoding: "utf8" }).split("\0").filter((f) => f && !/\.(png|ico|jpg|woff2?)$/.test(f) && f !== "package-lock.json");
    const hits = files.filter((f) => { try { return word.test(execFileSync("cat", [f], { encoding: "utf8", maxBuffer: 64 * 1024 * 1024 })) || word.test(f); } catch { return false; } });
    expect(hits).toEqual([]);
  });
});
