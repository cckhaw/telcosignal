import { describe, it, expect } from "vitest";
import { SANDBOX_BANNER } from "../../src/common/banner.js";
describe("banner", () => {
  it("states that live data is not approved", () => {
    expect(SANDBOX_BANNER).toContain("NOT approved for live data");
  });
});
