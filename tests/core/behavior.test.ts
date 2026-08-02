import { describe, expect, it } from "vitest";

import {
  inventoryBehavior,
  inventorySerializedBehaviorEvidence,
} from "../../src/core/behavior/inventory";

describe("static behavior inventory", () => {
  it("ignores API names in comments/strings but inventories URLs", () => {
    const source = `
-- hookfunction(fake)
local note = "loadstring and https://example.test/payload"
local replay = loadstring(code)
hookfunction(target, replay)
game:HttpGet("http://localhost/path")
`;
    const result = inventoryBehavior(source);
    expect(
      result.capabilities.find((finding) => finding.api === "loadstring")
        ?.occurrences,
    ).toBe(1);
    expect(
      result.capabilities.find((finding) => finding.api === "hookfunction")
        ?.occurrences,
    ).toBe(1);
    expect(result.urls.map((finding) => finding.url)).toEqual([
      "https://example.test/payload",
      "http://localhost/path",
    ]);
    expect(result.reachability).toBe("not-evaluated");
    expect(result.evidenceSource).toBe("source-code");
  });

  it("can separately inventory decoded serialized-string evidence", () => {
    const inventory = inventorySerializedBehaviorEvidence(
      "T2\tloadstring\nT2\tRequestAsync\nT2\tidentifyexecutor\n",
    );
    expect(inventory.capabilities.map((finding) => finding.api)).toEqual(
      expect.arrayContaining(["loadstring", "RequestAsync", "identifyexecutor"]),
    );
    expect(inventory.reachability).toBe("not-evaluated");
    expect(inventory.evidenceSource).toBe("serialized-string-inventory");
  });
});
