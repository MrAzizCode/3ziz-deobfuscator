import { describe, expect, it } from "vitest";

import type { DetectionResult } from "../../src/shared/contracts";
import { selectPlugin } from "../../src/core/plugins";

function result(pluginId: string, confidence: number): DetectionResult {
  return { pluginId, confidence, evidence: [] };
}

describe("deterministic plugin selection", () => {
  it("requires a 0.15 family margin", () => {
    const selection = selectPlugin([
      result("moonsec-v3-static", 0.82),
      result("luraph-audit", 0.75),
      result("generic-static", 0.8),
    ]);
    expect(selection.pluginId).toBe("generic-static");
    expect(selection.ambiguous).toBe(true);
  });

  it("selects the highest family detector when threshold and margin pass", () => {
    const selection = selectPlugin([
      result("luraph-audit", 0.91),
      result("moonsec-v3-static", 0.2),
      result("generic-static", 0.8),
    ]);
    expect(selection.pluginId).toBe("luraph-audit");
  });

  it("uses plugin ID as a stable tie breaker", () => {
    const selection = selectPlugin([
      result("moonsec-v3-static", 0.8),
      result("luraph-audit", 0.8),
      result("generic-static", 0.1),
    ]);
    expect(selection.rankedDetections.slice(0, 2).map((item) => item.pluginId)).toEqual([
      "luraph-audit",
      "moonsec-v3-static",
    ]);
  });
});

