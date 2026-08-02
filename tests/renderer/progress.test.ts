import { describe, expect, it } from "vitest";

import { canAutoCompletePriorStage } from "../../src/renderer/progress";

describe("renderer progress state", () => {
  it("auto-completes only unfinished prior stages", () => {
    expect(canAutoCompletePriorStage(undefined)).toBe(true);
    expect(canAutoCompletePriorStage("queued")).toBe(true);
    expect(canAutoCompletePriorStage("active")).toBe(true);
    expect(canAutoCompletePriorStage("complete")).toBe(false);
    expect(canAutoCompletePriorStage("warning")).toBe(false);
    expect(canAutoCompletePriorStage("skipped")).toBe(false);
    expect(canAutoCompletePriorStage("error")).toBe(false);
  });
});
