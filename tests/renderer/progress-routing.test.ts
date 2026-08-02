import { describe, expect, it } from "vitest";

import {
  cancellationAllowsCompletedResult,
  shouldAcceptProgressEvent,
  type CancelJobOutcome,
  type ProgressAcceptanceContext,
} from "../../src/renderer/api";

const expectedPath = "C:\\Inputs\\current.lua";

function context(
  overrides: Partial<ProgressAcceptanceContext> = {},
): ProgressAcceptanceContext {
  return {
    accepting: true,
    expectedInputPath: expectedPath,
    activeJobId: undefined,
    retiredJobIds: new Set(["job-a"]),
    ...overrides,
  };
}

describe("renderer progress routing", () => {
  it("does not let a retired run capture the next run's empty job slot", () => {
    expect(shouldAcceptProgressEvent({
      jobId: "job-a",
      inputPath: expectedPath,
      percent: 100,
    }, context())).toBe(false);
  });

  it("requires the expected path before accepting a new job ID", () => {
    expect(shouldAcceptProgressEvent({
      jobId: "job-b",
      inputPath: "C:\\Inputs\\old.lua",
    }, context())).toBe(false);
    expect(shouldAcceptProgressEvent({
      jobId: "job-b",
    }, context())).toBe(false);
    expect(shouldAcceptProgressEvent({
      jobId: "job-b",
      inputPath: "c:/inputs/current.lua",
    }, context())).toBe(true);
  });

  it("accepts only the established job while progress is enabled", () => {
    const active = context({ activeJobId: "job-b" });
    expect(shouldAcceptProgressEvent({
      jobId: "job-b",
      inputPath: expectedPath,
    }, active)).toBe(true);
    expect(shouldAcceptProgressEvent({
      jobId: "job-c",
      inputPath: expectedPath,
    }, active)).toBe(false);
    expect(shouldAcceptProgressEvent({
      jobId: "job-b",
      inputPath: expectedPath,
    }, context({ accepting: false }))).toBe(false);
  });

  it("waits for cancellation and renders only an already-complete result", async () => {
    let resolveOutcome!: (outcome: CancelJobOutcome) => void;
    const pending = new Promise<CancelJobOutcome>((resolvePromise) => {
      resolveOutcome = resolvePromise;
    });
    let settled = false;
    const decision = cancellationAllowsCompletedResult(pending).then((value) => {
      settled = true;
      return value;
    });

    await Promise.resolve();
    expect(settled).toBe(false);
    resolveOutcome({ outcome: "already-complete" });
    await expect(decision).resolves.toBe(true);
    await expect(cancellationAllowsCompletedResult(
      Promise.resolve({ outcome: "cancelled" }),
    )).resolves.toBe(false);
    await expect(cancellationAllowsCompletedResult(
      Promise.reject(new Error("cancel failed")),
    )).resolves.toBe(false);
  });

  it("uses a discriminated cancellation outcome", () => {
    const outcomes: CancelJobOutcome[] = [
      { outcome: "cancelled" },
      { outcome: "already-complete" },
    ];
    expect(outcomes.map((outcome) => outcome.outcome)).toEqual([
      "cancelled",
      "already-complete",
    ]);
  });
});
