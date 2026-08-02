import { describe, expect, it } from "vitest";

import {
  MINIMUM_ANALYSIS_PRESENTATION_MS,
  MINIMUM_VERIFIED_STAGE_DWELL_MS,
  presentVerifiedStages,
  type PresentationClock,
} from "../../src/desktop/progress-presentation";
import type { RendererAnalysisResult } from "../../src/desktop/result-adapter";

const stages: RendererAnalysisResult["stages"] = [
  { id: "ingesting", label: "Import", status: "complete", detail: "Imported." },
  { id: "fingerprinting", label: "Fingerprint", status: "complete", detail: "Detected." },
  { id: "extracting", label: "Extract", status: "complete", detail: "Streams were extracted." },
  { id: "reconstructing", label: "Reconstruct", status: "complete", detail: "Profile was loaded." },
  { id: "simplifying", label: "Simplify", status: "warning", detail: "Fragments remain." },
  { id: "validating", label: "Validate", status: "complete", detail: "Gates passed." },
  { id: "emitting", label: "Emit", status: "complete", detail: "Bundle was written." },
];

function virtualClock(start: number): PresentationClock & { value: number } {
  return {
    value: start,
    now() { return this.value; },
    async wait(milliseconds, signal) {
      if (signal.aborted) throw signal.reason;
      this.value += milliseconds;
    },
  };
}

describe("verified analysis presentation", () => {
  it("shows a fast result immediately and replays exact completed evidence", async () => {
    const clock = virtualClock(1_000);
    const emitted: Array<{ stage?: string; status?: string; message?: string; percent?: number }> = [];
    await presentVerifiedStages({
      jobId: "job",
      inputPath: "jnkie.lua",
      startedAt: 0,
      stages,
      signal: new AbortController().signal,
      emit: (event) => emitted.push(event),
      clock,
    });

    // No artificial floor: finished work is not held back to fill a screen.
    expect(MINIMUM_ANALYSIS_PRESENTATION_MS).toBe(0);
    expect(clock.value).toBe(1_000);
    expect(emitted.map((event) => event.stage)).toEqual([
      "extracting",
      "reconstructing",
      "simplifying",
      "validating",
    ]);
    expect(emitted.map((event) => event.percent)).toEqual([36, 56, 72, 88]);
    expect(emitted[2]).toMatchObject({ status: "warning", message: "Fragments remain." });
  });

  it("replays every verified stage without adding wall-clock time", async () => {
    const clock = virtualClock(7_000);
    const emittedAt: number[] = [];
    await presentVerifiedStages({
      jobId: "job",
      inputPath: "slow.lua",
      startedAt: 0,
      stages,
      signal: new AbortController().signal,
      emit: () => emittedAt.push(clock.value),
      clock,
    });
    expect(MINIMUM_VERIFIED_STAGE_DWELL_MS).toBe(0);
    expect(emittedAt).toEqual([7_000, 7_000, 7_000, 7_000]);
    expect(clock.value).toBe(7_000);
  });

  it("still honours an explicit dwell when a caller asks for one", async () => {
    // The pacing mechanism is intact; only its default floor was removed.
    const clock = virtualClock(0);
    const emittedAt: number[] = [];
    await presentVerifiedStages({
      jobId: "job",
      inputPath: "paced.lua",
      startedAt: 0,
      stages,
      signal: new AbortController().signal,
      emit: () => emittedAt.push(clock.value),
      minimumMs: 0,
      minimumStageMs: 50,
      clock,
    });
    expect(emittedAt).toEqual([0, 50, 100, 150]);
  });

  it("stops before another milestone when presentation is cancelled", async () => {
    const controller = new AbortController();
    const emitted: string[] = [];
    const clock: PresentationClock = {
      now: () => 1_000,
      async wait() {
        controller.abort(new Error("cancelled"));
        throw controller.signal.reason;
      },
    };
    await expect(presentVerifiedStages({
      jobId: "job",
      inputPath: "jnkie.lua",
      startedAt: 0,
      stages,
      signal: controller.signal,
      emit: (event) => emitted.push(event.stage ?? ""),
      // A dwell has to be in effect for cancellation to have a window at all.
      minimumStageMs: 50,
      clock,
    })).rejects.toThrow("cancelled");
    expect(emitted).toEqual(["extracting"]);
  });

  it("emits nothing when already cancelled", async () => {
    const controller = new AbortController();
    controller.abort(new Error("cancelled before presentation"));
    const emitted: string[] = [];
    await expect(presentVerifiedStages({
      jobId: "job",
      inputPath: "jnkie.lua",
      startedAt: 0,
      stages,
      signal: controller.signal,
      emit: (event) => emitted.push(event.stage ?? ""),
      clock: virtualClock(1_000),
    })).rejects.toThrow("cancelled before presentation");
    expect(emitted).toEqual([]);
  });
});
