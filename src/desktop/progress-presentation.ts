import type { DesktopProgressEvent } from "./channels";
import type { RendererAnalysisResult } from "./result-adapter";

/*
 * Results are shown as soon as they are ready.  These were once 10,400 ms and
 * 1,200 ms, which held finished work back purely so the progress screen stayed
 * on longer.  Milestones are still replayed in order, but without a floor: a
 * fast analysis should look fast.
 */
export const MINIMUM_ANALYSIS_PRESENTATION_MS = 0;
export const MINIMUM_VERIFIED_STAGE_DWELL_MS = 0;

const MILESTONES = [
  { id: "extracting", percent: 36 },
  { id: "reconstructing", percent: 56 },
  { id: "simplifying", percent: 72 },
  { id: "validating", percent: 88 },
] as const;

export interface PresentationClock {
  now(): number;
  wait(milliseconds: number, signal: AbortSignal): Promise<void>;
}

const systemClock: PresentationClock = {
  now: () => Date.now(),
  wait: (milliseconds, signal) => {
    if (signal.aborted) return Promise.reject(abortError(signal));
    return new Promise<void>((resolvePromise, rejectPromise) => {
      const timer = setTimeout(() => {
        signal.removeEventListener("abort", onAbort);
        resolvePromise();
      }, Math.max(0, milliseconds));
      const onAbort = (): void => {
        clearTimeout(timer);
        signal.removeEventListener("abort", onAbort);
        rejectPromise(abortError(signal));
      };
      signal.addEventListener("abort", onAbort, { once: true });
    });
  },
};

function abortError(signal: AbortSignal): Error {
  return signal.reason instanceof Error
    ? signal.reason
    : new Error(typeof signal.reason === "string" ? signal.reason : "Analysis cancelled.");
}

export interface PresentVerifiedStagesOptions {
  readonly jobId: string;
  readonly inputPath: string;
  readonly startedAt: number;
  readonly stages: RendererAnalysisResult["stages"];
  readonly signal: AbortSignal;
  readonly emit: (event: DesktopProgressEvent) => void;
  readonly minimumMs?: number;
  readonly minimumStageMs?: number;
  readonly clock?: PresentationClock;
}

/**
 * Gives the user time to see verified result milestones. Nothing here claims
 * that work is still running: statuses and past-tense details come directly
 * from the completed, adapted result.
 */
export async function presentVerifiedStages(
  options: PresentVerifiedStagesOptions,
): Promise<void> {
  const clock = options.clock ?? systemClock;
  const minimumMs = options.minimumMs ?? MINIMUM_ANALYSIS_PRESENTATION_MS;
  const minimumStageMs =
    options.minimumStageMs ?? MINIMUM_VERIFIED_STAGE_DWELL_MS;
  if (!Number.isFinite(minimumMs) || minimumMs < 0) {
    throw new Error("Analysis presentation duration must be a non-negative number.");
  }
  if (!Number.isFinite(minimumStageMs) || minimumStageMs < 0) {
    throw new Error("Stage presentation duration must be a non-negative number.");
  }
  if (options.signal.aborted) throw abortError(options.signal);

  const presentationStart = clock.now();
  const deadline = options.startedAt + minimumMs;
  const remaining = Math.max(0, deadline - presentationStart);
  const presentable = MILESTONES.flatMap((milestone) => {
    const stage = options.stages.find(
      (candidate) => candidate.id === milestone.id,
    );
    return stage === undefined ? [] : [{ milestone, stage }];
  });

  if (presentable.length === 0) {
    if (remaining > 0) await clock.wait(remaining, options.signal);
    if (options.signal.aborted) throw abortError(options.signal);
    return;
  }

  const dwell = Math.max(
    minimumStageMs,
    remaining / presentable.length,
  );

  for (const { milestone, stage } of presentable) {
    if (options.signal.aborted) throw abortError(options.signal);
    options.emit({
      jobId: options.jobId,
      inputPath: options.inputPath,
      stage: stage.id,
      status: stage.status,
      percent: milestone.percent,
      message: stage.detail,
    });
    if (dwell > 0) await clock.wait(dwell, options.signal);
  }

  if (options.signal.aborted) throw abortError(options.signal);
}
