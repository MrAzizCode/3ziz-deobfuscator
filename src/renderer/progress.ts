import type { AnalysisStage } from "./api";

/** Terminal evidence must survive later milestones. Only unfinished stages may
 * be auto-completed when progress advances beyond them. */
export function canAutoCompletePriorStage(
  status: AnalysisStage["status"],
): boolean {
  return status === undefined || status === "queued" || status === "active";
}
