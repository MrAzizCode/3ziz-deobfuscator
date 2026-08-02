import type {
  DetectionEvidence,
  DetectionResult,
} from "../../shared/contracts";

export function scoreDetection(
  pluginId: string,
  base: number,
  evidence: readonly DetectionEvidence[],
): DetectionResult {
  const raw = evidence.reduce(
    (score, item) =>
      score + (item.polarity === "positive" ? item.weight : -item.weight),
    base,
  );
  return {
    pluginId,
    confidence: Math.round(Math.min(1, Math.max(0, raw)) * 1_000) / 1_000,
    evidence,
  };
}

