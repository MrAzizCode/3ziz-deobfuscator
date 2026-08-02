import type {
  DetectionContext,
  DetectionEvidence,
  DetectionResult,
} from "../../shared/contracts";
import { scoreDetection } from "./scoring";

export const GENERIC_PLUGIN_ID = "generic-static";

export function detectGeneric(context: DetectionContext): DetectionResult {
  const evidence: DetectionEvidence[] = [];
  const { kind } = context.classification;

  if (kind === "lua-source" || kind === "luau-source") {
    evidence.push({
      id: "source-classification",
      description: `classified as ${kind}`,
      weight: 0.62,
      polarity: "positive",
    });
  } else if (kind === "lua-bytecode") {
    evidence.push({
      id: "bytecode-classification",
      description: "Lua binary chunk signature is handled by the generic route",
      weight: 0.7,
      polarity: "positive",
    });
  } else if (kind === "vm-audit-ir") {
    evidence.push({
      id: "family-ir",
      description: "family-specific VM audit evidence lowers generic confidence",
      weight: 0.15,
      polarity: "negative",
    });
  } else {
    evidence.push({
      id: "non-lua-input",
      description: `classification ${kind} is not a supported generic Lua form`,
      weight: 0.25,
      polarity: "negative",
    });
  }

  return scoreDetection(GENERIC_PLUGIN_ID, 0.18, evidence);
}

