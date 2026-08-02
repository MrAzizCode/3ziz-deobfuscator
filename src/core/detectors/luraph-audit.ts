import type {
  DetectionContext,
  DetectionEvidence,
  DetectionResult,
} from "../../shared/contracts";
import { countMatches } from "../source/lexical";
import { scoreDetection } from "./scoring";

export const LURAPH_AUDIT_PLUGIN_ID = "luraph-audit";

export function detectLuraphAudit(context: DetectionContext): DetectionResult {
  const source = context.text ?? "";
  const evidence: DetectionEvidence[] = [];

  if (/LURAPH PAYLOAD[\s\S]{0,100}DEVIRTUALIZED REGISTER-LEVEL/i.test(source)) {
    evidence.push({
      id: "luraph-audit-header",
      description: "specific Luraph devirtualized register-reconstruction header",
      weight: 0.4,
      polarity: "positive",
    });
  } else if (/\bLuraph\b/i.test(source)) {
    evidence.push({
      id: "luraph-name-only",
      description: "Luraph name without audit structure is weak evidence",
      weight: 0.06,
      polarity: "positive",
    });
  }

  const labels = countMatches(source, /::L\d+::/g);
  if (labels >= 8) {
    evidence.push({
      id: "recovered-label-density",
      description: "dense recovered VM program-counter labels",
      weight: labels >= 100 ? 0.23 : 0.14,
      polarity: "positive",
      occurrences: labels,
    });
  }

  const gotos = countMatches(source, /\bgoto\s+L\d+\b/g);
  if (gotos >= 4) {
    evidence.push({
      id: "recovered-goto-graph",
      description: "goto references form a recovered VM control-flow graph",
      weight: gotos >= 50 ? 0.12 : 0.07,
      polarity: "positive",
      occurrences: gotos,
    });
  }

  const metadata = countMatches(
    source,
    /stack slots:\s*\d+;\s*decoded instructions:\s*\d+;\s*reachable CFG instructions:\s*\d+/gi,
  );
  if (metadata > 0) {
    evidence.push({
      id: "function-audit-metadata",
      description: "per-function decoded/reachable instruction metadata",
      weight: metadata >= 2 ? 0.16 : 0.1,
      polarity: "positive",
      occurrences: metadata,
    });
  }

  const fragments = countMatches(source, /\bVM_FRAGMENT\b/g);
  if (fragments > 0) {
    evidence.push({
      id: "vm-fragments",
      description: "explicit unresolved VM fragment annotations",
      weight: 0.12,
      polarity: "positive",
      occurrences: fragments,
    });
  }

  if (context.classification.kind === "vm-audit-ir") {
    evidence.push({
      id: "vm-audit-classification",
      description: "generic classifier independently identified VM audit IR",
      weight: 0.13,
      polarity: "positive",
    });
  }

  return scoreDetection(LURAPH_AUDIT_PLUGIN_ID, 0.01, evidence);
}

