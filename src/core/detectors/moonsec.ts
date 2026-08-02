import type {
  DetectionContext,
  DetectionEvidence,
  DetectionResult,
} from "../../shared/contracts";
import { countMatches, physicalLineCount, scanLuaLexically } from "../source/lexical";
import { scoreDetection } from "./scoring";

export const MOONSEC_PLUGIN_ID = "moonsec-v3-static";

export function detectMoonSec(context: DetectionContext): DetectionResult {
  const source = context.text ?? "";
  const lexical = scanLuaLexically(source);
  const evidence: DetectionEvidence[] = [];

  const codeMarkers = countMatches(lexical.code, /\bMoonSec(?:\s+V3)?\b/gi);
  const rawMarkers = countMatches(source, /\bMoonSec(?:\s+V3)?\b/gi);
  if (codeMarkers > 0) {
    evidence.push({
      id: "moonsec-code-marker",
      description: "MoonSec marker appears in code rather than trivia",
      weight: 0.48,
      polarity: "positive",
      occurrences: codeMarkers,
    });
  } else if (rawMarkers > 0) {
    evidence.push({
      id: "moonsec-trivia-marker",
      description:
        "MoonSec marker appears only inside a string/comment and is weak on its own",
      weight: 0.2,
      polarity: "positive",
      occurrences: rawMarkers,
    });
  }

  const lineCount = physicalLineCount(source);
  if (source.length >= 50_000 && lineCount <= 3) {
    evidence.push({
      id: "dense-single-line-wrapper",
      description: "large source is compressed into very few physical lines",
      weight: 0.14,
      polarity: "positive",
    });
  }

  const hexConstants = countMatches(lexical.code, /\b0x[0-9a-f]+\b/gi);
  if (hexConstants >= 100) {
    evidence.push({
      id: "hex-constant-density",
      description: "high density of hexadecimal state constants",
      weight: 0.14,
      polarity: "positive",
      occurrences: hexConstants,
    });
  }

  const decimalEscapes = countMatches(source, /\\\d{1,3}/g);
  if (decimalEscapes >= 100) {
    evidence.push({
      id: "encoded-byte-string-density",
      description: "large decimal-escaped byte strings",
      weight: 0.16,
      polarity: "positive",
      occurrences: decimalEscapes,
    });
  }

  const loopCount = countMatches(lexical.code, /\bwhile\b[\s\S]{0,100}\bdo\b/g);
  const moduloCount = countMatches(lexical.code, /%\s*0x[0-9a-f]+/gi);
  if (loopCount >= 8 && moduloCount >= 30) {
    evidence.push({
      id: "opaque-state-machine",
      description: "nested loop/modulo state-machine structure",
      weight: 0.22,
      polarity: "positive",
      occurrences: Math.min(loopCount, moduloCount),
    });
  }

  const environmentRecovery = countMatches(
    lexical.code,
    /\b(?:getfenv|setfenv|_ENV)\b/g,
  );
  if (environmentRecovery > 0) {
    evidence.push({
      id: "environment-recovery",
      description: "environment recovery primitives",
      weight: 0.06,
      polarity: "positive",
      occurrences: environmentRecovery,
    });
  }

  if (context.classification.kind === "vm-audit-ir") {
    evidence.push({
      id: "negative-vm-audit",
      description: "input is already recovered VM audit IR",
      weight: 0.45,
      polarity: "negative",
    });
  }

  return scoreDetection(MOONSEC_PLUGIN_ID, 0.02, evidence);
}

