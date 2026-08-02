import type { DetectionContext, DetectionResult } from "../../shared/contracts";
import { scoreDetection } from "./scoring";

export const JNKIE_LURAPH_PLUGIN_ID = "jnkie-luraph-14-static";

export function detectJnkieLuraph(context: DetectionContext): DetectionResult {
  const source = context.text ?? "";
  const evidence = [];
  const protectedHeader = /protected\s+using\s+Luraph\s+Obfuscator\s+v14\.7/i.test(source);
  if (protectedHeader) {
    evidence.push({
      id: "jnkie.luraph.header",
      description: "Luraph Obfuscator v14.7 wrapper header",
      weight: 0.46,
      polarity: "positive" as const,
      occurrences: 1,
    });
  }
  const pairedStreams = /local\s+V\s*,\s*y\s*=\s*Y\s*\(\s*\[=\[LPH@V[\s\S]*?\]=\]\s*\)\s*,\s*Y\s*\(\s*\[==\[LPH!/m.test(source);
  if (pairedStreams) {
    evidence.push({
      id: "jnkie.luraph.stream-pair",
      description: "Paired LPH@V and LPH! encoded streams",
      weight: 0.36,
      polarity: "positive" as const,
      occurrences: 1,
    });
  }
  const staticDecoder = source.includes('i=a(i,"z","!!!!!"') &&
    source.includes('y("<I4",k)') &&
    source.includes("Luraph decompression error");
  if (staticDecoder) {
    evidence.push({
      id: "jnkie.luraph.decoder",
      description: "Luraph Ascii85 and bounded range-decoder structure",
      weight: 0.18,
      polarity: "positive" as const,
      occurrences: 1,
    });
  }
  if (/^jnkie(?:[_-]payload)?\.(?:lua|luau|txt)$/i.test(context.fileName)) {
    evidence.push({
      id: "jnkie.filename",
      description: "JNKIE payload filename hint",
      weight: 0.04,
      polarity: "positive" as const,
      occurrences: 1,
    });
  }
  return scoreDetection(JNKIE_LURAPH_PLUGIN_ID, 0, evidence);
}
