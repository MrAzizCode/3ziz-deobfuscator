import type {
  DetectionContext,
  DetectionResult,
} from "../../shared/contracts";
import { detectGeneric } from "./generic";
import { detectLuraphAudit } from "./luraph-audit";
import { detectJnkieLuraph } from "./jnkie-luraph";
import { detectMoonSec } from "./moonsec";

export async function runDetectors(
  context: DetectionContext,
): Promise<readonly DetectionResult[]> {
  const results = [
    detectGeneric(context),
    detectMoonSec(context),
    detectLuraphAudit(context),
    detectJnkieLuraph(context),
  ];
  return results.sort(
    (left, right) =>
      right.confidence - left.confidence ||
      left.pluginId.localeCompare(right.pluginId),
  );
}

export {
  GENERIC_PLUGIN_ID,
  detectGeneric,
} from "./generic";
export {
  MOONSEC_PLUGIN_ID,
  detectMoonSec,
} from "./moonsec";
export {
  LURAPH_AUDIT_PLUGIN_ID,
  detectLuraphAudit,
} from "./luraph-audit";
export {
  JNKIE_LURAPH_PLUGIN_ID,
  detectJnkieLuraph,
} from "./jnkie-luraph";
