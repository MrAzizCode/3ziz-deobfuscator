import type {
  DeobfuscatorPlugin,
  DetectionResult,
  PluginSelection,
} from "../../shared/contracts";
import { GENERIC_PLUGIN_ID } from "../detectors";
import { genericPlugin } from "./generic";
import { luraphAuditPlugin } from "./luraph-audit";
import { jnkieLuraphPlugin } from "./jnkie-luraph";
import { moonSecPlugin } from "./moonsec";

const PLUGINS: readonly DeobfuscatorPlugin[] = [
  genericPlugin,
  luraphAuditPlugin,
  moonSecPlugin,
  jnkieLuraphPlugin,
].sort((left, right) => left.manifest.id.localeCompare(right.manifest.id));

export function listPlugins(): readonly DeobfuscatorPlugin[] {
  return PLUGINS;
}

export function getPlugin(pluginId: string): DeobfuscatorPlugin {
  const plugin = PLUGINS.find((candidate) => candidate.manifest.id === pluginId);
  if (!plugin) throw new Error(`Unknown deobfuscator plugin: ${pluginId}`);
  return plugin;
}

export function selectPlugin(
  detections: readonly DetectionResult[],
): PluginSelection {
  const ranked = [...detections].sort(
    (left, right) =>
      right.confidence - left.confidence ||
      left.pluginId.localeCompare(right.pluginId),
  );
  const familyIds = new Set(
    PLUGINS.filter((plugin) => plugin.manifest.family !== "generic").map(
      (plugin) => plugin.manifest.id,
    ),
  );
  const family = ranked.filter((result) => familyIds.has(result.pluginId));
  const first = family[0];
  const second = family[1];

  if (
    first &&
    first.confidence >= 0.7 &&
    (!second || first.confidence - second.confidence >= 0.15)
  ) {
    return {
      pluginId: first.pluginId,
      reason: `Selected ${first.pluginId} at ${first.confidence.toFixed(3)} confidence with sufficient family margin.`,
      ambiguous: false,
      rankedDetections: ranked,
    };
  }

  const ambiguous =
    first !== undefined &&
    first.confidence >= 0.7 &&
    second !== undefined &&
    first.confidence - second.confidence < 0.15;
  return {
    pluginId: GENERIC_PLUGIN_ID,
    reason: ambiguous
      ? "Family detectors were too close; selected the generic static plugin."
      : "No family detector met the confidence and margin thresholds; selected the generic static plugin.",
    ambiguous,
    rankedDetections: ranked,
  };
}

export { genericPlugin, jnkieLuraphPlugin, luraphAuditPlugin, moonSecPlugin };
