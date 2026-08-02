import type {
  AnalysisContext,
  DeobfuscatorPlugin,
  DetectionContext,
  PluginManifest,
  StagePlan,
  ValidationContext,
  ValidationReport,
} from "../../shared/contracts";
import { inventoryBehavior } from "../behavior/inventory";
import { detectMoonSec, MOONSEC_PLUGIN_ID } from "../detectors";
import { parseLuaFacts } from "../source/parse-facts";

export const MOONSEC_MANIFEST: PluginManifest = {
  id: MOONSEC_PLUGIN_ID,
  name: "MoonSec V3 static route",
  version: "0.1.0",
  family: "moonsec-v3",
  description:
    "Explainable MoonSec detection and exact preservation; reviewed extractor not bundled.",
  supportedKinds: ["lua-source", "luau-source", "text"],
  authoritative: true,
};

async function planMoonSec(_context: AnalysisContext): Promise<StagePlan> {
  return {
    pluginId: MOONSEC_PLUGIN_ID,
    stages: [
      {
        id: "moonsec-static-confirmation",
        description: "Record wrapper markers and structural-density evidence",
        authoritative: true,
      },
      {
        id: "moonsec-extractor",
        description: "Reviewed static extractor sidecar (not installed)",
        authoritative: false,
      },
    ],
  };
}

export const moonSecPlugin: DeobfuscatorPlugin = {
  manifest: MOONSEC_MANIFEST,
  async detect(context: DetectionContext) {
    return detectMoonSec(context);
  },
  plan: planMoonSec,
  async analyze(context: AnalysisContext) {
    const text = context.text ?? "";
    return {
      status: "partial",
      diagnostics: [
        {
          code: "MOONSEC_EXTRACTOR_NOT_INSTALLED",
          severity: "warning",
          stage: "moonsec-analysis",
          message:
            "MoonSec V3 evidence is strong, but no reviewed static extractor is bundled. The protected wrapper is preserved exactly and never executed.",
          suggestedAction:
            "Install a provenance-reviewed extractor sidecar in a future release or audit the exact artifact manually.",
        },
      ],
      sourceFacts: parseLuaFacts(
        text,
        context.classification,
        context.limits.maxAstNodes,
      ),
      behavior: inventoryBehavior(text),
      passes: [],
    };
  },
  async validate(_context: ValidationContext): Promise<ValidationReport> {
    return {
      valid: true,
      diagnostics: [],
    };
  },
};

