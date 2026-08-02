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
import { detectLuraphAudit, LURAPH_AUDIT_PLUGIN_ID } from "../detectors";
import { parseLuaFacts } from "../source/parse-facts";
import { validateLuraphAudit } from "../validation/luraph-audit";

export const LURAPH_AUDIT_MANIFEST: PluginManifest = {
  id: LURAPH_AUDIT_PLUGIN_ID,
  name: "Luraph VM audit",
  version: "0.1.0",
  family: "luraph-audit",
  description:
    "Validates recovered labels, goto edges, metadata, and unresolved VM fragments without treating audit IR as source.",
  supportedKinds: ["vm-audit-ir", "text", "luau-source"],
  authoritative: true,
};

async function planLuraphAudit(_context: AnalysisContext): Promise<StagePlan> {
  return {
    pluginId: LURAPH_AUDIT_PLUGIN_ID,
    stages: [
      {
        id: "luraph-audit-structure",
        description: "Validate function metadata, labels, and goto targets",
        authoritative: true,
      },
      {
        id: "luraph-audit-inventory",
        description: "Inventory visible static behavior without reachability claims",
        authoritative: true,
      },
    ],
  };
}

export const luraphAuditPlugin: DeobfuscatorPlugin = {
  manifest: LURAPH_AUDIT_MANIFEST,
  async detect(context: DetectionContext) {
    return detectLuraphAudit(context);
  },
  plan: planLuraphAudit,
  async analyze(context: AnalysisContext) {
    const text = context.text ?? "";
    const validation = validateLuraphAudit(text);
    return {
      status: validation.report.valid ? "partial" : "failed-validation",
      diagnostics: validation.report.diagnostics,
      sourceFacts: parseLuaFacts(
        text,
        context.classification,
        context.limits.maxAstNodes,
      ),
      behavior: inventoryBehavior(text),
      luraphAudit: validation.facts,
      passes: [],
    };
  },
  async validate(context: ValidationContext): Promise<ValidationReport> {
    if (!context.analysis.luraphAudit) {
      return {
        valid: false,
        diagnostics: [
          {
            code: "LURAPH_AUDIT_FACTS_MISSING",
            severity: "error",
            stage: "luraph-validation",
            message: "The plugin did not produce Luraph audit facts.",
          },
        ],
      };
    }
    const text = context.text ?? "";
    return validateLuraphAudit(text).report;
  },
};

