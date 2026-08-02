import type {
  AnalysisContext,
  DeobfuscatorPlugin,
  DetectionContext,
  Diagnostic,
  PluginAnalysis,
  PluginManifest,
  StagePlan,
  ValidationContext,
  ValidationReport,
} from "../../shared/contracts";
import { inventoryBehavior } from "../behavior/inventory";
import { inspectBytecodeSafely } from "../bytecode-adapter";
import { detectGeneric, GENERIC_PLUGIN_ID } from "../detectors";
import { runSourceCleanup } from "../passes/source-cleanup";
import { parseLuaFacts } from "../source/parse-facts";

export const GENERIC_MANIFEST: PluginManifest = {
  id: GENERIC_PLUGIN_ID,
  name: "Generic static Lua/Luau",
  version: "0.1.0",
  family: "generic",
  description:
    "Static classification, Lua 5.1 facts, proof-gated cleanup, and capability inventory.",
  supportedKinds: [
    "lua-source",
    "luau-source",
    "lua-bytecode",
    "text",
    "binary",
    "vm-audit-ir",
  ],
  authoritative: true,
};

async function planGeneric(context: AnalysisContext): Promise<StagePlan> {
  if (context.classification.kind === "lua-bytecode") {
    return {
      pluginId: GENERIC_PLUGIN_ID,
      stages: [
        {
          id: "bytecode-validate",
          description: "Bounded Lua 5.1 chunk validation",
          authoritative: true,
        },
        {
          id: "bytecode-disassemble",
          description: "Exact structural disassembly",
          authoritative: true,
        },
      ],
    };
  }

  return {
    pluginId: GENERIC_PLUGIN_ID,
    stages: [
      {
        id: "source-parse-facts",
        description: "Lua 5.1 parse with static Luau fallback",
        authoritative: true,
      },
      {
        id: "behavior-inventory",
        description: "Reachability-neutral static API and URL inventory",
        authoritative: true,
      },
      {
        id: "proof-gated-cleanup",
        description: "Only transformations with explicit equivalence proof",
        authoritative: true,
      },
    ],
  };
}

async function analyzeGeneric(context: AnalysisContext): Promise<PluginAnalysis> {
  if (context.classification.kind === "lua-bytecode") {
    const inspected = await inspectBytecodeSafely(context.bytes);
    return {
      status: inspected.summary.valid ? "verified" : "failed-validation",
      diagnostics: inspected.diagnostics,
      passes: [],
      bytecode: inspected.summary,
    };
  }

  if (context.text === undefined) {
    return {
      status: "unsupported",
      diagnostics: [
        {
          code: "GENERIC_BINARY_UNSUPPORTED",
          severity: "error",
          stage: "analysis",
          message: "The input is neither UTF-8 source nor recognized Lua bytecode.",
        },
      ],
      passes: [],
    };
  }

  const sourceFacts = parseLuaFacts(
    context.text,
    context.classification,
    context.limits.maxAstNodes,
  );
  const behavior = inventoryBehavior(context.text);
  const diagnostics: Diagnostic[] = [];

  if (
    context.classification.kind !== "lua-source" &&
    context.classification.kind !== "luau-source"
  ) {
    diagnostics.push({
      code: "GENERIC_TEXT_NOT_SOURCE",
      severity: "warning",
      stage: "analysis",
      message:
        "The input is valid text but lacks enough evidence to publish as Lua/Luau source.",
    });
    return {
      status: "unsupported",
      diagnostics,
      sourceFacts,
      behavior,
      passes: [],
    };
  }

  if (!sourceFacts.parsed) {
    diagnostics.push({
      code:
        sourceFacts.mode === "luau-static-fallback"
          ? "LUAU_STATIC_FALLBACK"
          : "LUA_PARSE_FAILED",
      severity: "warning",
      stage: "source-parse",
      message:
        sourceFacts.mode === "luau-static-fallback"
          ? "Lua 5.1 parsing was not applicable; only lexical Luau facts and behavior inventory are authoritative."
          : "Lua 5.1 parsing failed; no readable rewrite was published.",
      ...(sourceFacts.syntaxError
        ? { evidence: [sourceFacts.syntaxError] }
        : {}),
    });
    return {
      status: "partial",
      diagnostics,
      sourceFacts,
      behavior,
      passes: [],
    };
  }

  /*
   * A Luau-only parse yields real AST facts and proves the source is
   * syntactically valid, but the authoritative cleanup passes are proven for
   * Lua 5.1 binding rules alone.  Report the stronger facts without claiming a
   * readable rewrite that was never performed.
   */
  if (sourceFacts.mode !== "lua-5.1-ast") {
    diagnostics.push({
      code: "LUAU_AST_ONLY",
      severity: "info",
      stage: "source-parse",
      message:
        "Parsed with the Luau front end. AST facts and behavior inventory are authoritative; proof-gated Lua 5.1 cleanup did not run, so no readable rewrite was published.",
    });
    return {
      status: "partial",
      diagnostics,
      sourceFacts,
      behavior,
      passes: [],
    };
  }

  const cleanup = runSourceCleanup(
    context.text,
    context.classification,
    sourceFacts,
  );
  diagnostics.push(...cleanup.diagnostics);
  return {
    status: "verified",
    diagnostics,
    sourceFacts,
    behavior,
    passes: cleanup.passes,
    readableSource: cleanup.source,
  };
}

async function validateGeneric(
  context: ValidationContext,
): Promise<ValidationReport> {
  const errors = context.analysis.diagnostics.filter(
    (diagnostic) => diagnostic.severity === "error",
  );
  return {
    valid:
      errors.length === 0 && context.analysis.status !== "failed-validation",
    diagnostics: errors,
  };
}

export const genericPlugin: DeobfuscatorPlugin = {
  manifest: GENERIC_MANIFEST,
  async detect(context: DetectionContext) {
    return detectGeneric(context);
  },
  plan: planGeneric,
  analyze: analyzeGeneric,
  validate: validateGeneric,
};

