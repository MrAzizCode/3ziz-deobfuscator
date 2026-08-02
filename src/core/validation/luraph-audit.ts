import type {
  Diagnostic,
  LuraphAuditFacts,
  LuraphFunctionFacts,
  ValidationReport,
} from "../../shared/contracts";

export interface LuraphAuditValidation {
  readonly facts: LuraphAuditFacts;
  readonly report: ValidationReport;
}

interface FunctionStart {
  readonly name: string;
  readonly lineIndex: number;
}

interface FunctionMetadata {
  readonly decodedInstructions?: number;
  readonly reachableInstructions?: number;
  readonly appliedPatches?: number;
  readonly omittedInstructions?: number;
}

function parseMetadata(lines: readonly string[], start: number): FunctionMetadata {
  const context = lines.slice(Math.max(0, start - 10), start + 1).join("\n");
  const instructionMatch = context.match(
    /stack slots:\s*\d+;\s*decoded instructions:\s*(\d+);\s*reachable CFG instructions:\s*(\d+)/i,
  );
  const patchMatch = context.match(
    /statically applied array patches:\s*(\d+);\s*unreachable PCs omitted:\s*(\d+)/i,
  );
  return {
    ...(instructionMatch
      ? {
          decodedInstructions: Number(instructionMatch[1]),
          reachableInstructions: Number(instructionMatch[2]),
        }
      : {}),
    ...(patchMatch
      ? {
          appliedPatches: Number(patchMatch[1]),
          omittedInstructions: Number(patchMatch[2]),
        }
      : {}),
  };
}

function inspectFunction(
  lines: readonly string[],
  start: FunctionStart,
  endIndex: number,
): LuraphFunctionFacts {
  const definitions = new Map<string, number>();
  const references = new Map<string, number>();

  for (let lineIndex = start.lineIndex; lineIndex <= endIndex; lineIndex += 1) {
    const line = lines[lineIndex] ?? "";
    for (const match of line.matchAll(/::(L\d+)::/g)) {
      const label = match[1];
      if (!label) continue;
      definitions.set(label, (definitions.get(label) ?? 0) + 1);
    }
    for (const match of line.matchAll(/\bgoto\s+(L\d+)\b/g)) {
      const label = match[1];
      if (!label) continue;
      references.set(label, (references.get(label) ?? 0) + 1);
    }
  }

  const duplicateLabels = [...definitions.entries()]
    .filter(([, count]) => count > 1)
    .map(([label]) => label)
    .sort();
  const unresolvedTargets = [...references.keys()]
    .filter((label) => !definitions.has(label))
    .sort();
  const metadata = parseMetadata(lines, start.lineIndex);

  return {
    name: start.name,
    ...metadata,
    labelDefinitions: [...definitions.values()].reduce(
      (sum, count) => sum + count,
      0,
    ),
    gotoReferences: [...references.values()].reduce(
      (sum, count) => sum + count,
      0,
    ),
    duplicateLabels,
    unresolvedTargets,
  };
}

function sumOptional(
  functions: readonly LuraphFunctionFacts[],
  key:
    | "decodedInstructions"
    | "reachableInstructions"
    | "appliedPatches"
    | "omittedInstructions",
): number {
  return functions.reduce((sum, func) => sum + (func[key] ?? 0), 0);
}

export function validateLuraphAudit(source: string): LuraphAuditValidation {
  const lines = source.split(/\r?\n/);
  const starts: FunctionStart[] = [];
  for (let lineIndex = 0; lineIndex < lines.length; lineIndex += 1) {
    const match = (lines[lineIndex] ?? "").match(
      /^local function\s+([A-Za-z_]\w*)\s*\(/,
    );
    if (match?.[1]) starts.push({ name: match[1], lineIndex });
  }

  const functions = starts.map((start, index) =>
    inspectFunction(
      lines,
      start,
      (starts[index + 1]?.lineIndex ?? lines.length) - 1,
    ),
  );
  const decodedInstructions = sumOptional(functions, "decodedInstructions");
  const reachableInstructions = sumOptional(functions, "reachableInstructions");
  const deterministicPatches = sumOptional(functions, "appliedPatches");
  const omittedInstructions = sumOptional(functions, "omittedInstructions");
  const labelDefinitions = functions.reduce(
    (sum, func) => sum + func.labelDefinitions,
    0,
  );
  const gotoReferences = functions.reduce(
    (sum, func) => sum + func.gotoReferences,
    0,
  );
  const ambiguousDecoderWrites = [
    ...source.matchAll(/ignored\s+(\d+)\s+non-opcode\/ambiguous decoder writes/gi),
  ].reduce((sum, match) => sum + Number(match[1] ?? 0), 0);
  const vmFragments = (
    source.match(/::L\d+::\s+VM_FRAGMENT\b/g) ?? []
  ).length;

  const summary = source.match(
    /Summary:\s*(\d+)\s+functions,\s*(\d+)\s+decoded instructions,\s*(\d+)\s+deterministic self-modifying writes applied/i,
  );
  const summaryMatchesMetadata =
    summary !== null &&
    Number(summary[1]) === functions.length &&
    Number(summary[2]) === decodedInstructions &&
    Number(summary[3]) === deterministicPatches;

  const nonExecutableReasons = [
    "opcode names are emitted as bare audit annotations before pseudocode statements",
    "labels and goto edges describe recovered VM control flow rather than Luau source",
    "reg, upvalues, environment, top, and temporary VM state are implicit",
    ...(source.includes("/*STR[")
      ? ["C-style constant annotations are not Lua/Luau comments"]
      : []),
    ...(vmFragments > 0
      ? [`${vmFragments} unresolved VM_FRAGMENT operations remain`]
      : []),
  ];

  const facts: LuraphAuditFacts = {
    functionCount: functions.length,
    decodedInstructions,
    reachableInstructions,
    omittedInstructions,
    deterministicPatches,
    ambiguousDecoderWrites,
    labelDefinitions,
    gotoReferences,
    vmFragments,
    functions,
    summaryMatchesMetadata,
    nonExecutableReasons,
  };

  const diagnostics: Diagnostic[] = [];
  const duplicateCount = functions.reduce(
    (sum, func) => sum + func.duplicateLabels.length,
    0,
  );
  const unresolvedCount = functions.reduce(
    (sum, func) => sum + func.unresolvedTargets.length,
    0,
  );

  if (functions.length === 0) {
    diagnostics.push({
      code: "LURAPH_AUDIT_NO_FUNCTIONS",
      severity: "error",
      stage: "luraph-validation",
      message: "No recovered function sections were found.",
    });
  }
  if (duplicateCount > 0) {
    diagnostics.push({
      code: "LURAPH_AUDIT_DUPLICATE_LABELS",
      severity: "error",
      stage: "luraph-validation",
      message: "Duplicate labels were found inside recovered functions.",
      evidence: functions
        .filter((func) => func.duplicateLabels.length > 0)
        .map((func) => `${func.name}: ${func.duplicateLabels.join(", ")}`),
    });
  }
  if (unresolvedCount > 0) {
    diagnostics.push({
      code: "LURAPH_AUDIT_UNRESOLVED_GOTOS",
      severity: "error",
      stage: "luraph-validation",
      message: "One or more goto targets do not resolve inside their function.",
      evidence: functions
        .filter((func) => func.unresolvedTargets.length > 0)
        .map((func) => `${func.name}: ${func.unresolvedTargets.join(", ")}`),
    });
  }
  if (reachableInstructions > 0 && labelDefinitions !== reachableInstructions) {
    diagnostics.push({
      code: "LURAPH_AUDIT_REACHABLE_COUNT_MISMATCH",
      severity: "error",
      stage: "luraph-validation",
      message:
        "Recovered label count does not match the sum of reachable-instruction metadata.",
      evidence: [
        `labels=${labelDefinitions}`,
        `reachable metadata=${reachableInstructions}`,
      ],
    });
  }
  if (summary && !summaryMatchesMetadata) {
    diagnostics.push({
      code: "LURAPH_AUDIT_SUMMARY_MISMATCH",
      severity: "error",
      stage: "luraph-validation",
      message: "The trailing summary does not match per-function metadata.",
    });
  }
  if (vmFragments > 0) {
    diagnostics.push({
      code: "LURAPH_AUDIT_UNRESOLVED_FRAGMENTS",
      severity: "warning",
      stage: "luraph-validation",
      message: `${vmFragments} unresolved VM fragment operations were retained exactly.`,
    });
  }
  diagnostics.push({
    code: "LURAPH_AUDIT_NON_EXECUTABLE_IR",
    severity: "warning",
    stage: "luraph-validation",
    message:
      "This artifact is audit-oriented VM IR and must not be presented or executed as source code.",
    evidence: nonExecutableReasons,
  });

  return {
    facts,
    report: {
      valid:
        functions.length > 0 &&
        duplicateCount === 0 &&
        unresolvedCount === 0 &&
        (reachableInstructions === 0 ||
          labelDefinitions === reachableInstructions) &&
        (!summary || summaryMatchesMetadata),
      diagnostics,
    },
  };
}
