/**
 * Devirtualize a decoded Luraph record section into readable Lua.
 *
 * What this produces is genuine, re-parseable Lua with the script's own global
 * names, string literals, and control flow.  What it cannot produce is the
 * original local variable names, comments, or source layout: those are
 * destroyed by compilation and are synthesized here (`v12`, `fn37`) rather
 * than guessed.  The emitted header states that distinction so the output is
 * never mistaken for the original file.
 *
 * Submitted code is never executed.
 */

import type {
  JnkieDecodedPrototype,
  JnkieRecordSection,
} from "../recovery/jnkie-record-model";
import { parseLuau } from "../source/luau-parser";
import {
  renderStatements,
  type LuaStatement,
} from "./lua-ast";
import {
  liftPrototype,
  prototypeFunctionName,
  registerName,
  type LiftedPrototype,
} from "./lift";

export interface DevirtualizeOptions {
  /** Stop after this many prototypes; the rest are reported, not emitted. */
  readonly maxPrototypes?: number;
  /** Stop when a prototype declares more instructions than this. */
  readonly maxInstructionsPerPrototype?: number;
  /** Label used in the header to identify what was decompiled. */
  readonly sourceLabel?: string;
}

export interface DevirtualizationCoverage {
  readonly prototypesEmitted: number;
  readonly prototypesSkipped: number;
  readonly instructionRecords: number;
  /** Records reachable from an entry point; the remainder is decoy code. */
  readonly reachableInstructions: number;
  readonly unreachableInstructions: number;
  readonly provenInstructions: number;
  /** Decoder-protocol records: explained, with no guest-level effect. */
  readonly protocolInstructions: number;
  readonly unresolvedInstructions: number;
  readonly provenRatio: number;
  /** Proven plus protocol: the share of records this build accounts for. */
  readonly explainedRatio: number;
  readonly unstructuredRegions: number;
  readonly resolvedGlobalNames: readonly string[];
}

export interface DevirtualizationResult {
  readonly lua: string;
  readonly coverage: DevirtualizationCoverage;
  /** True when the emitted text re-parses under the Luau front end. */
  readonly reparses: boolean;
  readonly reparseError?: string;
  readonly warnings: readonly string[];
}

const DEFAULT_MAX_PROTOTYPES = 2_000;
const DEFAULT_MAX_INSTRUCTIONS = 200_000;

/**
 * Emit `local function fnN(...)` for one prototype.
 *
 * Every register the body touches is declared up front.  Lua caps a function
 * at 200 locals, so wide frames spill into a table; correctness first, and the
 * spill is stated in a comment rather than silently truncating registers.
 */
const MAX_DECLARED_LOCALS = 150;

function declarationStatements(lifted: LiftedPrototype): LuaStatement[] {
  if (lifted.registers.length === 0) return [];
  if (lifted.registers.length > MAX_DECLARED_LOCALS) {
    return [
      {
        kind: "comment",
        text:
          `[3ziz] ${lifted.registers.length} VM registers exceed Lua's local limit; ` +
          "they are declared in batches below",
      },
      ...batchedLocals(lifted.registers),
    ];
  }
  return [{ kind: "local", names: lifted.registers.map(registerName), values: [] }];
}

function batchedLocals(registers: readonly number[]): LuaStatement[] {
  const statements: LuaStatement[] = [];
  for (let start = 0; start < registers.length; start += MAX_DECLARED_LOCALS) {
    statements.push({
      kind: "local",
      names: registers
        .slice(start, start + MAX_DECLARED_LOCALS)
        .map(registerName),
      values: [],
    });
  }
  return statements;
}

function functionText(lifted: LiftedPrototype, prototype: JnkieDecodedPrototype): string {
  const header =
    `-- prototype ${prototype.index}: ` +
    `${lifted.reachableInstructionCount} reachable VM instructions of ` +
    `${lifted.instructionCount}, ${lifted.provenCount} lifted, ` +
    `${lifted.unresolvedCount} unresolved` +
    (lifted.unreachableInstructionCount > 0
      ? `, ${lifted.unreachableInstructionCount} unreachable and omitted`
      : "") +
    (prototype.captures.length > 0
      ? `, ${prototype.captures.length} captured upvalue(s)`
      : "");
  const body = renderStatements(
    [...declarationStatements(lifted), ...lifted.statements],
    1,
  );
  return [
    header,
    `local function ${prototypeFunctionName(prototype.index)}(...)`,
    body,
    "end",
    "",
  ].join("\n");
}

/**
 * Emit prototypes in dependency order so a closure's target is already
 * declared when it is referenced.  Cycles cannot occur in a prototype tree,
 * but an unreachable or forward reference can, so declaration order falls back
 * to stream order for anything not reached from the root.
 */
function emissionOrder(
  section: JnkieRecordSection,
  lifted: ReadonlyMap<number, LiftedPrototype>,
): readonly number[] {
  const order: number[] = [];
  const visited = new Set<number>();
  const visit = (index: number): void => {
    if (visited.has(index)) return;
    visited.add(index);
    for (const child of lifted.get(index)?.childPrototypes ?? []) {
      if (child !== index) visit(child);
    }
    order.push(index);
  };
  visit(section.rootPrototypeIndex);
  for (const prototype of section.prototypes) {
    if (lifted.has(prototype.index)) visit(prototype.index);
  }
  return order;
}

/**
 * Global names the script actually resolves, as readability evidence.
 *
 * Synthesized names are excluded: registers (`v12`), prototypes (`fn37`), and
 * labels (`L118`) say nothing about what the script does.
 */
const SYNTHESIZED_NAME = /^(?:v\d+|fn\d+|L\d+|upvalue\d+)$/;

/** Keywords are Lua's own; counting them would pad the evidence. */
const LUA_KEYWORD = new Set([
  "and", "break", "do", "else", "elseif", "end", "false", "for", "function",
  "goto", "if", "in", "local", "nil", "not", "or", "repeat", "return", "then",
  "true", "until", "while",
]);

function collectGlobalNames(statements: readonly string[]): readonly string[] {
  const names = new Set<string>();
  for (const body of statements) {
    // Comments carry prose, not resolved names.
    const text = body
      .split("\n")
      .filter((line) => !line.trimStart().startsWith("--"))
      .join("\n");
    for (const match of text.matchAll(/(?:^|[^\w.:"])([A-Za-z_]\w{2,})\s*[.:(]/g)) {
      const candidate = match[1]!;
      if (SYNTHESIZED_NAME.test(candidate)) continue;
      if (LUA_KEYWORD.has(candidate)) continue;
      names.add(candidate);
    }
  }
  return [...names].sort();
}

/**
 * The devirtualization section of the payload report.  Shared by extraction
 * and independent validation so the two cannot describe the same result
 * differently.
 */
export function renderDevirtualizationAppendix(
  result: DevirtualizationResult,
): string {
  const { coverage } = result;
  return [
    "# JNKIE devirtualization to Lua",
    "",
    `- Prototypes emitted: ${coverage.prototypesEmitted.toLocaleString("en-US")}`,
    `- Instruction records: ${coverage.instructionRecords.toLocaleString("en-US")}`,
    `- Proven and lifted: ${coverage.provenInstructions.toLocaleString("en-US")} (${(coverage.provenRatio * 100).toFixed(2)}%)`,
    `- VM decoder-protocol records: ${coverage.protocolInstructions.toLocaleString("en-US")}`,
    `- Explained (lifted plus protocol): ${(coverage.explainedRatio * 100).toFixed(2)}%`,
    `- Unresolved, preserved as comments: ${coverage.unresolvedInstructions.toLocaleString("en-US")}`,
    `- Regions emitted as goto/labels: ${coverage.unstructuredRegions.toLocaleString("en-US")}`,
    `- Emitted Lua re-parses: ${result.reparses ? "yes" : `no (${result.reparseError ?? "unknown"})`}`,
    `- Recovered global names: ${coverage.resolvedGlobalNames.slice(0, 24).join(", ") || "none"}`,
    "- Local names, comments, and source layout were destroyed by compilation and are synthesized, not recovered.",
    "- Submitted code execution: never.",
  ].join("\n");
}

/** The label the target-script section is devirtualized under. */
export function devirtualizationSourceLabel(payloadSha256: string): string {
  return `JNKIE/Luraph target script, payload ${payloadSha256.slice(0, 16)}`;
}

export function devirtualizeSection(
  section: JnkieRecordSection,
  options: DevirtualizeOptions = {},
): DevirtualizationResult {
  const maxPrototypes = options.maxPrototypes ?? DEFAULT_MAX_PROTOTYPES;
  const maxInstructions =
    options.maxInstructionsPerPrototype ?? DEFAULT_MAX_INSTRUCTIONS;
  const warnings: string[] = [];

  const lifted = new Map<number, LiftedPrototype>();
  const prototypeById = new Map<number, JnkieDecodedPrototype>();
  let skipped = 0;

  for (const prototype of section.prototypes) {
    prototypeById.set(prototype.index, prototype);
    if (lifted.size >= maxPrototypes) {
      skipped += 1;
      continue;
    }
    if (prototype.instructionCount > maxInstructions) {
      skipped += 1;
      warnings.push(
        `Prototype ${prototype.index} declares ${prototype.instructionCount} instructions and was not lifted.`,
      );
      continue;
    }
    lifted.set(prototype.index, liftPrototype(section, prototype));
  }

  let instructionRecords = 0;
  let reachableInstructions = 0;
  let unreachableInstructions = 0;
  let provenInstructions = 0;
  let protocolInstructions = 0;
  let unresolvedInstructions = 0;
  let unstructuredRegions = 0;
  const resolvedGlobals = new Set<string>();
  const bodies: string[] = [];

  for (const index of emissionOrder(section, lifted)) {
    const entry = lifted.get(index);
    const prototype = prototypeById.get(index);
    if (entry === undefined || prototype === undefined) continue;
    instructionRecords += entry.instructionCount;
    reachableInstructions += entry.reachableInstructionCount;
    unreachableInstructions += entry.unreachableInstructionCount;
    provenInstructions += entry.provenCount;
    protocolInstructions += entry.protocolCount;
    unresolvedInstructions += entry.unresolvedCount;
    unstructuredRegions += entry.unstructuredRegions;
    for (const global of entry.resolvedGlobals) resolvedGlobals.add(global);
    bodies.push(functionText(entry, prototype));
  }

  /*
   * Ratios are measured against what is emitted, not against the whole stream.
   * Unreachable decoy code is omitted, so counting it in the denominator would
   * understate how much of the emitted program is actually explained.
   */
  const denominator =
    reachableInstructions === 0 ? instructionRecords : reachableInstructions;
  const provenRatio = denominator === 0 ? 0 : provenInstructions / denominator;
  const explainedRatio =
    denominator === 0
      ? 0
      : (provenInstructions + protocolInstructions) / denominator;

  const header = [
    "-- Recovered by 3ziz Deobfuscator from a Luraph VM record stream.",
    "--",
    "-- This is REAL Lua reconstructed from proven VM opcode effects, not the",
    "-- original file. Control flow, global names, and literals are recovered;",
    "-- local variable names, comments, and source layout were destroyed by",
    "-- compilation and are synthesized here (v12, fn37) rather than guessed.",
    "--",
    `-- source: ${options.sourceLabel ?? `section ${section.index} (${section.kind})`}`,
    `-- prototypes: ${lifted.size} emitted, ${skipped} skipped`,
    `-- instructions: ${provenInstructions} of ${reachableInstructions} reachable lifted to source ` +
      `(${(provenRatio * 100).toFixed(2)}%), plus ${protocolInstructions} VM decoder-protocol ` +
      `records, for ${(explainedRatio * 100).toFixed(2)}% explained`,
    `-- unresolved VM ops stay inline; VM decoder-protocol records have no`,
    `-- guest-level effect and are counted per function, not printed`,
    `-- every record is retained in the exported record artifacts`,
    "-- submitted code was never executed",
    "",
  ].join("\n");

  const lua = `${header}${bodies.join("\n")}\nreturn ${prototypeFunctionName(section.rootPrototypeIndex)}\n`;

  let reparses = false;
  let reparseError: string | undefined;
  try {
    parseLuau(lua);
    reparses = true;
  } catch (error) {
    reparseError =
      error instanceof Error ? error.message.slice(0, 300) : "parse failed";
    warnings.push(`The emitted Lua did not re-parse: ${reparseError}`);
  }

  if (unresolvedInstructions > 0) {
    warnings.push(
      `${unresolvedInstructions} instruction record(s) use opcodes this dispatcher never proved and are preserved as comments.`,
    );
  }

  return {
    lua,
    coverage: {
      prototypesEmitted: lifted.size,
      prototypesSkipped: skipped,
      instructionRecords,
      reachableInstructions,
      unreachableInstructions,
      provenInstructions,
      protocolInstructions,
      unresolvedInstructions,
      provenRatio,
      explainedRatio,
      unstructuredRegions,
      resolvedGlobalNames: [...resolvedGlobals].sort(),
    },
    reparses,
    ...(reparseError === undefined ? {} : { reparseError }),
    warnings,
  };
}
