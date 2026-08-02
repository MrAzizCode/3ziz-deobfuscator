import { gzipSync } from "node:zlib";

import type { ExtractedArtifact } from "../../shared/contracts";
import { sha256Bytes } from "../hash";
import {
  instructionAt,
  type JnkieDecodedConstant,
  type JnkieDecodedInstruction,
  type JnkieDecodedPrototype,
  type JnkieRecordDecodeResult,
  type JnkieRecordSection,
} from "./jnkie-record-model";

const FULL_INSTRUCTION_COLUMNS = [
  "section",
  "prototype",
  "pc",
  "byteStart",
  "wordA",
  "opcode",
  "wordN",
  "wordQ",
  "wordABytes",
  "opcodeBytes",
  "wordNBytes",
  "wordQBytes",
] as const;

const ROOT_EXCERPT_HEAD_ROWS = 192;
const ROOT_EXCERPT_TAIL_ROWS = 64;

export interface JnkieRecordSummarySection {
  readonly index: number;
  readonly kind: "outer-loader" | "nested-payload";
  readonly byteRange: readonly [number, number];
  readonly wrappedConstants: boolean;
  readonly constants: number;
  readonly prototypes: number;
  readonly instructions: number;
  readonly captures: number;
  readonly constantChannelReferences: number;
  readonly stringConstantChannelReferences: number;
  readonly prototypeReferences: number;
  readonly unresolvedConstantReferences: number;
  readonly unresolvedPrototypeReferences: number;
  readonly rootPrototypeIndex: number;
  readonly rootInstructions: number;
}

export interface JnkieRecordSummary {
  readonly schemaVersion: 1;
  readonly format: Readonly<{
    constantCountBias: 60_177;
    prototypeCountBias: 29_334;
    instructionCountBias: 94_145;
    indexBase: 1;
    byteRanges: "zero-based-half-open";
  }>;
  readonly safety: Readonly<{
    submittedCodeExecution: "never";
    decodeMode: "bounded-static-record-reader";
  }>;
  readonly coverage: Readonly<{
    inputBytes: number;
    decodedRecordBytes: number;
    unresolvedBytes: number;
    trailingBytes: number;
    sections: number;
    unresolvedRegions: readonly {
      readonly kind: "interstitial-prelude" | "trailing-data";
      readonly byteRange: readonly [number, number];
      readonly byteLength: number;
      readonly previewHex: string;
    }[];
  }>;
  readonly totals: Readonly<{
    constants: number;
    prototypes: number;
    instructions: number;
    constantChannelReferences: number;
    stringConstantChannelReferences: number;
    prototypeReferences: number;
    unresolvedConstantReferences: number;
    unresolvedPrototypeReferences: number;
  }>;
  readonly semanticSectionIndex: number;
  readonly sections: readonly JnkieRecordSummarySection[];
}

function summarySection(section: JnkieRecordSection): JnkieRecordSummarySection {
  const facts = section.statistics;
  return {
    index: section.index,
    kind: section.kind,
    byteRange: [section.byteRange.start, section.byteRange.end],
    wrappedConstants: section.wrappedConstants,
    constants: facts.constantCount,
    prototypes: facts.prototypeCount,
    instructions: facts.instructionCount,
    captures: facts.captureCount,
    constantChannelReferences: facts.constantReferenceCount,
    stringConstantChannelReferences: facts.stringConstantReferenceCount,
    prototypeReferences: facts.prototypeReferenceCount,
    unresolvedConstantReferences: facts.unresolvedConstantReferenceCount,
    unresolvedPrototypeReferences: facts.unresolvedPrototypeReferenceCount,
    rootPrototypeIndex: section.rootPrototypeIndex,
    rootInstructions: section.rootPrototype.instructionCount,
  };
}

export function buildJnkieRecordSummary(
  result: JnkieRecordDecodeResult,
): JnkieRecordSummary {
  const facts = result.statistics;
  return {
    schemaVersion: 1,
    format: {
      constantCountBias: 60_177,
      prototypeCountBias: 29_334,
      instructionCountBias: 94_145,
      indexBase: 1,
      byteRanges: "zero-based-half-open",
    },
    safety: result.safety,
    coverage: {
      inputBytes: facts.inputBytes,
      decodedRecordBytes: facts.decodedBytes,
      unresolvedBytes: facts.unresolvedBytes,
      trailingBytes: facts.trailingBytes,
      sections: facts.sectionCount,
      unresolvedRegions: result.unresolvedRegions.map((region) => ({
        kind: region.kind,
        byteRange: [region.byteRange.start, region.byteRange.end],
        byteLength: region.byteLength,
        previewHex: region.previewHex,
      })),
    },
    totals: {
      constants: facts.constantCount,
      prototypes: facts.prototypeCount,
      instructions: facts.instructionCount,
      constantChannelReferences: facts.constantReferenceCount,
      stringConstantChannelReferences: facts.stringConstantReferenceCount,
      prototypeReferences: facts.prototypeReferenceCount,
      unresolvedConstantReferences: facts.unresolvedConstantReferenceCount,
      unresolvedPrototypeReferences: facts.unresolvedPrototypeReferenceCount,
    },
    semanticSectionIndex: result.semanticSection.index,
    sections: result.sections.map(summarySection),
  };
}

function isObject(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

function finiteInteger(
  record: Record<string, unknown>,
  field: string,
  minimum = 0,
): number {
  const value = record[field];
  if (!Number.isSafeInteger(value) || (value as number) < minimum) {
    throw new Error(`Invalid JNKIE record summary field ${field}.`);
  }
  return value as number;
}

function exactString<T extends string>(
  record: Record<string, unknown>,
  field: string,
  values: readonly T[],
): T {
  const value = record[field];
  if (typeof value !== "string" || !values.includes(value as T)) {
    throw new Error(`Invalid JNKIE record summary field ${field}.`);
  }
  return value as T;
}

function parseRange(value: unknown, field: string): readonly [number, number] {
  if (
    !Array.isArray(value) ||
    value.length !== 2 ||
    !Number.isSafeInteger(value[0]) ||
    !Number.isSafeInteger(value[1]) ||
    (value[0] as number) < 0 ||
    (value[1] as number) < (value[0] as number)
  ) {
    throw new Error(`Invalid JNKIE record summary range ${field}.`);
  }
  return [value[0] as number, value[1] as number];
}

/** Strict parser for GUI/plugin consumers; never trust a loose summary JSON. */
export function parseJnkieRecordSummary(
  source: string | Uint8Array,
): JnkieRecordSummary {
  const text = typeof source === "string"
    ? source
    : new TextDecoder("utf-8", { fatal: true }).decode(source);
  const parsed: unknown = JSON.parse(text);
  if (!isObject(parsed) || parsed.schemaVersion !== 1) {
    throw new Error("Unsupported JNKIE record summary schema.");
  }
  if (!isObject(parsed.format)) throw new Error("Missing JNKIE record format.");
  if (
    finiteInteger(parsed.format, "constantCountBias") !== 60_177 ||
    finiteInteger(parsed.format, "prototypeCountBias") !== 29_334 ||
    finiteInteger(parsed.format, "instructionCountBias") !== 94_145 ||
    finiteInteger(parsed.format, "indexBase") !== 1 ||
    exactString(parsed.format, "byteRanges", ["zero-based-half-open"] as const) !==
      "zero-based-half-open"
  ) {
    throw new Error("JNKIE record summary format constants do not match.");
  }
  if (!isObject(parsed.safety)) throw new Error("Missing JNKIE safety record.");
  exactString(parsed.safety, "submittedCodeExecution", ["never"] as const);
  exactString(parsed.safety, "decodeMode", ["bounded-static-record-reader"] as const);
  if (!isObject(parsed.coverage)) throw new Error("Missing JNKIE coverage record.");
  const coverage = parsed.coverage;
  const inputBytes = finiteInteger(coverage, "inputBytes");
  const decodedRecordBytes = finiteInteger(coverage, "decodedRecordBytes");
  const unresolvedBytes = finiteInteger(coverage, "unresolvedBytes");
  const trailingBytes = finiteInteger(coverage, "trailingBytes");
  const sectionCount = finiteInteger(coverage, "sections", 1);
  if (decodedRecordBytes + unresolvedBytes !== inputBytes) {
    throw new Error("JNKIE record summary coverage does not span the input.");
  }
  if (!Array.isArray(coverage.unresolvedRegions)) {
    throw new Error("Missing JNKIE unresolved-region list.");
  }
  const unresolvedRegions = coverage.unresolvedRegions.map((value, index) => {
    if (!isObject(value)) throw new Error(`Invalid unresolved region ${index + 1}.`);
    const byteRange = parseRange(value.byteRange, `unresolvedRegions[${index}].byteRange`);
    const byteLength = finiteInteger(value, "byteLength");
    if (byteRange[1] - byteRange[0] !== byteLength) {
      throw new Error(`Unresolved region ${index + 1} has an inconsistent length.`);
    }
    const previewHex = value.previewHex;
    if (typeof previewHex !== "string" || !/^(?:[0-9a-f]{2})*$/.test(previewHex)) {
      throw new Error(`Invalid unresolved region ${index + 1} preview.`);
    }
    return {
      kind: exactString(value, "kind", ["interstitial-prelude", "trailing-data"] as const),
      byteRange,
      byteLength,
      previewHex,
    };
  });
  if (
    unresolvedRegions.reduce((sum, region) => sum + region.byteLength, 0) !==
    unresolvedBytes
  ) {
    throw new Error("JNKIE unresolved-region totals do not match coverage.");
  }

  if (!isObject(parsed.totals)) throw new Error("Missing JNKIE totals record.");
  const totals = {
    constants: finiteInteger(parsed.totals, "constants"),
    prototypes: finiteInteger(parsed.totals, "prototypes"),
    instructions: finiteInteger(parsed.totals, "instructions"),
    constantChannelReferences: finiteInteger(
      parsed.totals,
      "constantChannelReferences",
    ),
    stringConstantChannelReferences: finiteInteger(
      parsed.totals,
      "stringConstantChannelReferences",
    ),
    prototypeReferences: finiteInteger(parsed.totals, "prototypeReferences"),
    unresolvedConstantReferences: finiteInteger(
      parsed.totals,
      "unresolvedConstantReferences",
    ),
    unresolvedPrototypeReferences: finiteInteger(
      parsed.totals,
      "unresolvedPrototypeReferences",
    ),
  };
  if (!Array.isArray(parsed.sections) || parsed.sections.length !== sectionCount) {
    throw new Error("JNKIE section list does not match coverage.");
  }
  const sections = parsed.sections.map((value, index): JnkieRecordSummarySection => {
    if (!isObject(value)) throw new Error(`Invalid section ${index + 1}.`);
    if (finiteInteger(value, "index", 1) !== index + 1) {
      throw new Error("JNKIE section indices are not contiguous and one-based.");
    }
    if (typeof value.wrappedConstants !== "boolean") {
      throw new Error(`Invalid section ${index + 1} wrapped-constant flag.`);
    }
    return {
      index: index + 1,
      kind: exactString(value, "kind", ["outer-loader", "nested-payload"] as const),
      byteRange: parseRange(value.byteRange, `sections[${index}].byteRange`),
      wrappedConstants: value.wrappedConstants,
      constants: finiteInteger(value, "constants"),
      prototypes: finiteInteger(value, "prototypes"),
      instructions: finiteInteger(value, "instructions"),
      captures: finiteInteger(value, "captures"),
      constantChannelReferences: finiteInteger(value, "constantChannelReferences"),
      stringConstantChannelReferences: finiteInteger(
        value,
        "stringConstantChannelReferences",
      ),
      prototypeReferences: finiteInteger(value, "prototypeReferences"),
      unresolvedConstantReferences: finiteInteger(
        value,
        "unresolvedConstantReferences",
      ),
      unresolvedPrototypeReferences: finiteInteger(
        value,
        "unresolvedPrototypeReferences",
      ),
      rootPrototypeIndex: finiteInteger(value, "rootPrototypeIndex", 1),
      rootInstructions: finiteInteger(value, "rootInstructions"),
    };
  });
  const summed = (field: "constants" | "prototypes" | "instructions"): number =>
    sections.reduce((sum, section) => sum + section[field], 0);
  if (
    summed("constants") !== totals.constants ||
    summed("prototypes") !== totals.prototypes ||
    summed("instructions") !== totals.instructions
  ) {
    throw new Error("JNKIE section metrics do not match aggregate totals.");
  }
  const semanticSectionIndex = finiteInteger(parsed, "semanticSectionIndex", 1);
  if (semanticSectionIndex > sections.length) {
    throw new Error("JNKIE semantic section index is out of range.");
  }
  return {
    schemaVersion: 1,
    format: {
      constantCountBias: 60_177,
      prototypeCountBias: 29_334,
      instructionCountBias: 94_145,
      indexBase: 1,
      byteRanges: "zero-based-half-open",
    },
    safety: {
      submittedCodeExecution: "never",
      decodeMode: "bounded-static-record-reader",
    },
    coverage: {
      inputBytes,
      decodedRecordBytes,
      unresolvedBytes,
      trailingBytes,
      sections: sectionCount,
      unresolvedRegions,
    },
    totals,
    semanticSectionIndex,
    sections,
  };
}

function artifact(
  fileName: string,
  mediaType: string,
  bytes: Uint8Array,
): ExtractedArtifact {
  return { fileName, mediaType, bytes, sha256: sha256Bytes(bytes) };
}

function jsonBytes(value: unknown): Uint8Array {
  return Buffer.from(`${JSON.stringify(value, null, 2)}\n`, "utf8");
}

function jsonlBytes(lines: readonly unknown[]): Uint8Array {
  return Buffer.from(`${lines.map((line) => JSON.stringify(line)).join("\n")}\n`, "utf8");
}

function instructionArray(
  sectionIndex: number,
  prototypeIndex: number,
  instruction: JnkieDecodedInstruction,
): readonly number[] {
  const ranges = instruction.wordByteRanges;
  return [
    sectionIndex,
    prototypeIndex,
    instruction.pc,
    instruction.byteRange.start,
    instruction.rawWords[0],
    instruction.rawWords[1],
    instruction.rawWords[2],
    instruction.rawWords[3],
    ranges[0].end - ranges[0].start,
    ranges[1].end - ranges[1].start,
    ranges[2].end - ranges[2].start,
    ranges[3].end - ranges[3].start,
  ];
}

function instructionJsonl(
  result: JnkieRecordDecodeResult,
  rootsOnly: boolean,
): Uint8Array {
  const chunks: string[] = [
    JSON.stringify({
      schemaVersion: 1,
      kind: rootsOnly ? "root-instructions" : "all-instructions",
      columns: FULL_INSTRUCTION_COLUMNS,
      byteRanges: "zero-based-half-open",
      channelDecode:
        "mode=word%8; payload=floor(word/8); mode2=constant index; mode4=prototype index; mode3=pc+payload; mode6=pc-payload",
    }),
  ];
  for (const section of result.sections) {
    const prototypes = rootsOnly ? [section.rootPrototype] : section.prototypes;
    for (const prototype of prototypes) {
      const columns = prototype.instructions;
      for (let offset = 0; offset < columns.count; offset += 1) {
        const pc = offset + 1;
        // Avoid materializing three nested channel objects for the 261k-row dump.
        chunks.push(
          JSON.stringify([
            section.index,
            prototype.index,
            pc,
            columns.byteStart[offset]!,
            columns.rawWordA[offset]!,
            columns.rawOpcode[offset]!,
            columns.rawWordN[offset]!,
            columns.rawWordQ[offset]!,
            columns.wordAByteEnd[offset]! - columns.wordAByteStart[offset]!,
            columns.opcodeByteEnd[offset]! - columns.opcodeByteStart[offset]!,
            columns.wordNByteEnd[offset]! - columns.wordNByteStart[offset]!,
            columns.wordQByteEnd[offset]! - columns.wordQByteStart[offset]!,
          ]),
        );
      }
    }
  }
  return Buffer.from(`${chunks.join("\n")}\n`, "utf8");
}

function constantArtifactRecord(
  sectionIndex: number,
  constant: JnkieDecodedConstant,
): Record<string, unknown> {
  const base: Record<string, unknown> = {
    section: sectionIndex,
    index: constant.index,
    tag: constant.tag,
    kind: constant.kind,
    byteRange: [constant.byteRange.start, constant.byteRange.end],
    encodedBase64: constant.encodedBase64,
  };
  if (constant.kind === "integer") {
    return {
      ...base,
      encoding: constant.encoding,
      exactDecimal: constant.exactDecimal,
      runtimeValue: constant.value,
    };
  }
  if (constant.kind === "float") {
    return {
      ...base,
      encoding: constant.encoding,
      ieee754Hex: constant.ieee754Hex,
      displayValue: constant.displayValue,
    };
  }
  if (constant.kind === "boolean") return { ...base, value: constant.value };
  if (constant.kind === "string") {
    return {
      ...base,
      byteLength: constant.byteLength,
      utf8Text: constant.utf8Text,
      latin1Text: constant.latin1Text,
    };
  }
  return { ...base, byteLength: constant.byteLength };
}

function prototypesJsonl(result: JnkieRecordDecodeResult): Uint8Array {
  const lines: unknown[] = [
    {
      schemaVersion: 1,
      columns: {
        section: "one-based section index",
        prototype: "one-based stream-order prototype index",
        byteRange: "zero-based half-open absolute payload range",
      },
    },
  ];
  for (const section of result.sections) {
    for (const prototype of section.prototypes) {
      lines.push({
        section: section.index,
        prototype: prototype.index,
        byteRange: [prototype.byteRange.start, prototype.byteRange.end],
        instructions: prototype.instructionCount,
        selector: prototype.selector,
        maxStack: prototype.maxStack,
        root: prototype.index === section.rootPrototypeIndex,
        captures: prototype.captures.map((capture) => [
          capture.index,
          capture.encoded,
          capture.kind,
          capture.sourceIndex,
          capture.byteRange.start,
          capture.byteRange.end,
        ]),
      });
    }
  }
  return jsonlBytes(lines);
}

function constantsJsonl(result: JnkieRecordDecodeResult): Uint8Array {
  const lines: unknown[] = [
    {
      schemaVersion: 1,
      kind: "lossless-constants",
      note: "encodedBase64 is the sole exact tag-plus-payload copy; buffers are not duplicated",
    },
  ];
  for (const section of result.sections) {
    for (const constant of section.constants) {
      lines.push(constantArtifactRecord(section.index, constant));
    }
  }
  return jsonlBytes(lines);
}

function opcodeHistogram(prototype: JnkieDecodedPrototype): readonly [number, number][] {
  const counts = new Map<number, number>();
  for (const opcode of prototype.instructions.rawOpcode) {
    counts.set(opcode, (counts.get(opcode) ?? 0) + 1);
  }
  return [...counts.entries()].sort(
    (left, right) => right[1] - left[1] || left[0] - right[0],
  );
}

function channelText(instruction: JnkieDecodedInstruction, name: "A" | "N" | "Q"): string {
  const channel = instruction.channels[name];
  const reference = channel.constantIndex !== null
    ? ` C#${channel.constantIndex}`
    : channel.childPrototypeIndex !== null
      ? ` P#${channel.childPrototypeIndex}`
      : channel.resolvedValue !== null
        ? ` =>${channel.resolvedValue}`
        : "";
  return `${name}[m${channel.mode}:${channel.payload}${reference}]`;
}

function readableInstruction(
  section: JnkieRecordSection,
  prototype: JnkieDecodedPrototype,
  pc: number,
): string {
  const instruction = instructionAt(prototype.instructions, pc);
  return [
    `S${String(section.index).padStart(2, "0")}`,
    `P${String(prototype.index).padStart(4, "0")}`,
    `PC${String(pc).padStart(6, "0")}`,
    `@${instruction.byteRange.start}..${instruction.byteRange.end}`,
    `OP ${instruction.rawOpcode}`,
    channelText(instruction, "A"),
    channelText(instruction, "N"),
    channelText(instruction, "Q"),
  ].join("  ");
}

function selectedExcerptPcs(count: number): readonly number[] {
  if (count <= ROOT_EXCERPT_HEAD_ROWS + ROOT_EXCERPT_TAIL_ROWS) {
    return Array.from({ length: count }, (_, offset) => offset + 1);
  }
  return [
    ...Array.from({ length: ROOT_EXCERPT_HEAD_ROWS }, (_, offset) => offset + 1),
    ...Array.from(
      { length: ROOT_EXCERPT_TAIL_ROWS },
      (_, offset) => count - ROOT_EXCERPT_TAIL_ROWS + offset + 1,
    ),
  ];
}

function renderReadableIndex(result: JnkieRecordDecodeResult): string {
  const lines = [
    "3ziz Deobfuscator - JNKIE decoded record index",
    "",
    "All submitted code remained unexecuted. Indices/PCs are one-based; byte ranges are absolute half-open ranges.",
    "This human view is an explicitly labeled index/excerpt. Every instruction is retained without truncation in jnkie-record-instructions.jsonl.gz.",
    "",
  ];
  for (const section of result.sections) {
    const facts = section.statistics;
    lines.push(
      `SECTION S${String(section.index).padStart(2, "0")} ${section.kind}`,
      `  bytes: [${section.byteRange.start}, ${section.byteRange.end}) (${facts.byteLength})`,
      `  constants=${facts.constantCount} prototypes=${facts.prototypeCount} instructions=${facts.instructionCount} captures=${facts.captureCount}`,
      `  root=P${section.rootPrototypeIndex} rootInstructions=${section.rootPrototype.instructionCount} wrappedConstants=${section.wrappedConstants}`,
      "",
      "  Prototype index:",
    );
    for (const prototype of section.prototypes) {
      lines.push(
        `  P${String(prototype.index).padStart(4, "0")} @${prototype.byteRange.start}..${prototype.byteRange.end} instructions=${prototype.instructionCount} selector=${prototype.selector} stack=${prototype.maxStack} captures=${prototype.captures.length}${prototype.index === section.rootPrototypeIndex ? " ROOT" : ""}`,
      );
    }
    lines.push("", "  Root opcode histogram:");
    for (const [opcode, count] of opcodeHistogram(section.rootPrototype)) {
      lines.push(`  OP ${String(opcode).padStart(3, " ")}  ${count}`);
    }
    lines.push("", "  Root instruction excerpt:");
    const excerptPcs = selectedExcerptPcs(section.rootPrototype.instructionCount);
    for (const pc of excerptPcs) {
      lines.push(readableInstruction(section, section.rootPrototype, pc));
      if (
        pc === ROOT_EXCERPT_HEAD_ROWS &&
        section.rootPrototype.instructionCount >
          ROOT_EXCERPT_HEAD_ROWS + ROOT_EXCERPT_TAIL_ROWS
      ) {
        lines.push(
          `  ... ${section.rootPrototype.instructionCount - ROOT_EXCERPT_HEAD_ROWS - ROOT_EXCERPT_TAIL_ROWS} middle root rows are present in the complete gzip artifact ...`,
        );
      }
    }
    lines.push("");
  }
  if (result.unresolvedRegions.length !== 0) {
    lines.push("Opaque byte regions:");
    for (const region of result.unresolvedRegions) {
      lines.push(
        `  ${region.kind} @${region.byteRange.start}..${region.byteRange.end} (${region.byteLength} bytes), preview=${region.previewHex}`,
      );
    }
    lines.push("");
  }
  return `${lines.join("\n")}\n`;
}

function renderReport(result: JnkieRecordDecodeResult): string {
  const facts = result.statistics;
  const lines = [
    "# JNKIE bounded record decode",
    "",
    "## Outcome",
    "",
    `- Decoded **${facts.sectionCount} serialized record sections** covering ${facts.decodedBytes.toLocaleString("en-US")} of ${facts.inputBytes.toLocaleString("en-US")} payload bytes.`,
    `- Constants: ${facts.constantCount.toLocaleString("en-US")}`,
    `- Prototypes: ${facts.prototypeCount.toLocaleString("en-US")}`,
    `- Instructions: ${facts.instructionCount.toLocaleString("en-US")}`,
    `- Resolved prototype references: ${facts.resolvedPrototypeReferenceCount.toLocaleString("en-US")} / ${facts.prototypeReferenceCount.toLocaleString("en-US")}`,
    `- Resolved encoded constant-channel references: ${facts.resolvedConstantReferenceCount.toLocaleString("en-US")} / ${facts.constantReferenceCount.toLocaleString("en-US")}`,
    `- Opaque bytes: ${facts.unresolvedBytes.toLocaleString("en-US")}; trailing bytes after the final section: ${facts.trailingBytes.toLocaleString("en-US")}`,
    "",
    "## Sections",
    "",
  ];
  for (const section of result.sections) {
    const sectionFacts = section.statistics;
    lines.push(
      `### S${section.index} - ${section.kind}`,
      "",
      `- Byte range: [${section.byteRange.start}, ${section.byteRange.end})`,
      `- Constants: ${sectionFacts.constantCount.toLocaleString("en-US")} (wrapped flag: ${section.wrappedConstants})`,
      `- Prototypes: ${sectionFacts.prototypeCount.toLocaleString("en-US")}`,
      `- Instructions: ${sectionFacts.instructionCount.toLocaleString("en-US")}`,
      `- Captures: ${sectionFacts.captureCount.toLocaleString("en-US")}`,
      `- Root: P${section.rootPrototypeIndex}, ${section.rootPrototype.instructionCount.toLocaleString("en-US")} instructions, stack ${section.rootPrototype.maxStack}`,
      `- Constant-channel references: ${sectionFacts.constantReferenceCount.toLocaleString("en-US")} (${sectionFacts.stringConstantReferenceCount.toLocaleString("en-US")} point at strings)`,
      `- Prototype references: ${sectionFacts.prototypeReferenceCount.toLocaleString("en-US")}`,
      "",
    );
  }
  lines.push(
    "## Artifact map",
    "",
    "- `jnkie-record-summary.json`: strict machine-readable coverage and metrics.",
    "- `jnkie-record-prototypes.jsonl`: every prototype and capture descriptor.",
    "- `jnkie-record-constants.jsonl.gz`: every lossless constant record; each raw buffer occurs once.",
    "- `jnkie-record-root.jsonl.gz`: every instruction in both root prototypes.",
    "- `jnkie-record-instructions.jsonl.gz`: every instruction in every prototype (no truncation).",
    "- `jnkie-records-readable.txt`: compact human index and explicitly labeled root excerpts.",
    "",
    "## Evidence boundary",
    "",
    "The decoder only performs bounded reads over recovered bytes. It never executes submitted Lua/Luau, calls `loadstring`, evaluates JavaScript generated from the sample, or invokes a native sidecar. Operand modes and references are decoded exactly; opcode behavior and high-level control-flow claims require a separate evidence-backed semantic pass.",
    "",
  );
  return lines.join("\n");
}

/** Build compact metadata plus complete gzip JSONL evidence without truncation. */
export function buildJnkieRecordArtifacts(
  result: JnkieRecordDecodeResult,
): readonly ExtractedArtifact[] {
  const summary = buildJnkieRecordSummary(result);
  const prototypes = prototypesJsonl(result);
  const constants = constantsJsonl(result);
  const roots = instructionJsonl(result, true);
  const instructions = instructionJsonl(result, false);
  const readable = Buffer.from(renderReadableIndex(result), "utf8");
  const report = Buffer.from(renderReport(result), "utf8");
  return [
    artifact("jnkie-record-summary.json", "application/json", jsonBytes(summary)),
    artifact(
      "jnkie-record-prototypes.jsonl",
      "application/x-ndjson; charset=utf-8",
      prototypes,
    ),
    artifact(
      "jnkie-record-constants.jsonl.gz",
      "application/gzip",
      gzipSync(constants, { level: 9 }),
    ),
    artifact(
      "jnkie-record-root.jsonl.gz",
      "application/gzip",
      gzipSync(roots, { level: 9 }),
    ),
    artifact(
      "jnkie-record-instructions.jsonl.gz",
      "application/gzip",
      gzipSync(instructions, { level: 9 }),
    ),
    artifact(
      "jnkie-records-readable.txt",
      "text/plain; charset=utf-8",
      readable,
    ),
    artifact(
      "jnkie-record-report.md",
      "text/markdown; charset=utf-8",
      report,
    ),
  ];
}
