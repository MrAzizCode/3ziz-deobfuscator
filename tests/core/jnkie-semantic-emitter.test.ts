import { existsSync, readFileSync } from "node:fs";
import { join } from "node:path";
import { gunzipSync } from "node:zlib";

import { describe, expect, it } from "vitest";

import {
  emitKnownJnkieSemanticPseudocode,
  JNKIE_PROVEN_SEMANTIC_OPCODES,
  JNKIE_PROTOCOL_OPCODES,
  JNKIE_UI_PSEUDOCODE_MAX_BYTES,
} from "../../src/core/recovery/jnkie-semantic-emitter";
import {
  KNOWN_JNKIE_LOADER_SHA256,
  KNOWN_JNKIE_PAYLOAD_SHA256,
} from "../../src/core/recovery/jnkie-known-profile";
import { decodeJnkieRecordStream } from "../../src/core/recovery/jnkie-record-decoder";
import {
  JNKIE_RECORD_FORMAT,
  type JnkieDecodedPrototype,
  type JnkieInstructionColumns,
  type JnkieRecordDecodeResult,
  type JnkieRecordSection,
} from "../../src/core/recovery/jnkie-record-model";

interface TestInstruction {
  readonly opcode: number;
  readonly A: number;
  readonly N: number;
  readonly Q: number;
  readonly modeA?: number;
  readonly modeN?: number;
  readonly modeQ?: number;
  readonly constantA?: number;
  readonly constantN?: number;
  readonly constantQ?: number;
  readonly resolvedA?: number;
  readonly resolvedN?: number;
  readonly resolvedQ?: number;
}

const DIRECT_RENDER_CASES: readonly {
  readonly row: TestInstruction;
  readonly text: string;
}[] = [
  { row: { opcode: 1, A: 2, N: 5, Q: 8 }, text: "R[2] = NEW_TABLE(array_capacity=8)" },
  { row: { opcode: 5, A: 2, N: 5, Q: 8 }, text: "R[8] = (R[2] != R[5])" },
  { row: { opcode: 14, A: 2, N: 5, Q: 8 }, text: "R[5] = (R[2] <= R[8])" },
  {
    row: { opcode: 20, A: 2, N: 5, Q: 8 },
    text: "CALL_DISCARD(R[5], R[6]); VM_TOP = 4",
  },
  {
    row: { opcode: 22, A: 2, N: 5, Q: 8, modeA: 2, constantA: 1 },
    text: "R[8] = (R[5] <= C0001)",
  },
  { row: { opcode: 25, A: 2, N: 5, Q: 8 }, text: "R[8] = NIL" },
  {
    row: { opcode: 41, A: 2, N: 5, Q: 8, modeA: 2, constantA: 1 },
    text: "R[5] = (R[8] == C0001)",
  },
  {
    row: { opcode: 50, A: 2, N: 5, Q: 8 },
    text: "CLOSE_OPEN_UPVALUES(from_register=1); TAILCALL R[5](R[6])",
  },
  {
    row: { opcode: 62, A: 2, N: 0, Q: 0 },
    text: "CALL_GENERIC(function=R[2], arguments=REGISTERS(R[3] .. VM_TOP), results=ALL_RESULTS(start=R[2], update=VM_TOP))",
  },
  {
    row: { opcode: 62, A: 2, N: 1, Q: 1 },
    text: "CALL_GENERIC(function=R[2], arguments=NO_ARGUMENTS, results=DISCARD_RESULTS(update=VM_TOP=1))",
  },
  {
    row: { opcode: 62, A: 2, N: 4, Q: 3 },
    text: "CALL_GENERIC(function=R[2], arguments=REGISTERS(R[3] .. R[5]), results=REGISTERS(R[2] .. R[3]) (count=2, update=VM_TOP=4))",
  },
  {
    row: { opcode: 69, A: 2, N: 5, Q: 8, modeN: 2, constantN: 1 },
    text: "IF R[2] <= C0001 THEN GOTO PC0009",
  },
  {
    row: {
      opcode: 72,
      A: 2,
      N: 5,
      Q: 8,
      modeA: 2,
      modeQ: 2,
      constantA: 1,
      constantQ: 1,
    },
    text: "R[5] = C0001 * C0001",
  },
  {
    row: { opcode: 73, A: 2, N: 5, Q: 8 },
    text: "LOOP_INDEX += LOOP_STEP; IF ((LOOP_STEP > 0 AND LOOP_INDEX <= LOOP_LIMIT) OR (LOOP_STEP <= 0 AND LOOP_INDEX >= LOOP_LIMIT)) THEN R[11] = LOOP_INDEX; GOTO PC0003",
  },
  {
    row: { opcode: 75, A: 2, N: 5, Q: 8 },
    text: "TABLE_MOVE(source=REGISTERS, first=3, last=7, destination=R[2], destination_first=9)",
  },
  {
    row: { opcode: 79, A: 2, N: 5, Q: 4 },
    text: "CLOSE_OPEN_UPVALUES(from_register=1); RETURN REGISTERS(R[5] .. R[7])",
  },
  { row: { opcode: 105, A: 2, N: 5, Q: 8 }, text: "R[8] = (R[2] >= R[5])" },
  {
    row: { opcode: 118, A: 2, N: 5, Q: 8 },
    text: "CLOSE_OPEN_UPVALUES(from_register=1); RETURN",
  },
  {
    row: { opcode: 123, A: 2, N: 5, Q: 8 },
    text: "R[5] = CALL(R[5], REGISTERS(R[6] .. VM_TOP)); VM_TOP = 5",
  },
  { row: { opcode: 127, A: 2, N: 5, Q: 8 }, text: "R[5] = (R[2] == R[8])" },
  {
    row: { opcode: 129, A: 2, N: 5, Q: 4 },
    text: "REGISTERS(R[1] .. R[4]) = INCOMING_VARARGS(start=1, count=4)",
  },
  {
    row: { opcode: 131, A: 2, N: 5, Q: 8 },
    text: "CALL_DISCARD(R[5]); VM_TOP = 4",
  },
  {
    row: {
      opcode: 137,
      A: 2,
      N: 5,
      Q: 8,
      modeA: 2,
      modeN: 2,
      constantA: 1,
      constantN: 1,
    },
    text: "R[8] = C0001 - C0001",
  },
  {
    row: { opcode: 138, A: 2, N: 5, Q: 8, modeQ: 2, constantQ: 1 },
    text: "R[2] = (R[5] > C0001)",
  },
  {
    row: { opcode: 144, A: 2, N: 5, Q: 8, modeA: 2, constantA: 1 },
    text: "IF R[8] != C0001 THEN GOTO PC0006",
  },
  {
    row: { opcode: 147, A: 2, N: 5, Q: 8, modeN: 2, constantN: 1 },
    text: "R[8] = (R[2] != C0001)",
  },
  {
    row: { opcode: 154, A: 3, N: 5, Q: 8 },
    text: "REGISTERS(R[8] .. R[10]) = INCOMING_VARARGS(cursor=VARARG_CURSOR, count=3)",
  },
  { row: { opcode: 162, A: 2, N: 5, Q: 8 }, text: "R[5] = LENGTH(R[8])" },
  {
    row: { opcode: 176, A: 2, N: 5, Q: 8 },
    text: "PUSH_NUMERIC_LOOP_FRAME(index=LOOP_INDEX, limit=LOOP_LIMIT, step=LOOP_STEP); LOOP_BASE = 8; LOOP_STEP = NUMERIC(R[10]); LOOP_LIMIT = NUMERIC(R[9]); LOOP_INDEX = R[8] - LOOP_STEP; GOTO PC0003",
  },
  {
    row: { opcode: 193, A: 2, N: 5, Q: 8 },
    text: "CALL_DISCARD(R[5], R[6], R[7]); VM_TOP = 4",
  },
  { row: { opcode: 198, A: 2, N: 5, Q: 8 }, text: "R[2] = (R[5] < R[8])" },
  {
    row: { opcode: 199, A: 2, N: 5, Q: 8, modeA: 2, constantA: 1 },
    text: "IF R[8] >= C0001 THEN GOTO PC0006",
  },
  { row: { opcode: 208, A: 2, N: 5, Q: 8 }, text: "R[2] = (R[5] > R[8])" },
  {
    row: { opcode: 212, A: 2, N: 5, Q: 8, modeA: 2, constantA: 1 },
    text: "R[8] = R[5] / C0001",
  },
  { row: { opcode: 215, A: 2, N: 5, Q: 8 }, text: "R[8] = R[5][R[2]]" },
  {
    row: { opcode: 216, A: 2, N: 5, Q: 8 },
    text: "IF R[8] != R[2] THEN GOTO PC0006",
  },
  {
    row: { opcode: 219, A: 2, N: 5, Q: 8 },
    text: "CLOSE_OPEN_UPVALUES(from_register=1); RETURN R[8]",
  },
  {
    row: { opcode: 230, A: 2, N: 5, Q: 8, modeA: 2, constantA: 1 },
    text: "R[5] = R[8] % C0001",
  },
  { row: { opcode: 250, A: 2, N: 5, Q: 8 }, text: "R[2] = R[8] * R[5]" },
  {
    row: { opcode: 252, A: 2, N: 5, Q: 8, modeN: 2, constantN: 1 },
    text: "R[2] = R[8] - C0001",
  },
  { row: { opcode: 253, A: 2, N: 5, Q: 8 }, text: "R[8][R[5]] = R[2]" },
  {
    row: { opcode: 255, A: 2, N: 5, Q: 8, modeA: 2, constantA: 1 },
    text: "R[8] = (R[5] < C0001)",
  },
  {
    row: { opcode: 259, A: 2, N: 5, Q: 8 },
    text: "R[8] = CALL(R[8]); VM_TOP = 8",
  },
  {
    row: { opcode: 263, A: 2, N: 5, Q: 8, modeQ: 2, constantQ: 1 },
    text: "R[5] = C0001 - R[2]",
  },
  {
    row: { opcode: 266, A: 2, N: 5, Q: 8, modeA: 2, constantA: 1 },
    text: "R[5] = R[8] * C0001",
  },
  { row: { opcode: 267, A: 2, N: 5, Q: 8 }, text: "R[8] = UPVALUE(2).VALUE" },
];

const PROTOCOL_RENDER_CASES: readonly {
  readonly row: TestInstruction;
  readonly text: string;
}[] = [
  {
    row: { opcode: 39, A: 2, N: 5, Q: 8 },
    text: "VM_PROTOCOL R[2] = N_OPERAND_STREAM",
  },
  {
    row: { opcode: 52, A: 2, N: 5, Q: 8 },
    text: "VM_STATE.d = 2; VM_STATE.v = 8",
  },
  {
    row: { opcode: 56, A: 2, N: 5, Q: 8 },
    text: "REQUIRE_VM_STATE(s,f); VM_STATE.s = VM_STATE.s[VM_STATE.f]",
  },
  {
    row: { opcode: 81, A: 2, N: 5, Q: 8 },
    text: "VM_STATE.d = REGISTER_FILE; VM_STATE.v = 8",
  },
  {
    row: { opcode: 91, A: 2, N: 5, Q: 8, modeA: 2, constantA: 1 },
    text: "REQUIRE_VM_STATE(d,v); VM_STATE.s = C0001; VM_STATE.d[VM_STATE.v] = VM_STATE.s",
  },
  {
    row: { opcode: 98, A: 2, N: 5, Q: 8 },
    text: "REQUIRE_VM_STATE(loop_frame); LOOP_INDEX = LOOP_FRAME.index; LOOP_LIMIT = LOOP_FRAME.limit; LOOP_STEP = LOOP_FRAME.step; LOOP_FRAME = LOOP_FRAME.parent",
  },
  {
    row: { opcode: 203, A: 2, N: 5, Q: 8 },
    text: "VM_STATE.d = REGISTER_FILE; VM_STATE.v = 5",
  },
  {
    row: { opcode: 244, A: 2, N: 5, Q: 8, modeA: 2, constantA: 1 },
    text: "VM_STATE.f = C0001",
  },
  {
    row: { opcode: 277, A: 2, N: 5, Q: 8 },
    text: "REQUIRE_VM_STATE(d,v,s,f); VM_STATE.s = VM_STATE.s[VM_STATE.f]; VM_STATE.d[VM_STATE.v] = VM_STATE.s",
  },
  {
    row: { opcode: 282, A: 2, N: 5, Q: 8 },
    text: "R[2] = CAPTURE_CELLS[5] (cell_object, not_value)",
  },
];

function numberColumn(rows: readonly TestInstruction[], pick: (row: TestInstruction) => number): Float64Array {
  return Float64Array.from(rows.map(pick));
}

function optionalColumn(
  rows: readonly TestInstruction[],
  pick: (row: TestInstruction) => number | undefined,
): Float64Array {
  return Float64Array.from(rows.map((row) => pick(row) ?? Number.NaN));
}

function instructionColumns(
  rows: readonly TestInstruction[],
  byteStart: number,
): JnkieInstructionColumns {
  const byteOffsets = Uint32Array.from(rows.map((_, index) => byteStart + index * 4));
  const byteEnds = Uint32Array.from(byteOffsets, (value) => value + 4);
  const wordStart = (offset: number): Uint32Array =>
    Uint32Array.from(byteOffsets, (value) => value + offset);
  const wordEnd = (offset: number): Uint32Array =>
    Uint32Array.from(byteOffsets, (value) => value + offset + 1);
  const modeA = Uint8Array.from(rows.map((row) => row.modeA ?? 0));
  const modeN = Uint8Array.from(rows.map((row) => row.modeN ?? 0));
  const modeQ = Uint8Array.from(rows.map((row) => row.modeQ ?? 0));
  return {
    count: rows.length,
    rawWordA: numberColumn(rows, (row) => row.A * 8 + (row.modeA ?? 0)),
    rawOpcode: numberColumn(rows, (row) => row.opcode),
    rawWordN: numberColumn(rows, (row) => row.N * 8 + (row.modeN ?? 0)),
    rawWordQ: numberColumn(rows, (row) => row.Q * 8 + (row.modeQ ?? 0)),
    payloadA: numberColumn(rows, (row) => row.A),
    payloadN: numberColumn(rows, (row) => row.N),
    payloadQ: numberColumn(rows, (row) => row.Q),
    modeA,
    modeN,
    modeQ,
    resolvedA: optionalColumn(rows, (row) => row.resolvedA),
    resolvedN: optionalColumn(rows, (row) => row.resolvedN),
    resolvedQ: optionalColumn(rows, (row) => row.resolvedQ),
    constantIndexA: optionalColumn(rows, (row) => row.constantA),
    constantIndexN: optionalColumn(rows, (row) => row.constantN),
    constantIndexQ: optionalColumn(rows, (row) => row.constantQ),
    childPrototypeIndexA: optionalColumn(rows, () => undefined),
    childPrototypeIndexN: optionalColumn(rows, () => undefined),
    childPrototypeIndexQ: optionalColumn(rows, () => undefined),
    byteStart: byteOffsets,
    byteEnd: byteEnds,
    wordAByteStart: wordStart(0),
    wordAByteEnd: wordEnd(0),
    opcodeByteStart: wordStart(1),
    opcodeByteEnd: wordEnd(1),
    wordNByteStart: wordStart(2),
    wordNByteEnd: wordEnd(2),
    wordQByteStart: wordStart(3),
    wordQByteEnd: wordEnd(3),
  };
}

function prototype(
  index: number,
  byteStart: number,
  rows: readonly TestInstruction[],
  selector = 0,
): JnkieDecodedPrototype {
  const instructions = instructionColumns(rows, byteStart + 1);
  return {
    index,
    byteRange: { start: byteStart, end: byteStart + 1 + rows.length * 4 + 4 },
    instructionCountByteRange: { start: byteStart, end: byteStart + 1 },
    selectorByteRange: { start: byteStart + rows.length * 4 + 1, end: byteStart + rows.length * 4 + 2 },
    captureCountByteRange: { start: byteStart + rows.length * 4 + 2, end: byteStart + rows.length * 4 + 3 },
    maxStackByteRange: { start: byteStart + rows.length * 4 + 3, end: byteStart + rows.length * 4 + 4 },
    instructionCount: rows.length,
    instructions,
    selector,
    captures: [],
    maxStack: 8,
  };
}

function section(
  index: number,
  kind: JnkieRecordSection["kind"],
  prototypes: readonly JnkieDecodedPrototype[],
  rootPrototypeIndex: number,
): JnkieRecordSection {
  const instructionCount = prototypes.reduce((sum, item) => sum + item.instructionCount, 0);
  const start = prototypes[0]!.byteRange.start - 4;
  const end = prototypes[prototypes.length - 1]!.byteRange.end + 1;
  const rootPrototype = prototypes.find((item) => item.index === rootPrototypeIndex)!;
  return {
    index,
    kind,
    byteRange: { start, end },
    constantCountByteRange: { start, end: start + 1 },
    wrappedConstantsByteRange: { start: start + 1, end: start + 2 },
    prototypeCountByteRange: { start: start + 2, end: start + 3 },
    rootPrototypeIndexByteRange: { start: end - 1, end },
    wrappedConstants: false,
    constants: index === 1
      ? [
          {
            index: 1,
            tag: 110,
            kind: "string",
            byteRange: { start, end: start + 1 },
            tagByteRange: { start, end: start + 1 },
            payloadByteRange: { start: start + 1, end: start + 1 },
            encodedBase64: "bg==",
            valueBase64: "b2s=",
            byteLength: 2,
            utf8Text: "ok",
            latin1Text: "ok",
          },
        ]
      : [],
    prototypes,
    rootPrototypeIndex,
    rootPrototype,
    statistics: {
      byteLength: end - start,
      constantCount: index === 1 ? 1 : 0,
      prototypeCount: prototypes.length,
      instructionCount,
      captureCount: 0,
      constantReferenceCount: index === 1 ? 1 : 0,
      stringConstantReferenceCount: index === 1 ? 1 : 0,
      resolvedConstantReferenceCount: index === 1 ? 1 : 0,
      unresolvedConstantReferenceCount: 0,
      prototypeReferenceCount: 0,
      resolvedPrototypeReferenceCount: 0,
      unresolvedPrototypeReferenceCount: 0,
      rootPrototypeIndex,
      rootInstructionCount: rootPrototype.instructionCount,
    },
  };
}

function decodeFixture(options: {
  readonly nestedRows?: readonly TestInstruction[];
  readonly nestedSelector?: number;
} = {}): JnkieRecordDecodeResult {
  const outerP1 = prototype(1, 40, [{ opcode: 118, A: 0, N: 0, Q: 0 }]);
  const outerP2 = prototype(2, 80, [
    { opcode: 71, A: 1, N: 4, Q: 0, modeA: 2, constantA: 1 },
    { opcode: 280, A: 3, N: 5, Q: 7, modeA: 1, modeN: 3, modeQ: 6, resolvedA: 3 },
    { opcode: 166, A: 0, N: 0, Q: 0 },
  ]);
  const nestedP1 = prototype(
    1,
    200,
    options.nestedRows ?? [{ opcode: 187, A: 2, N: 9, Q: 0 }],
    options.nestedSelector ?? 0,
  );
  const outer = section(1, "outer-loader", [outerP1, outerP2], 2);
  const nested = section(2, "nested-payload", [nestedP1], 1);
  return {
    schemaVersion: 1,
    format: JNKIE_RECORD_FORMAT,
    constantCountByteRange: outer.constantCountByteRange,
    wrappedConstantsByteRange: outer.wrappedConstantsByteRange,
    prototypeCountByteRange: outer.prototypeCountByteRange,
    rootPrototypeIndexByteRange: outer.rootPrototypeIndexByteRange,
    sections: [outer, nested],
    primarySection: outer,
    semanticSection: nested,
    unresolvedRegions: [
      {
        kind: "interstitial-prelude",
        byteRange: { start: outer.byteRange.end, end: nested.byteRange.start },
        byteLength: nested.byteRange.start - outer.byteRange.end,
        previewHex: "0001",
      },
    ],
    wrappedConstants: nested.wrappedConstants,
    constants: nested.constants,
    prototypes: nested.prototypes,
    rootPrototypeIndex: nested.rootPrototypeIndex,
    rootPrototype: nested.rootPrototype,
    decodedByteRange: { start: outer.byteRange.start, end: nested.byteRange.end },
    trailingRegion: {
      byteRange: { start: nested.byteRange.end, end: nested.byteRange.end },
      byteLength: 0,
      previewHex: "",
    },
    statistics: {
      sectionCount: 2,
      inputBytes: nested.byteRange.end,
      decodedBytes: outer.statistics.byteLength + nested.statistics.byteLength,
      unresolvedBytes: nested.byteRange.start - outer.byteRange.end,
      trailingBytes: 0,
      constantCount: 1,
      prototypeCount: 3,
      instructionCount: outer.statistics.instructionCount + nested.statistics.instructionCount,
      constantReferenceCount: 1,
      stringConstantReferenceCount: 1,
      resolvedConstantReferenceCount: 1,
      unresolvedConstantReferenceCount: 0,
      prototypeReferenceCount: 0,
      resolvedPrototypeReferenceCount: 0,
      unresolvedPrototypeReferenceCount: 0,
      rootPrototypeIndex: 1,
      rootInstructionCount: 1,
    },
    diagnostics: [],
    safety: {
      submittedCodeExecution: "never",
      decodeMode: "bounded-static-record-reader",
    },
  };
}

describe("JNKIE conservative semantic emitter", () => {
  it("gates the handler map to the exact known loader hash", () => {
    const emission = emitKnownJnkieSemanticPseudocode(decodeFixture(), {
      loaderSha256: "0".repeat(64),
      payloadSha256: "1".repeat(64),
    });
    expect(emission.status).toBe("not-applicable");
  });

  it("emits both sections root-first with honest partitioned coverage", () => {
    const emission = emitKnownJnkieSemanticPseudocode(decodeFixture(), {
      loaderSha256: KNOWN_JNKIE_LOADER_SHA256,
      payloadSha256: "1".repeat(64),
    });
    expect(emission.status).toBe("emitted");
    if (emission.status !== "emitted") return;

    expect(emission.coverage).toMatchObject({
      sectionCount: 2,
      prototypeCount: 3,
      totalInstructionRecords: 5,
      provenSemanticInstructions: 3,
      decoderProtocolInstructions: 1,
      rawUnresolvedInstructions: 1,
      statefulMicroInstructions: 1,
    });
    expect(emission.coverage.sections.map((item) => item.sectionIndex)).toEqual([1, 2]);
    expect(emission.prototypeOrder).toEqual([
      { sectionIndex: 1, prototypeIndices: [2, 1] },
      { sectionIndex: 2, prototypeIndices: [1] },
    ]);
    expect(emission.compactIncludedInstructionRecords).toBe(5);
    expect(emission.compactOmittedInstructionRecords).toBe(0);
    expect(emission.compactByteLength).toBeLessThanOrEqual(JNKIE_UI_PSEUDOCODE_MAX_BYTES);
  });

  it("keeps unknown channels and byte provenance in the complete gzip artifact", () => {
    const identity = {
      loaderSha256: KNOWN_JNKIE_LOADER_SHA256,
      payloadSha256: "1".repeat(64),
    };
    const first = emitKnownJnkieSemanticPseudocode(decodeFixture(), identity);
    const second = emitKnownJnkieSemanticPseudocode(decodeFixture(), identity);
    expect(first.status).toBe("emitted");
    expect(second.status).toBe("emitted");
    if (first.status !== "emitted" || second.status !== "emitted") return;

    expect(first.fullArtifact.bytes).toEqual(second.fullArtifact.bytes);
    expect(first.fullArtifact.bytes[4]).toBe(0);
    expect(first.fullArtifact.bytes[9]).toBe(255);
    const full = gunzipSync(first.fullArtifact.bytes).toString("utf8");
    expect(full).toContain("SECTION S01 [outer-loader]");
    expect(full.indexOf("PROTOTYPE P002 [ROOT]")).toBeLessThan(
      full.indexOf("PROTOTYPE P001"),
    );
    expect(full).toContain("R[4] = C0001");
    expect(full).toContain("VM_PROTOCOL_CAPTURE_INCOMING_VARARGS()");
    expect(full).toContain("VM_OP_raw(op=280");
    expect(full).toContain("A=[25,1,3,3,null,null,85,86]");
    expect(full).toContain("N=[43,3,5,null,null,null,87,88]");
    expect(full).toContain("Q=[62,6,7,null,null,null,88,89]");
    expect(full).toContain("semantic_effect=unresolved");
    expect(full).toContain("not recovered original Lua/Luau source");
    expect(full).toContain("submitted_code_execution: never");
  });

  it("renders the exact selector-zero direct handlers with operand directions and modes", () => {
    const emission = emitKnownJnkieSemanticPseudocode(
      decodeFixture({ nestedRows: DIRECT_RENDER_CASES.map((item) => item.row) }),
      {
        loaderSha256: KNOWN_JNKIE_LOADER_SHA256,
        payloadSha256: "1".repeat(64),
      },
    );
    expect(emission.status).toBe("emitted");
    if (emission.status !== "emitted") return;

    expect(emission.coverage.sections[1]).toMatchObject({
      totalInstructionRecords: DIRECT_RENDER_CASES.length,
      provenSemanticInstructions: DIRECT_RENDER_CASES.length,
      decoderProtocolInstructions: 0,
      rawUnresolvedInstructions: 0,
    });
    const full = gunzipSync(emission.fullArtifact.bytes).toString("utf8");
    for (const candidate of DIRECT_RENDER_CASES) {
      expect(full, `missing opcode ${candidate.row.opcode}`).toContain(candidate.text);
    }
    expect(JNKIE_PROVEN_SEMANTIC_OPCODES).toEqual([
      1, 5, 9, 10, 14, 20, 21, 22, 25, 34, 36, 41, 50, 58, 59, 62, 69,
      71, 72, 73, 75, 77, 79, 84, 87, 97, 105, 118, 120, 123, 125, 126, 127,
      129, 131, 135, 136, 137, 138, 143, 144, 147, 150, 154, 155, 161, 162,
      164, 176, 187, 188, 192, 193, 198, 199, 208, 212, 215, 216, 219, 230, 233,
      250, 251, 252, 253, 255, 259, 263, 266, 267, 271,
    ]);
  });

  it("labels exact VM state transfers as protocol effects with prerequisites", () => {
    const emission = emitKnownJnkieSemanticPseudocode(
      decodeFixture({ nestedRows: PROTOCOL_RENDER_CASES.map((item) => item.row) }),
      {
        loaderSha256: KNOWN_JNKIE_LOADER_SHA256,
        payloadSha256: "1".repeat(64),
      },
    );
    expect(emission.status).toBe("emitted");
    if (emission.status !== "emitted") return;

    expect(emission.coverage.sections[1]).toMatchObject({
      totalInstructionRecords: PROTOCOL_RENDER_CASES.length,
      provenSemanticInstructions: 0,
      decoderProtocolInstructions: PROTOCOL_RENDER_CASES.length,
      rawUnresolvedInstructions: 0,
    });
    const full = gunzipSync(emission.fullArtifact.bytes).toString("utf8");
    for (const candidate of PROTOCOL_RENDER_CASES) {
      expect(full, `missing protocol opcode ${candidate.row.opcode}`).toContain(
        candidate.text,
      );
    }
    expect(JNKIE_PROTOCOL_OPCODES).toEqual([
      39, 51, 52, 56, 81, 91, 98, 166, 203, 238, 239, 244, 247, 248, 277,
      282,
    ]);
  });

  it("keeps selector-three raw opcodes outside the selector-zero handler map", () => {
    const emission = emitKnownJnkieSemanticPseudocode(
      decodeFixture({
        nestedRows: [
          { opcode: 1, A: 2, N: 5, Q: 8 },
          { opcode: 5, A: 2, N: 5, Q: 8 },
        ],
        nestedSelector: 3,
      }),
      {
        loaderSha256: KNOWN_JNKIE_LOADER_SHA256,
        payloadSha256: "1".repeat(64),
      },
    );
    expect(emission.status).toBe("emitted");
    if (emission.status !== "emitted") return;

    expect(emission.coverage.sections[1]).toMatchObject({
      totalInstructionRecords: 2,
      provenSemanticInstructions: 0,
      decoderProtocolInstructions: 0,
      rawUnresolvedInstructions: 2,
    });
    const full = gunzipSync(emission.fullArtifact.bytes).toString("utf8");
    expect(full).toContain("selector: 3");
    expect(full).toContain("VM_OP_raw(op=1");
    expect(full).toContain("VM_OP_raw(op=5");
    expect(full).not.toContain("handler=NEW_TABLE_WITH_ARRAY_CAPACITY");
    expect(full).not.toContain("handler=COMPARE_REG_NE_REG");
  });

  it("covers every record in both sections of the supplied JNKIE stream when available", { timeout: 30_000 }, () => {
    const fixture = join(
      process.cwd(),
      "outputs",
      "jnkie_payload_results_v04_verified",
      "6b164acc-72d6-4c29-a4de-0de6c7843a8b",
      "jnkie-payload.bin",
    );
    if (!existsSync(fixture)) return;
    const decoded = decodeJnkieRecordStream(readFileSync(fixture), {
      requireNestedSection: true,
    });
    const emission = emitKnownJnkieSemanticPseudocode(decoded, {
      loaderSha256: KNOWN_JNKIE_LOADER_SHA256,
      payloadSha256: KNOWN_JNKIE_PAYLOAD_SHA256,
    });
    expect(emission.status).toBe("emitted");
    if (emission.status !== "emitted") return;

    expect(emission.coverage).toMatchObject({
      sectionCount: 2,
      prototypeCount: 902,
      totalInstructionRecords: 261_864,
      provenSemanticInstructions: 239_010,
      decoderProtocolInstructions: 15_781,
      rawUnresolvedInstructions: 7_073,
      statefulMicroInstructions: 1_482,
      fusedSemanticInstructions: 5,
    });
    expect(emission.coverage.sections.map((item) => item.totalInstructionRecords)).toEqual([
      34_696,
      227_168,
    ]);
    expect(
      emission.coverage.provenSemanticInstructions +
        emission.coverage.decoderProtocolInstructions +
        emission.coverage.rawUnresolvedInstructions,
    ).toBe(261_864);
    expect(emission.compactIncludedInstructionRecords).toBeGreaterThan(0);
    expect(
      emission.compactIncludedInstructionRecords + emission.compactOmittedInstructionRecords,
    ).toBe(261_864);
    expect(emission.compactByteLength).toBeLessThanOrEqual(JNKIE_UI_PSEUDOCODE_MAX_BYTES);
    expect(emission.compactTruncated).toBe(true);
    expect(emission.fullArtifact.uncompressedByteLength).toBeGreaterThan(
      emission.compactByteLength,
    );
    expect(emission.fullArtifact.compressedByteLength).toBeLessThan(
      emission.fullArtifact.uncompressedByteLength,
    );
  });
});
