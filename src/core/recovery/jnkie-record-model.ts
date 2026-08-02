/**
 * Static, lossless model for the serialized record stream consumed by the
 * known JNKIE loader.  All byte ranges are absolute, zero-based, half-open
 * ranges into the recovered payload.  All VM-facing indices and PCs remain
 * one-based so an artifact never silently changes the source convention.
 */

/**
 * Count biases are per-build obfuscation constants, not part of the container
 * design.  A second authorized sample uses the same ULEB framing with
 * different biases, so consumers may supply their own resolved format.
 */
export interface JnkieRecordFormat {
  readonly schemaVersion: 1;
  readonly constantCountBias: number;
  readonly prototypeCountBias: number;
  readonly instructionCountBias: number;
  readonly indexBase: 1;
  readonly byteRangeConvention: "zero-based-half-open";
}

export const JNKIE_RECORD_FORMAT: JnkieRecordFormat = Object.freeze({
  schemaVersion: 1 as const,
  constantCountBias: 60_177,
  prototypeCountBias: 29_334,
  instructionCountBias: 94_145,
  indexBase: 1 as const,
  byteRangeConvention: "zero-based-half-open" as const,
});

export const KNOWN_JNKIE_RECORD_INVARIANTS = Object.freeze({
  inputBytes: 2_284_927,
  decodedRecordBytes: 2_284_527,
  unresolvedBytes: 400,
  outer: Object.freeze({
    start: 0,
    end: 221_167,
    constantCount: 2_335,
    prototypeCount: 371,
    instructionCount: 34_696,
    prototypeReferenceCount: 370,
    rootPrototypeIndex: 302,
    rootInstructionCount: 1_409,
  }),
  nested: Object.freeze({
    start: 221_567,
    end: 2_284_927,
    constantCount: 14_572,
    prototypeCount: 531,
    instructionCount: 227_168,
    prototypeReferenceCount: 718,
    rootPrototypeIndex: 149,
    rootInstructionCount: 86_843,
  }),
});

export interface JnkieByteRange {
  readonly start: number;
  readonly end: number;
}

interface JnkieConstantBase {
  /** One-based position in the global constant pool. */
  readonly index: number;
  readonly tag: number;
  readonly byteRange: JnkieByteRange;
  readonly tagByteRange: JnkieByteRange;
  readonly payloadByteRange: JnkieByteRange;
  /** Exact bytes of the complete tag-plus-payload record. */
  readonly encodedBase64: string;
}

export type JnkieIntegerEncoding =
  | "negative-u8"
  | "i16"
  | "signed-two-u32"
  | "i32"
  | "u8"
  | "u16"
  | "u32";

export interface JnkieIntegerConstant extends JnkieConstantBase {
  readonly kind: "integer";
  readonly encoding: JnkieIntegerEncoding;
  /** Loader-compatible IEEE-754 value; may be rounded for integers over 2^53. */
  readonly value: number;
  /** Exact mathematical integer reconstructed from the serialized words. */
  readonly exactDecimal: string;
}

export interface JnkieFloatConstant extends JnkieConstantBase {
  readonly kind: "float";
  readonly encoding: "f32" | "f64";
  readonly value: number;
  /** Exact little-endian IEEE-754 payload, independent of JSON number rules. */
  readonly ieee754Hex: string;
  /** Stable rendering that preserves NaN, infinities, and negative zero. */
  readonly displayValue: string;
}

export interface JnkieBooleanConstant extends JnkieConstantBase {
  readonly kind: "boolean";
  readonly value: boolean;
}

export interface JnkieStringConstant extends JnkieConstantBase {
  readonly kind: "string";
  /** Exact Lua string bytes (without the encoded length prefix). */
  readonly valueBase64: string;
  readonly byteLength: number;
  /** UTF-8 text only when the complete byte sequence is valid UTF-8. */
  readonly utf8Text: string | null;
  /** One-code-point-per-byte rendering for forensic display. */
  readonly latin1Text: string;
}

export interface JnkieBufferConstant extends JnkieConstantBase {
  readonly kind: "buffer";
  readonly valueBase64: string;
  readonly byteLength: number;
}

export type JnkieDecodedConstant =
  | JnkieIntegerConstant
  | JnkieFloatConstant
  | JnkieBooleanConstant
  | JnkieStringConstant
  | JnkieBufferConstant;

/** Backwards-friendly descriptive alias for integrations. */
export type JnkieConstantRecord = JnkieDecodedConstant;

export interface JnkieCaptureDescriptor {
  /** One-based capture slot within this prototype. */
  readonly index: number;
  readonly encoded: number;
  readonly kind: number;
  readonly sourceIndex: number;
  readonly byteRange: JnkieByteRange;
}

export type JnkieOperandName = "A" | "N" | "Q";

export interface JnkieInstructionChannel {
  readonly mode: number;
  readonly payload: number;
  /** Numeric value after applying absolute/relative modes, else null. */
  readonly resolvedValue: number | null;
  /** One-based global constant-pool index for mode 2, else null. */
  readonly constantIndex: number | null;
  /** One-based prototype index for mode 4, else null. */
  readonly childPrototypeIndex: number | null;
}

/**
 * Efficient storage for every instruction in a prototype.  Float64Array is
 * intentional: the serialized ULEB words are safe signed-53-bit integers and
 * must not be truncated through JavaScript bitwise operators.
 */
export interface JnkieInstructionColumns {
  readonly count: number;
  readonly rawWordA: Float64Array;
  readonly rawOpcode: Float64Array;
  readonly rawWordN: Float64Array;
  readonly rawWordQ: Float64Array;
  readonly payloadA: Float64Array;
  readonly payloadN: Float64Array;
  readonly payloadQ: Float64Array;
  readonly modeA: Uint8Array;
  readonly modeN: Uint8Array;
  readonly modeQ: Uint8Array;
  readonly resolvedA: Float64Array;
  readonly resolvedN: Float64Array;
  readonly resolvedQ: Float64Array;
  readonly constantIndexA: Float64Array;
  readonly constantIndexN: Float64Array;
  readonly constantIndexQ: Float64Array;
  readonly childPrototypeIndexA: Float64Array;
  readonly childPrototypeIndexN: Float64Array;
  readonly childPrototypeIndexQ: Float64Array;
  readonly byteStart: Uint32Array;
  readonly byteEnd: Uint32Array;
  readonly wordAByteStart: Uint32Array;
  readonly wordAByteEnd: Uint32Array;
  readonly opcodeByteStart: Uint32Array;
  readonly opcodeByteEnd: Uint32Array;
  readonly wordNByteStart: Uint32Array;
  readonly wordNByteEnd: Uint32Array;
  readonly wordQByteStart: Uint32Array;
  readonly wordQByteEnd: Uint32Array;
}

export interface JnkieDecodedInstruction {
  readonly pc: number;
  readonly rawOpcode: number;
  readonly byteRange: JnkieByteRange;
  readonly wordByteRanges: readonly [
    JnkieByteRange,
    JnkieByteRange,
    JnkieByteRange,
    JnkieByteRange,
  ];
  readonly rawWords: readonly [number, number, number, number];
  readonly channels: Readonly<{
    A: JnkieInstructionChannel;
    N: JnkieInstructionChannel;
    Q: JnkieInstructionChannel;
  }>;
}

/** Backwards-friendly descriptive alias for integrations. */
export type JnkieInstructionRecord = JnkieDecodedInstruction;

export interface JnkieDecodedPrototype {
  /** One-based prototype position in stream order. */
  readonly index: number;
  readonly byteRange: JnkieByteRange;
  readonly instructionCountByteRange: JnkieByteRange;
  readonly selectorByteRange: JnkieByteRange;
  readonly captureCountByteRange: JnkieByteRange;
  readonly maxStackByteRange: JnkieByteRange;
  readonly instructionCount: number;
  readonly instructions: JnkieInstructionColumns;
  /** Loader dispatch selector; semantics are separate from decoding. */
  readonly selector: number;
  readonly captures: readonly JnkieCaptureDescriptor[];
  readonly maxStack: number;
}

export interface JnkieRecordStatistics {
  readonly sectionCount: number;
  readonly inputBytes: number;
  readonly decodedBytes: number;
  readonly unresolvedBytes: number;
  readonly trailingBytes: number;
  readonly constantCount: number;
  readonly prototypeCount: number;
  readonly instructionCount: number;
  readonly constantReferenceCount: number;
  readonly stringConstantReferenceCount: number;
  readonly resolvedConstantReferenceCount: number;
  readonly unresolvedConstantReferenceCount: number;
  readonly prototypeReferenceCount: number;
  readonly resolvedPrototypeReferenceCount: number;
  readonly unresolvedPrototypeReferenceCount: number;
  readonly rootPrototypeIndex: number;
  readonly rootInstructionCount: number;
}

export interface JnkieRecordSectionStatistics {
  readonly byteLength: number;
  readonly constantCount: number;
  readonly prototypeCount: number;
  readonly instructionCount: number;
  readonly captureCount: number;
  readonly constantReferenceCount: number;
  readonly stringConstantReferenceCount: number;
  readonly resolvedConstantReferenceCount: number;
  readonly unresolvedConstantReferenceCount: number;
  readonly prototypeReferenceCount: number;
  readonly resolvedPrototypeReferenceCount: number;
  readonly unresolvedPrototypeReferenceCount: number;
  readonly rootPrototypeIndex: number;
  readonly rootInstructionCount: number;
}

export type JnkieRecordSectionKind = "outer-loader" | "nested-payload";

export interface JnkieRecordSection {
  readonly index: number;
  readonly kind: JnkieRecordSectionKind;
  readonly byteRange: JnkieByteRange;
  readonly constantCountByteRange: JnkieByteRange;
  readonly wrappedConstantsByteRange: JnkieByteRange;
  readonly prototypeCountByteRange: JnkieByteRange;
  readonly rootPrototypeIndexByteRange: JnkieByteRange;
  readonly wrappedConstants: boolean;
  readonly constants: readonly JnkieDecodedConstant[];
  readonly prototypes: readonly JnkieDecodedPrototype[];
  readonly rootPrototypeIndex: number;
  readonly rootPrototype: JnkieDecodedPrototype;
  readonly statistics: JnkieRecordSectionStatistics;
}

export interface JnkieUnresolvedRegion {
  readonly kind: "interstitial-prelude" | "trailing-data";
  readonly byteRange: JnkieByteRange;
  readonly byteLength: number;
  readonly previewHex: string;
}

export interface JnkieTrailingRegion {
  readonly byteRange: JnkieByteRange;
  readonly byteLength: number;
  readonly previewHex: string;
}

export interface JnkieRecordDecodeResult {
  readonly schemaVersion: 1;
  readonly format: JnkieRecordFormat;
  readonly constantCountByteRange: JnkieByteRange;
  readonly wrappedConstantsByteRange: JnkieByteRange;
  readonly prototypeCountByteRange: JnkieByteRange;
  readonly rootPrototypeIndexByteRange: JnkieByteRange;
  readonly sections: readonly JnkieRecordSection[];
  readonly primarySection: JnkieRecordSection;
  readonly semanticSection: JnkieRecordSection;
  readonly unresolvedRegions: readonly JnkieUnresolvedRegion[];
  /** Aliases below point at semanticSection for consumers decoding payload logic. */
  readonly wrappedConstants: boolean;
  readonly constants: readonly JnkieDecodedConstant[];
  readonly prototypes: readonly JnkieDecodedPrototype[];
  readonly rootPrototypeIndex: number;
  readonly rootPrototype: JnkieDecodedPrototype;
  readonly decodedByteRange: JnkieByteRange;
  readonly trailingRegion: JnkieTrailingRegion;
  readonly statistics: JnkieRecordStatistics;
  readonly diagnostics: readonly string[];
  readonly safety: Readonly<{
    submittedCodeExecution: "never";
    decodeMode: "bounded-static-record-reader";
  }>;
}

function optionalIndex(value: number): number | null {
  return Number.isNaN(value) ? null : value;
}

function channelAt(
  mode: Uint8Array,
  payload: Float64Array,
  resolved: Float64Array,
  constantIndex: Float64Array,
  childPrototypeIndex: Float64Array,
  offset: number,
): JnkieInstructionChannel {
  return {
    mode: mode[offset]!,
    payload: payload[offset]!,
    resolvedValue: optionalIndex(resolved[offset]!),
    constantIndex: optionalIndex(constantIndex[offset]!),
    childPrototypeIndex: optionalIndex(childPrototypeIndex[offset]!),
  };
}

/** Materialize one one-based PC without expanding the complete column store. */
export function instructionAt(
  columns: JnkieInstructionColumns,
  pc: number,
): JnkieDecodedInstruction {
  if (!Number.isInteger(pc) || pc < 1 || pc > columns.count) {
    throw new RangeError(`Instruction PC ${pc} is outside 1..${columns.count}.`);
  }
  const offset = pc - 1;
  return {
    pc,
    rawOpcode: columns.rawOpcode[offset]!,
    byteRange: {
      start: columns.byteStart[offset]!,
      end: columns.byteEnd[offset]!,
    },
    wordByteRanges: [
      {
        start: columns.wordAByteStart[offset]!,
        end: columns.wordAByteEnd[offset]!,
      },
      {
        start: columns.opcodeByteStart[offset]!,
        end: columns.opcodeByteEnd[offset]!,
      },
      {
        start: columns.wordNByteStart[offset]!,
        end: columns.wordNByteEnd[offset]!,
      },
      {
        start: columns.wordQByteStart[offset]!,
        end: columns.wordQByteEnd[offset]!,
      },
    ],
    rawWords: [
      columns.rawWordA[offset]!,
      columns.rawOpcode[offset]!,
      columns.rawWordN[offset]!,
      columns.rawWordQ[offset]!,
    ],
    channels: {
      A: channelAt(
        columns.modeA,
        columns.payloadA,
        columns.resolvedA,
        columns.constantIndexA,
        columns.childPrototypeIndexA,
        offset,
      ),
      N: channelAt(
        columns.modeN,
        columns.payloadN,
        columns.resolvedN,
        columns.constantIndexN,
        columns.childPrototypeIndexN,
        offset,
      ),
      Q: channelAt(
        columns.modeQ,
        columns.payloadQ,
        columns.resolvedQ,
        columns.constantIndexQ,
        columns.childPrototypeIndexQ,
        offset,
      ),
    },
  };
}

export function* instructionsOf(
  prototype: JnkieDecodedPrototype,
): Generator<JnkieDecodedInstruction, void, undefined> {
  for (let pc = 1; pc <= prototype.instructionCount; pc += 1) {
    yield instructionAt(prototype.instructions, pc);
  }
}
