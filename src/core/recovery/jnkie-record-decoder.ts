import {
  JNKIE_RECORD_FORMAT,
  KNOWN_JNKIE_RECORD_INVARIANTS,
  type JnkieBooleanConstant,
  type JnkieBufferConstant,
  type JnkieByteRange,
  type JnkieCaptureDescriptor,
  type JnkieDecodedConstant,
  type JnkieDecodedPrototype,
  type JnkieFloatConstant,
  type JnkieInstructionColumns,
  type JnkieIntegerConstant,
  type JnkieIntegerEncoding,
  type JnkieRecordDecodeResult,
  type JnkieRecordFormat,
  type JnkieRecordSection,
  type JnkieRecordSectionKind,
  type JnkieRecordSectionStatistics,
  type JnkieStringConstant,
} from "./jnkie-record-model";

const MAX_SAFE_BIGINT = BigInt(Number.MAX_SAFE_INTEGER);
const TWO_TO_32 = 4_294_967_296;
const TWO_TO_32_BIGINT = 4_294_967_296n;
const MAX_DIAGNOSTICS = 128;

export interface JnkieRecordDecodeLimits {
  readonly maxInputBytes: number;
  readonly maxConstants: number;
  readonly maxConstantValueBytes: number;
  readonly maxPrototypes: number;
  readonly maxInstructionsPerPrototype: number;
  readonly maxInstructionsTotal: number;
  readonly maxCapturesPerPrototype: number;
  readonly maxCapturesTotal: number;
}

export interface JnkieRecordDecodeOptions {
  readonly limits?: Partial<JnkieRecordDecodeLimits>;
  /** Resolved per-build count biases; defaults to the 14.7 profile. */
  readonly format?: JnkieRecordFormat;
  readonly rejectTrailingBytes?: boolean;
  /** Known format uses a 400-byte opaque prelude before its nested section. */
  readonly nestedSectionPreludeBytes?: number;
  readonly decodeNestedSection?: boolean;
  readonly requireNestedSection?: boolean;
}

export type JnkieRecordDecodeErrorCode =
  | "INPUT_LIMIT"
  | "TRUNCATED"
  | "ULEB_OVERFLOW"
  | "INVALID_COUNT"
  | "COUNT_LIMIT"
  | "VALUE_LIMIT"
  | "INVALID_ROOT"
  | "NESTED_SECTION"
  | "TRAILING_BYTES"
  | "KNOWN_INVARIANT_MISMATCH";

export class JnkieRecordDecodeError extends Error {
  readonly code: JnkieRecordDecodeErrorCode;
  readonly offset: number;
  readonly field: string;

  constructor(
    code: JnkieRecordDecodeErrorCode,
    offset: number,
    field: string,
    message: string,
  ) {
    super(`${message} (field ${field}, byte ${offset})`);
    this.name = "JnkieRecordDecodeError";
    this.code = code;
    this.offset = offset;
    this.field = field;
  }
}

/** Internal marker so an aggregate limit cannot be mistaken for an invalid optional section. */
class JnkieAggregateCountLimitError extends JnkieRecordDecodeError {}

interface ReadValue<T> {
  readonly value: T;
  readonly byteRange: JnkieByteRange;
}

const DEFAULT_LIMITS: JnkieRecordDecodeLimits = Object.freeze({
  maxInputBytes: 256 * 1_024 * 1_024,
  maxConstants: 1_000_000,
  maxConstantValueBytes: 64 * 1_024 * 1_024,
  maxPrototypes: 100_000,
  maxInstructionsPerPrototype: 1_000_000,
  maxInstructionsTotal: 4_000_000,
  maxCapturesPerPrototype: 1_000_000,
  maxCapturesTotal: 2_000_000,
});

function checkedLimit(value: number, name: string): number {
  if (!Number.isSafeInteger(value) || value < 0) {
    throw new TypeError(`${name} must be a non-negative safe integer.`);
  }
  return value;
}

function resolveLimits(
  partial: Partial<JnkieRecordDecodeLimits> | undefined,
): JnkieRecordDecodeLimits {
  return {
    maxInputBytes: checkedLimit(
      partial?.maxInputBytes ?? DEFAULT_LIMITS.maxInputBytes,
      "maxInputBytes",
    ),
    maxConstants: checkedLimit(
      partial?.maxConstants ?? DEFAULT_LIMITS.maxConstants,
      "maxConstants",
    ),
    maxConstantValueBytes: checkedLimit(
      partial?.maxConstantValueBytes ?? DEFAULT_LIMITS.maxConstantValueBytes,
      "maxConstantValueBytes",
    ),
    maxPrototypes: checkedLimit(
      partial?.maxPrototypes ?? DEFAULT_LIMITS.maxPrototypes,
      "maxPrototypes",
    ),
    maxInstructionsPerPrototype: checkedLimit(
      partial?.maxInstructionsPerPrototype ??
        DEFAULT_LIMITS.maxInstructionsPerPrototype,
      "maxInstructionsPerPrototype",
    ),
    maxInstructionsTotal: checkedLimit(
      partial?.maxInstructionsTotal ?? DEFAULT_LIMITS.maxInstructionsTotal,
      "maxInstructionsTotal",
    ),
    maxCapturesPerPrototype: checkedLimit(
      partial?.maxCapturesPerPrototype ??
        DEFAULT_LIMITS.maxCapturesPerPrototype,
      "maxCapturesPerPrototype",
    ),
    maxCapturesTotal: checkedLimit(
      partial?.maxCapturesTotal ?? DEFAULT_LIMITS.maxCapturesTotal,
      "maxCapturesTotal",
    ),
  };
}

class BoundedReader {
  readonly bytes: Uint8Array;
  readonly view: DataView;
  offset = 0;

  constructor(bytes: Uint8Array, initialOffset = 0) {
    this.bytes = bytes;
    this.view = new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength);
    if (
      !Number.isSafeInteger(initialOffset) ||
      initialOffset < 0 ||
      initialOffset > bytes.byteLength
    ) {
      throw new RangeError("Initial reader offset is outside the input.");
    }
    this.offset = initialOffset;
  }

  private require(length: number, field: string): void {
    if (
      !Number.isSafeInteger(length) ||
      length < 0 ||
      this.offset + length > this.bytes.byteLength
    ) {
      throw new JnkieRecordDecodeError(
        "TRUNCATED",
        this.offset,
        field,
        `Need ${length} byte(s), but only ${this.bytes.byteLength - this.offset} remain`,
      );
    }
  }

  readU8(field: string): ReadValue<number> {
    const start = this.offset;
    this.require(1, field);
    const value = this.view.getUint8(this.offset);
    this.offset += 1;
    return { value, byteRange: { start, end: this.offset } };
  }

  readI16(field: string): ReadValue<number> {
    return this.readFixedNumber(field, 2, (offset) =>
      this.view.getInt16(offset, true),
    );
  }

  readU16(field: string): ReadValue<number> {
    return this.readFixedNumber(field, 2, (offset) =>
      this.view.getUint16(offset, true),
    );
  }

  readI32(field: string): ReadValue<number> {
    return this.readFixedNumber(field, 4, (offset) =>
      this.view.getInt32(offset, true),
    );
  }

  readU32(field: string): ReadValue<number> {
    return this.readFixedNumber(field, 4, (offset) =>
      this.view.getUint32(offset, true),
    );
  }

  readF32(field: string): ReadValue<number> {
    return this.readFixedNumber(field, 4, (offset) =>
      this.view.getFloat32(offset, true),
    );
  }

  readF64(field: string): ReadValue<number> {
    return this.readFixedNumber(field, 8, (offset) =>
      this.view.getFloat64(offset, true),
    );
  }

  private readFixedNumber(
    field: string,
    length: number,
    read: (offset: number) => number,
  ): ReadValue<number> {
    const start = this.offset;
    this.require(length, field);
    const value = read(this.offset);
    this.offset += length;
    return { value, byteRange: { start, end: this.offset } };
  }

  readBytes(length: number, field: string): ReadValue<Uint8Array> {
    const start = this.offset;
    this.require(length, field);
    this.offset += length;
    return {
      value: this.bytes.subarray(start, this.offset),
      byteRange: { start, end: this.offset },
    };
  }

  /**
   * Read the loader's base-128 little-endian integer without bitwise
   * truncation. Eight bytes cover all JavaScript safe integers; a ninth
   * continuation can never contribute to a signed-53-bit value.
   */
  readUleb53(field: string): ReadValue<number> {
    const start = this.offset;
    let value = 0n;
    let shift = 0n;
    for (let index = 0; index < 8; index += 1) {
      const byte = this.readU8(field).value;
      value += BigInt(byte & 0x7f) << shift;
      if (value > MAX_SAFE_BIGINT) {
        throw new JnkieRecordDecodeError(
          "ULEB_OVERFLOW",
          start,
          field,
          "ULEB value exceeds the exact signed-53-bit integer domain",
        );
      }
      if (byte < 0x80) {
        return {
          value: Number(value),
          byteRange: { start, end: this.offset },
        };
      }
      shift += 7n;
    }
    throw new JnkieRecordDecodeError(
      "ULEB_OVERFLOW",
      start,
      field,
      "ULEB uses more than eight bytes",
    );
  }

  base64(range: JnkieByteRange): string {
    return Buffer.from(this.bytes.subarray(range.start, range.end)).toString(
      "base64",
    );
  }

  hex(range: JnkieByteRange): string {
    return Buffer.from(this.bytes.subarray(range.start, range.end)).toString(
      "hex",
    );
  }
}

function countAfterBias(
  encoded: ReadValue<number>,
  bias: number,
  limit: number,
  field: string,
): number {
  const value = encoded.value - bias;
  if (!Number.isSafeInteger(value) || value < 0) {
    throw new JnkieRecordDecodeError(
      "INVALID_COUNT",
      encoded.byteRange.start,
      field,
      `Encoded count ${encoded.value} is below bias ${bias}`,
    );
  }
  if (value > limit) {
    throw new JnkieRecordDecodeError(
      "COUNT_LIMIT",
      encoded.byteRange.start,
      field,
      `Decoded count ${value} exceeds configured limit ${limit}`,
    );
  }
  return value;
}

function aggregateCountAfter(
  totalBefore: number,
  count: number,
  limit: number,
  offset: number,
  field: string,
  label: string,
): number {
  if (count > limit - totalBefore) {
    const attemptedTotal = BigInt(totalBefore) + BigInt(count);
    throw new JnkieAggregateCountLimitError(
      "COUNT_LIMIT",
      offset,
      field,
      `Aggregate ${label} count ${attemptedTotal.toString()} exceeds configured limit ${limit}`,
    );
  }
  return totalBefore + count;
}

function exactInteger(
  reader: BoundedReader,
  index: number,
  tag: number,
  start: number,
  tagByteRange: JnkieByteRange,
  payload: ReadValue<number>,
  encoding: JnkieIntegerEncoding,
  exact: bigint = BigInt(payload.value),
): JnkieIntegerConstant {
  const byteRange = { start, end: reader.offset };
  return {
    index,
    tag,
    kind: "integer",
    encoding,
    value: payload.value,
    exactDecimal: exact.toString(10),
    byteRange,
    tagByteRange,
    payloadByteRange: payload.byteRange,
    encodedBase64: reader.base64(byteRange),
  };
}

function displayFloat(value: number): string {
  if (Number.isNaN(value)) return "NaN";
  if (value === Number.POSITIVE_INFINITY) return "+Infinity";
  if (value === Number.NEGATIVE_INFINITY) return "-Infinity";
  if (Object.is(value, -0)) return "-0";
  return String(value);
}

function floatConstant(
  reader: BoundedReader,
  index: number,
  tag: number,
  start: number,
  tagByteRange: JnkieByteRange,
  payload: ReadValue<number>,
  encoding: "f32" | "f64",
): JnkieFloatConstant {
  const byteRange = { start, end: reader.offset };
  return {
    index,
    tag,
    kind: "float",
    encoding,
    value: payload.value,
    ieee754Hex: reader.hex(payload.byteRange),
    displayValue: displayFloat(payload.value),
    byteRange,
    tagByteRange,
    payloadByteRange: payload.byteRange,
    encodedBase64: reader.base64(byteRange),
  };
}

function decodeByteText(bytes: Uint8Array): {
  readonly utf8Text: string | null;
  readonly latin1Text: string;
} {
  let utf8Text: string | null = null;
  try {
    utf8Text = new TextDecoder("utf-8", { fatal: true }).decode(bytes);
  } catch {
    // Lua strings are byte strings; invalid UTF-8 is valid evidence.
  }
  return {
    utf8Text,
    latin1Text: Buffer.from(bytes).toString("latin1"),
  };
}

function readLengthPrefixedBytes(
  reader: BoundedReader,
  limits: JnkieRecordDecodeLimits,
  field: string,
): { readonly value: Uint8Array; readonly byteRange: JnkieByteRange } {
  const start = reader.offset;
  const length = reader.readUleb53(`${field}.length`).value;
  if (length > limits.maxConstantValueBytes) {
    throw new JnkieRecordDecodeError(
      "VALUE_LIMIT",
      start,
      field,
      `Constant value length ${length} exceeds configured limit ${limits.maxConstantValueBytes}`,
    );
  }
  const bytes = reader.readBytes(length, `${field}.bytes`);
  return { value: bytes.value, byteRange: { start, end: bytes.byteRange.end } };
}

function decodeConstant(
  reader: BoundedReader,
  limits: JnkieRecordDecodeLimits,
  index: number,
): JnkieDecodedConstant {
  const start = reader.offset;
  const tagRead = reader.readU8(`constants[${index}].tag`);
  const tag = tagRead.value;
  const field = `constants[${index}].value`;

  if (tag <= 6) {
    const raw = reader.readU8(field);
    const value = -raw.value;
    return exactInteger(
      reader,
      index,
      tag,
      start,
      tagRead.byteRange,
      { value, byteRange: raw.byteRange },
      "negative-u8",
    );
  }
  if (tag <= 48) {
    const value = reader.readI16(field);
    return exactInteger(
      reader,
      index,
      tag,
      start,
      tagRead.byteRange,
      value,
      "i16",
    );
  }
  if (tag === 49) {
    const low = reader.readU32(`${field}.low`);
    const high = reader.readU32(`${field}.high`);
    const highSigned = high.value >= 0x8000_0000
      ? high.value - TWO_TO_32
      : high.value;
    const exact = BigInt(highSigned) * TWO_TO_32_BIGINT + BigInt(low.value);
    const runtimeValue = highSigned * TWO_TO_32 + low.value;
    return exactInteger(
      reader,
      index,
      tag,
      start,
      tagRead.byteRange,
      {
        value: runtimeValue,
        byteRange: { start: low.byteRange.start, end: high.byteRange.end },
      },
      "signed-two-u32",
      exact,
    );
  }
  if (tag <= 103) {
    const value = reader.readI32(field);
    return exactInteger(
      reader,
      index,
      tag,
      start,
      tagRead.byteRange,
      value,
      "i32",
    );
  }
  if (tag <= 109) {
    const byteRange = { start, end: reader.offset };
    const value: JnkieBooleanConstant = {
      index,
      tag,
      kind: "boolean",
      value: true,
      byteRange,
      tagByteRange: tagRead.byteRange,
      payloadByteRange: { start: reader.offset, end: reader.offset },
      encodedBase64: reader.base64(byteRange),
    };
    return value;
  }
  if (tag === 110) {
    const payload = readLengthPrefixedBytes(reader, limits, field);
    const text = decodeByteText(payload.value);
    const byteRange = { start, end: reader.offset };
    const value: JnkieStringConstant = {
      index,
      tag,
      kind: "string",
      valueBase64: Buffer.from(payload.value).toString("base64"),
      byteLength: payload.value.byteLength,
      utf8Text: text.utf8Text,
      latin1Text: text.latin1Text,
      byteRange,
      tagByteRange: tagRead.byteRange,
      payloadByteRange: payload.byteRange,
      encodedBase64: reader.base64(byteRange),
    };
    return value;
  }
  if (tag <= 131) {
    const value = reader.readU8(field);
    return exactInteger(
      reader,
      index,
      tag,
      start,
      tagRead.byteRange,
      value,
      "u8",
    );
  }
  if (tag <= 153) {
    return floatConstant(
      reader,
      index,
      tag,
      start,
      tagRead.byteRange,
      reader.readF64(field),
      "f64",
    );
  }
  if (tag === 154) {
    const value = reader.readU32(field);
    return exactInteger(
      reader,
      index,
      tag,
      start,
      tagRead.byteRange,
      value,
      "u32",
    );
  }
  if (tag <= 179) {
    const value = reader.readU16(field);
    return exactInteger(
      reader,
      index,
      tag,
      start,
      tagRead.byteRange,
      value,
      "u16",
    );
  }
  if (tag === 180) {
    const byteRange = { start, end: reader.offset };
    const value: JnkieBooleanConstant = {
      index,
      tag,
      kind: "boolean",
      value: false,
      byteRange,
      tagByteRange: tagRead.byteRange,
      payloadByteRange: { start: reader.offset, end: reader.offset },
      encodedBase64: reader.base64(byteRange),
    };
    return value;
  }
  if (tag <= 220) {
    return floatConstant(
      reader,
      index,
      tag,
      start,
      tagRead.byteRange,
      reader.readF32(field),
      "f32",
    );
  }

  const payload = readLengthPrefixedBytes(reader, limits, field);
  const byteRange = { start, end: reader.offset };
  const value: JnkieBufferConstant = {
    index,
    tag,
    kind: "buffer",
    valueBase64: Buffer.from(payload.value).toString("base64"),
    byteLength: payload.value.byteLength,
    byteRange,
    tagByteRange: tagRead.byteRange,
    payloadByteRange: payload.byteRange,
    encodedBase64: reader.base64(byteRange),
  };
  return value;
}

function nanArray(length: number): Float64Array {
  const values = new Float64Array(length);
  values.fill(Number.NaN);
  return values;
}

function createInstructionColumns(count: number): JnkieInstructionColumns {
  return {
    count,
    rawWordA: new Float64Array(count),
    rawOpcode: new Float64Array(count),
    rawWordN: new Float64Array(count),
    rawWordQ: new Float64Array(count),
    payloadA: new Float64Array(count),
    payloadN: new Float64Array(count),
    payloadQ: new Float64Array(count),
    modeA: new Uint8Array(count),
    modeN: new Uint8Array(count),
    modeQ: new Uint8Array(count),
    resolvedA: nanArray(count),
    resolvedN: nanArray(count),
    resolvedQ: nanArray(count),
    constantIndexA: nanArray(count),
    constantIndexN: nanArray(count),
    constantIndexQ: nanArray(count),
    childPrototypeIndexA: nanArray(count),
    childPrototypeIndexN: nanArray(count),
    childPrototypeIndexQ: nanArray(count),
    byteStart: new Uint32Array(count),
    byteEnd: new Uint32Array(count),
    wordAByteStart: new Uint32Array(count),
    wordAByteEnd: new Uint32Array(count),
    opcodeByteStart: new Uint32Array(count),
    opcodeByteEnd: new Uint32Array(count),
    wordNByteStart: new Uint32Array(count),
    wordNByteEnd: new Uint32Array(count),
    wordQByteStart: new Uint32Array(count),
    wordQByteEnd: new Uint32Array(count),
  };
}

function assignChannel(
  mode: number,
  payload: number,
  pc: number,
  offset: number,
  resolved: Float64Array,
  constantIndex: Float64Array,
  childPrototypeIndex: Float64Array,
): void {
  if (mode === 2) {
    constantIndex[offset] = payload;
  } else if (mode === 4) {
    childPrototypeIndex[offset] = payload;
  } else if (mode === 3) {
    resolved[offset] = pc + payload;
  } else if (mode === 6) {
    resolved[offset] = pc - payload;
  } else {
    // Modes 0, 1, 5, and 7 retain their numeric payload unchanged.
    resolved[offset] = payload;
  }
}

function readInstructionColumns(
  reader: BoundedReader,
  prototypeIndex: number,
  count: number,
): JnkieInstructionColumns {
  const columns = createInstructionColumns(count);
  for (let offset = 0; offset < count; offset += 1) {
    const pc = offset + 1;
    const prefix = `prototypes[${prototypeIndex}].instructions[${pc}]`;
    const start = reader.offset;
    const wordA = reader.readUleb53(`${prefix}.wordA`);
    const opcode = reader.readUleb53(`${prefix}.opcode`);
    const wordN = reader.readUleb53(`${prefix}.wordN`);
    const wordQ = reader.readUleb53(`${prefix}.wordQ`);
    const modeA = wordA.value % 8;
    const modeN = wordN.value % 8;
    const modeQ = wordQ.value % 8;
    const payloadA = Math.floor(wordA.value / 8);
    const payloadN = Math.floor(wordN.value / 8);
    const payloadQ = Math.floor(wordQ.value / 8);

    columns.rawWordA[offset] = wordA.value;
    columns.rawOpcode[offset] = opcode.value;
    columns.rawWordN[offset] = wordN.value;
    columns.rawWordQ[offset] = wordQ.value;
    columns.payloadA[offset] = payloadA;
    columns.payloadN[offset] = payloadN;
    columns.payloadQ[offset] = payloadQ;
    columns.modeA[offset] = modeA;
    columns.modeN[offset] = modeN;
    columns.modeQ[offset] = modeQ;
    columns.byteStart[offset] = start;
    columns.byteEnd[offset] = reader.offset;
    columns.wordAByteStart[offset] = wordA.byteRange.start;
    columns.wordAByteEnd[offset] = wordA.byteRange.end;
    columns.opcodeByteStart[offset] = opcode.byteRange.start;
    columns.opcodeByteEnd[offset] = opcode.byteRange.end;
    columns.wordNByteStart[offset] = wordN.byteRange.start;
    columns.wordNByteEnd[offset] = wordN.byteRange.end;
    columns.wordQByteStart[offset] = wordQ.byteRange.start;
    columns.wordQByteEnd[offset] = wordQ.byteRange.end;

    assignChannel(
      modeA,
      payloadA,
      pc,
      offset,
      columns.resolvedA,
      columns.constantIndexA,
      columns.childPrototypeIndexA,
    );
    assignChannel(
      modeN,
      payloadN,
      pc,
      offset,
      columns.resolvedN,
      columns.constantIndexN,
      columns.childPrototypeIndexN,
    );
    assignChannel(
      modeQ,
      payloadQ,
      pc,
      offset,
      columns.resolvedQ,
      columns.constantIndexQ,
      columns.childPrototypeIndexQ,
    );
  }
  return columns;
}

function decodePrototype(
  reader: BoundedReader,
  limits: JnkieRecordDecodeLimits,
  format: JnkieRecordFormat,
  index: number,
  totalInstructionsBefore: number,
  totalCapturesBefore: number,
): {
  readonly prototype: JnkieDecodedPrototype;
  readonly totalInstructions: number;
  readonly totalCaptures: number;
} {
  const start = reader.offset;
  const countRead = reader.readUleb53(
    `prototypes[${index}].instructionCount`,
  );
  const instructionCount = countAfterBias(
    countRead,
    format.instructionCountBias,
    limits.maxInstructionsPerPrototype,
    `prototypes[${index}].instructionCount`,
  );
  const totalInstructions = aggregateCountAfter(
    totalInstructionsBefore,
    instructionCount,
    limits.maxInstructionsTotal,
    countRead.byteRange.start,
    `prototypes[${index}].instructionCount`,
    "instruction",
  );
  const instructions = readInstructionColumns(
    reader,
    index,
    instructionCount,
  );
  const selector = reader.readUleb53(`prototypes[${index}].selector`);
  const captureCountRead = reader.readUleb53(
    `prototypes[${index}].captureCount`,
  );
  const captureCount = captureCountRead.value;
  if (captureCount > limits.maxCapturesPerPrototype) {
    throw new JnkieRecordDecodeError(
      "COUNT_LIMIT",
      captureCountRead.byteRange.start,
      `prototypes[${index}].captureCount`,
      `Capture count ${captureCount} exceeds configured limit ${limits.maxCapturesPerPrototype}`,
    );
  }
  const totalCaptures = aggregateCountAfter(
    totalCapturesBefore,
    captureCount,
    limits.maxCapturesTotal,
    captureCountRead.byteRange.start,
    `prototypes[${index}].captureCount`,
    "capture",
  );
  const captures: JnkieCaptureDescriptor[] = [];
  for (let captureOffset = 0; captureOffset < captureCount; captureOffset += 1) {
    const encoded = reader.readUleb53(
      `prototypes[${index}].captures[${captureOffset + 1}]`,
    );
    captures.push({
      index: captureOffset + 1,
      encoded: encoded.value,
      kind: encoded.value % 4,
      sourceIndex: Math.floor(encoded.value / 4),
      byteRange: encoded.byteRange,
    });
  }
  const maxStack = reader.readUleb53(`prototypes[${index}].maxStack`);
  const prototype: JnkieDecodedPrototype = {
    index,
    byteRange: { start, end: reader.offset },
    instructionCountByteRange: countRead.byteRange,
    selectorByteRange: selector.byteRange,
    captureCountByteRange: captureCountRead.byteRange,
    maxStackByteRange: maxStack.byteRange,
    instructionCount,
    instructions,
    selector: selector.value,
    captures,
    maxStack: maxStack.value,
  };
  return { prototype, totalInstructions, totalCaptures };
}

function appendDiagnostic(diagnostics: string[], message: string): void {
  if (diagnostics.length < MAX_DIAGNOSTICS) diagnostics.push(message);
}

function inspectReferences(
  constants: readonly JnkieDecodedConstant[],
  prototypes: readonly JnkieDecodedPrototype[],
  diagnostics: string[],
): {
  readonly constantReferenceCount: number;
  readonly stringConstantReferenceCount: number;
  readonly resolvedConstantReferenceCount: number;
  readonly unresolvedConstantReferenceCount: number;
  readonly prototypeReferenceCount: number;
  readonly resolvedPrototypeReferenceCount: number;
  readonly unresolvedPrototypeReferenceCount: number;
} {
  let constantReferenceCount = 0;
  let stringConstantReferenceCount = 0;
  let resolvedConstantReferenceCount = 0;
  let unresolvedConstantReferenceCount = 0;
  let prototypeReferenceCount = 0;
  let resolvedPrototypeReferenceCount = 0;
  let unresolvedPrototypeReferenceCount = 0;
  const channelNames = ["A", "N", "Q"] as const;

  for (const prototype of prototypes) {
    const columns = prototype.instructions;
    const constantColumns = [
      columns.constantIndexA,
      columns.constantIndexN,
      columns.constantIndexQ,
    ] as const;
    const childColumns = [
      columns.childPrototypeIndexA,
      columns.childPrototypeIndexN,
      columns.childPrototypeIndexQ,
    ] as const;
    for (let offset = 0; offset < columns.count; offset += 1) {
      for (let channelOffset = 0; channelOffset < 3; channelOffset += 1) {
        const constantIndex = constantColumns[channelOffset]![offset]!;
        if (!Number.isNaN(constantIndex)) {
          constantReferenceCount += 1;
          const constant = Number.isInteger(constantIndex) && constantIndex >= 1
            ? constants[constantIndex - 1]
            : undefined;
          if (constant) {
            resolvedConstantReferenceCount += 1;
            if (constant.kind === "string") stringConstantReferenceCount += 1;
          } else {
            unresolvedConstantReferenceCount += 1;
            appendDiagnostic(
              diagnostics,
              `Prototype ${prototype.index}, PC ${offset + 1}, ${channelNames[channelOffset]} references missing constant ${constantIndex}.`,
            );
          }
        }
        const childIndex = childColumns[channelOffset]![offset]!;
        if (!Number.isNaN(childIndex)) {
          prototypeReferenceCount += 1;
          if (
            Number.isInteger(childIndex) &&
            childIndex >= 1 &&
            childIndex <= prototypes.length
          ) {
            resolvedPrototypeReferenceCount += 1;
          } else {
            unresolvedPrototypeReferenceCount += 1;
            appendDiagnostic(
              diagnostics,
              `Prototype ${prototype.index}, PC ${offset + 1}, ${channelNames[channelOffset]} references missing prototype ${childIndex}.`,
            );
          }
        }
      }
    }
  }
  return {
    constantReferenceCount,
    stringConstantReferenceCount,
    resolvedConstantReferenceCount,
    unresolvedConstantReferenceCount,
    prototypeReferenceCount,
    resolvedPrototypeReferenceCount,
    unresolvedPrototypeReferenceCount,
  };
}

function previewHex(bytes: Uint8Array, start: number): string {
  return Buffer.from(bytes.subarray(start, Math.min(bytes.length, start + 32))).toString(
    "hex",
  );
}

interface JnkieRecordAggregateCounts {
  readonly constantCount: number;
  readonly prototypeCount: number;
  readonly instructionCount: number;
  readonly captureCount: number;
}

const EMPTY_AGGREGATE_COUNTS: JnkieRecordAggregateCounts = Object.freeze({
  constantCount: 0,
  prototypeCount: 0,
  instructionCount: 0,
  captureCount: 0,
});

function decodeSection(
  bytes: Uint8Array,
  limits: JnkieRecordDecodeLimits,
  format: JnkieRecordFormat,
  start: number,
  index: number,
  kind: JnkieRecordSectionKind,
  diagnostics: string[],
  aggregateCountsBefore: JnkieRecordAggregateCounts,
): JnkieRecordSection {
  const reader = new BoundedReader(bytes, start);
  const prefix = `sections[${index}]`;
  const constantCountRead = reader.readUleb53(`${prefix}.constantCount`);
  const constantCount = countAfterBias(
    constantCountRead,
    format.constantCountBias,
    limits.maxConstants,
    `${prefix}.constantCount`,
  );
  aggregateCountAfter(
    aggregateCountsBefore.constantCount,
    constantCount,
    limits.maxConstants,
    constantCountRead.byteRange.start,
    `${prefix}.constantCount`,
    "constant",
  );
  const wrappedRead = reader.readU8(`${prefix}.wrappedConstants`);
  const wrappedConstants = wrappedRead.value !== 0;
  const constants: JnkieDecodedConstant[] = [];
  for (let constantIndex = 1; constantIndex <= constantCount; constantIndex += 1) {
    constants.push(decodeConstant(reader, limits, constantIndex));
  }

  const prototypeCountRead = reader.readUleb53(`${prefix}.prototypeCount`);
  const prototypeCount = countAfterBias(
    prototypeCountRead,
    format.prototypeCountBias,
    limits.maxPrototypes,
    `${prefix}.prototypeCount`,
  );
  aggregateCountAfter(
    aggregateCountsBefore.prototypeCount,
    prototypeCount,
    limits.maxPrototypes,
    prototypeCountRead.byteRange.start,
    `${prefix}.prototypeCount`,
    "prototype",
  );
  const prototypes: JnkieDecodedPrototype[] = [];
  let aggregateInstructionCount = aggregateCountsBefore.instructionCount;
  let aggregateCaptureCount = aggregateCountsBefore.captureCount;
  for (let prototypeIndex = 1; prototypeIndex <= prototypeCount; prototypeIndex += 1) {
    const decoded = decodePrototype(
      reader,
      limits,
      format,
      prototypeIndex,
      aggregateInstructionCount,
      aggregateCaptureCount,
    );
    prototypes.push(decoded.prototype);
    aggregateInstructionCount = decoded.totalInstructions;
    aggregateCaptureCount = decoded.totalCaptures;
  }
  const instructionCount =
    aggregateInstructionCount - aggregateCountsBefore.instructionCount;
  const captureCount = aggregateCaptureCount - aggregateCountsBefore.captureCount;

  const rootRead = reader.readUleb53(`${prefix}.rootPrototypeIndex`);
  const rootPrototypeIndex = rootRead.value;
  const rootPrototype =
    Number.isInteger(rootPrototypeIndex) && rootPrototypeIndex >= 1
      ? prototypes[rootPrototypeIndex - 1]
      : undefined;
  if (!rootPrototype) {
    throw new JnkieRecordDecodeError(
      "INVALID_ROOT",
      rootRead.byteRange.start,
      `${prefix}.rootPrototypeIndex`,
      `Root prototype ${rootPrototypeIndex} is outside 1..${prototypes.length}`,
    );
  }

  const sectionDiagnostics: string[] = [];
  const referenceFacts = inspectReferences(
    constants,
    prototypes,
    sectionDiagnostics,
  );
  for (const message of sectionDiagnostics) {
    appendDiagnostic(diagnostics, `Section ${index}: ${message}`);
  }
  const byteRange = { start, end: reader.offset };
  const statistics: JnkieRecordSectionStatistics = {
    byteLength: byteRange.end - byteRange.start,
    constantCount,
    prototypeCount,
    instructionCount,
    captureCount,
    ...referenceFacts,
    rootPrototypeIndex,
    rootInstructionCount: rootPrototype.instructionCount,
  };
  return {
    index,
    kind,
    byteRange,
    constantCountByteRange: constantCountRead.byteRange,
    wrappedConstantsByteRange: wrappedRead.byteRange,
    prototypeCountByteRange: prototypeCountRead.byteRange,
    rootPrototypeIndexByteRange: rootRead.byteRange,
    wrappedConstants,
    constants,
    prototypes,
    rootPrototypeIndex,
    rootPrototype,
    statistics,
  };
}

function sumSectionStatistic(
  sections: readonly JnkieRecordSection[],
  field:
    | "byteLength"
    | "constantCount"
    | "prototypeCount"
    | "instructionCount"
    | "constantReferenceCount"
    | "stringConstantReferenceCount"
    | "resolvedConstantReferenceCount"
    | "unresolvedConstantReferenceCount"
    | "prototypeReferenceCount"
    | "resolvedPrototypeReferenceCount"
    | "unresolvedPrototypeReferenceCount",
): number {
  return sections.reduce((sum, section) => sum + section.statistics[field], 0);
}

/**
 * Decode the recovered JNKIE payload as data. This function never imports,
 * evaluates, or invokes submitted Lua/Luau or a native decoder sidecar.
 */
export function decodeJnkieRecordStream(
  bytes: Uint8Array,
  options: JnkieRecordDecodeOptions = {},
): JnkieRecordDecodeResult {
  const limits = resolveLimits(options.limits);
  if (bytes.byteLength > limits.maxInputBytes || bytes.byteLength > 0xffff_ffff) {
    throw new JnkieRecordDecodeError(
      "INPUT_LIMIT",
      0,
      "input",
      `Input length ${bytes.byteLength} exceeds the bounded decoder limit`,
    );
  }
  const preludeBytes = checkedLimit(
    options.nestedSectionPreludeBytes ?? 400,
    "nestedSectionPreludeBytes",
  );
  const format = options.format ?? JNKIE_RECORD_FORMAT;
  const diagnostics: string[] = [];
  const primarySection = decodeSection(
    bytes,
    limits,
    format,
    0,
    1,
    "outer-loader",
    diagnostics,
    EMPTY_AGGREGATE_COUNTS,
  );
  const sections: JnkieRecordSection[] = [primarySection];
  let nestedFailure: JnkieRecordDecodeError | undefined;
  const nestedStart = primarySection.byteRange.end + preludeBytes;
  if (
    options.decodeNestedSection !== false &&
    nestedStart < bytes.byteLength
  ) {
    try {
      sections.push(
        decodeSection(
          bytes,
          limits,
          format,
          nestedStart,
          2,
          "nested-payload",
          diagnostics,
          {
            constantCount: primarySection.statistics.constantCount,
            prototypeCount: primarySection.statistics.prototypeCount,
            instructionCount: primarySection.statistics.instructionCount,
            captureCount: primarySection.statistics.captureCount,
          },
        ),
      );
    } catch (error) {
      if (!(error instanceof JnkieRecordDecodeError)) throw error;
      if (error instanceof JnkieAggregateCountLimitError) throw error;
      nestedFailure = error;
      appendDiagnostic(
        diagnostics,
        `A candidate nested section at byte ${nestedStart} was not accepted: ${error.message}`,
      );
    }
  }
  if (options.requireNestedSection === true && sections.length < 2) {
    throw new JnkieRecordDecodeError(
      "NESTED_SECTION",
      nestedStart,
      "nestedSection",
      nestedFailure?.message ?? "Required nested record section is absent",
    );
  }

  const semanticSection = sections[sections.length - 1]!;
  const unresolvedRegions: {
    kind: "interstitial-prelude" | "trailing-data";
    byteRange: JnkieByteRange;
    byteLength: number;
    previewHex: string;
  }[] = [];
  if (sections.length > 1 && preludeBytes > 0) {
    const range = {
      start: primarySection.byteRange.end,
      end: semanticSection.byteRange.start,
    };
    unresolvedRegions.push({
      kind: "interstitial-prelude",
      byteRange: range,
      byteLength: range.end - range.start,
      previewHex: previewHex(bytes, range.start),
    });
    appendDiagnostic(
      diagnostics,
      `${range.end - range.start} interstitial prelude byte(s) at [${range.start}, ${range.end}) remain opaque; both surrounding record sections are structurally decoded.`,
    );
  }
  const lastSectionEnd = semanticSection.byteRange.end;
  if (lastSectionEnd < bytes.byteLength) {
    const range = { start: lastSectionEnd, end: bytes.byteLength };
    unresolvedRegions.push({
      kind: "trailing-data",
      byteRange: range,
      byteLength: range.end - range.start,
      previewHex: previewHex(bytes, range.start),
    });
    appendDiagnostic(
      diagnostics,
      `${range.end - range.start} trailing byte(s) at [${range.start}, ${range.end}) remain unresolved.`,
    );
  }
  const trailingBytes = bytes.byteLength - lastSectionEnd;
  if (options.rejectTrailingBytes === true && trailingBytes !== 0) {
    throw new JnkieRecordDecodeError(
      "TRAILING_BYTES",
      lastSectionEnd,
      "trailingRegion",
      `Decoded record sections leave ${trailingBytes} trailing byte(s)`,
    );
  }
  const unresolvedBytes = unresolvedRegions.reduce(
    (sum, region) => sum + region.byteLength,
    0,
  );
  if (diagnostics.length === MAX_DIAGNOSTICS) {
    diagnostics.push("Additional reference diagnostics were omitted from this bounded list.");
  }

  return {
    schemaVersion: 1,
    format,
    constantCountByteRange: semanticSection.constantCountByteRange,
    wrappedConstantsByteRange: semanticSection.wrappedConstantsByteRange,
    prototypeCountByteRange: semanticSection.prototypeCountByteRange,
    rootPrototypeIndexByteRange: semanticSection.rootPrototypeIndexByteRange,
    sections,
    primarySection,
    semanticSection,
    unresolvedRegions,
    wrappedConstants: semanticSection.wrappedConstants,
    constants: semanticSection.constants,
    prototypes: semanticSection.prototypes,
    rootPrototypeIndex: semanticSection.rootPrototypeIndex,
    rootPrototype: semanticSection.rootPrototype,
    decodedByteRange: semanticSection.byteRange,
    trailingRegion: {
      byteRange: { start: lastSectionEnd, end: bytes.byteLength },
      byteLength: trailingBytes,
      previewHex: previewHex(bytes, lastSectionEnd),
    },
    statistics: {
      sectionCount: sections.length,
      inputBytes: bytes.byteLength,
      decodedBytes: sumSectionStatistic(sections, "byteLength"),
      unresolvedBytes,
      trailingBytes,
      constantCount: sumSectionStatistic(sections, "constantCount"),
      prototypeCount: sumSectionStatistic(sections, "prototypeCount"),
      instructionCount: sumSectionStatistic(sections, "instructionCount"),
      constantReferenceCount: sumSectionStatistic(
        sections,
        "constantReferenceCount",
      ),
      stringConstantReferenceCount: sumSectionStatistic(
        sections,
        "stringConstantReferenceCount",
      ),
      resolvedConstantReferenceCount: sumSectionStatistic(
        sections,
        "resolvedConstantReferenceCount",
      ),
      unresolvedConstantReferenceCount: sumSectionStatistic(
        sections,
        "unresolvedConstantReferenceCount",
      ),
      prototypeReferenceCount: sumSectionStatistic(
        sections,
        "prototypeReferenceCount",
      ),
      resolvedPrototypeReferenceCount: sumSectionStatistic(
        sections,
        "resolvedPrototypeReferenceCount",
      ),
      unresolvedPrototypeReferenceCount: sumSectionStatistic(
        sections,
        "unresolvedPrototypeReferenceCount",
      ),
      rootPrototypeIndex: semanticSection.rootPrototypeIndex,
      rootInstructionCount: semanticSection.rootPrototype.instructionCount,
    },
    diagnostics,
    safety: {
      submittedCodeExecution: "never",
      decodeMode: "bounded-static-record-reader",
    },
  };
}

function invariantMismatch(
  result: JnkieRecordDecodeResult,
  field: string,
  actual: number,
  expected: number,
): never {
  throw new JnkieRecordDecodeError(
    "KNOWN_INVARIANT_MISMATCH",
    result.semanticSection.byteRange.end,
    field,
    `Known-stream invariant ${field} is ${actual}, expected ${expected}`,
  );
}

/** Assert both exact record sections of the currently known JNKIE stream. */
export function assertKnownJnkieRecordInvariants(
  result: JnkieRecordDecodeResult,
): void {
  const expected = KNOWN_JNKIE_RECORD_INVARIANTS;
  const aggregateChecks: readonly [string, number, number][] = [
    ["inputBytes", result.statistics.inputBytes, expected.inputBytes],
    ["sectionCount", result.statistics.sectionCount, 2],
    ["decodedRecordBytes", result.statistics.decodedBytes, expected.decodedRecordBytes],
    ["unresolvedBytes", result.statistics.unresolvedBytes, expected.unresolvedBytes],
    ["trailingBytes", result.statistics.trailingBytes, 0],
  ];
  for (const [field, actual, wanted] of aggregateChecks) {
    if (actual !== wanted) invariantMismatch(result, field, actual, wanted);
  }
  const expectedSections = [expected.outer, expected.nested] as const;
  for (let sectionOffset = 0; sectionOffset < expectedSections.length; sectionOffset += 1) {
    const section = result.sections[sectionOffset];
    const wanted = expectedSections[sectionOffset]!;
    if (!section) invariantMismatch(result, `sections[${sectionOffset + 1}]`, 0, 1);
    const checks: readonly [string, number, number][] = [
      ["start", section.byteRange.start, wanted.start],
      ["end", section.byteRange.end, wanted.end],
      ["constantCount", section.statistics.constantCount, wanted.constantCount],
      ["prototypeCount", section.statistics.prototypeCount, wanted.prototypeCount],
      ["instructionCount", section.statistics.instructionCount, wanted.instructionCount],
      [
        "prototypeReferenceCount",
        section.statistics.prototypeReferenceCount,
        wanted.prototypeReferenceCount,
      ],
      ["rootPrototypeIndex", section.rootPrototypeIndex, wanted.rootPrototypeIndex],
      [
        "rootInstructionCount",
        section.rootPrototype.instructionCount,
        wanted.rootInstructionCount,
      ],
    ];
    for (const [field, actual, expectedValue] of checks) {
      if (actual !== expectedValue) {
        invariantMismatch(
          result,
          `sections[${sectionOffset + 1}].${field}`,
          actual,
          expectedValue,
        );
      }
    }
    if (
      section.statistics.unresolvedConstantReferenceCount !== 0 ||
      section.statistics.resolvedPrototypeReferenceCount !==
        wanted.prototypeReferenceCount ||
      section.statistics.unresolvedPrototypeReferenceCount !== 0
    ) {
      invariantMismatch(
        result,
        `sections[${sectionOffset + 1}].unresolvedReferences`,
        section.statistics.unresolvedConstantReferenceCount +
          section.statistics.unresolvedPrototypeReferenceCount,
        0,
      );
    }
  }
  const prelude = result.unresolvedRegions[0];
  if (
    !prelude ||
    prelude.kind !== "interstitial-prelude" ||
    prelude.byteRange.start !== expected.outer.end ||
    prelude.byteRange.end !== expected.nested.start ||
    result.unresolvedRegions.length !== 1
  ) {
    invariantMismatch(
      result,
      "interstitialPrelude",
      prelude?.byteLength ?? -1,
      expected.unresolvedBytes,
    );
  }
}
