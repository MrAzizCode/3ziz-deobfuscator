/**
 * Bounded, static Lua 5.1 binary-chunk parsing and disassembly.
 *
 * This module never evaluates, repairs, normalizes, or re-serializes input.
 * Every decoded instruction and constant retains its exact source bytes.
 */

export const LUA51_SIGNATURE = Object.freeze([0x1b, 0x4c, 0x75, 0x61] as const);

export interface Lua51Limits {
  readonly maxInputBytes: number;
  readonly maxPrototypeDepth: number;
  readonly maxPrototypes: number;
  readonly maxChildPrototypesPerPrototype: number;
  readonly maxInstructionsPerPrototype: number;
  readonly maxInstructionsTotal: number;
  readonly maxConstantsPerPrototype: number;
  readonly maxConstantsTotal: number;
  readonly maxStringBytes: number;
  readonly maxStringBytesTotal: number;
  readonly maxLineInfoTotal: number;
  readonly maxLocalsTotal: number;
  readonly maxUpvalueNamesTotal: number;
  readonly maxDiagnostics: number;
  readonly maxAuditLines: number;
  readonly maxAuditChars: number;
}

export const DEFAULT_LUA51_LIMITS: Readonly<Lua51Limits> = Object.freeze({
  maxInputBytes: 10 * 1024 * 1024,
  maxPrototypeDepth: 64,
  maxPrototypes: 10_000,
  maxChildPrototypesPerPrototype: 10_000,
  maxInstructionsPerPrototype: 1_000_000,
  maxInstructionsTotal: 2_000_000,
  maxConstantsPerPrototype: 500_000,
  maxConstantsTotal: 1_000_000,
  maxStringBytes: 1024 * 1024,
  maxStringBytesTotal: 8 * 1024 * 1024,
  maxLineInfoTotal: 2_000_000,
  maxLocalsTotal: 250_000,
  maxUpvalueNamesTotal: 250_000,
  maxDiagnostics: 1_000,
  maxAuditLines: 500_000,
  maxAuditChars: 16 * 1024 * 1024,
});

export interface Lua51Options {
  readonly limits?: Partial<Lua51Limits>;
}

export type Lua51DiagnosticSeverity = "warning" | "error";

export interface Lua51Diagnostic {
  readonly code: string;
  readonly severity: Lua51DiagnosticSeverity;
  readonly message: string;
  readonly offset: number;
  readonly prototypePath: string | null;
  readonly pc: number | null;
}

export type Lua51Endianness = "little" | "big";
export type Lua51NumberKind = "float" | "integer";

export interface Lua51Header {
  readonly signatureHex: "1b4c7561";
  readonly version: 0x51;
  readonly format: 0;
  readonly endianness: Lua51Endianness;
  readonly intSize: number;
  readonly sizeTSize: number;
  readonly instructionSize: 4;
  readonly numberSize: number;
  readonly numberKind: Lua51NumberKind;
  readonly rawIntegralFlag: 0 | 1;
}

export interface Lua51String {
  /** Offset of the encoded size_t, not the first payload byte. */
  readonly offset: number;
  /** Exact string payload excluding the mandatory trailing NUL byte. */
  readonly bytes: Uint8Array;
  /** A convenience rendering only; exact consumers should use bytes. */
  readonly utf8: string;
}

export interface Lua51NilConstant {
  readonly type: "nil";
  readonly offset: number;
}

export interface Lua51BooleanConstant {
  readonly type: "boolean";
  readonly offset: number;
  readonly value: boolean;
  readonly rawValue: 0 | 1;
}

export interface Lua51NumberConstant {
  readonly type: "number";
  readonly offset: number;
  readonly kind: Lua51NumberKind;
  readonly value: number | bigint;
  readonly rawBytes: Uint8Array;
  readonly rawHex: string;
}

export interface Lua51StringConstant {
  readonly type: "string";
  readonly offset: number;
  readonly value: Lua51String;
}

export type Lua51Constant =
  | Lua51NilConstant
  | Lua51BooleanConstant
  | Lua51NumberConstant
  | Lua51StringConstant;

export type Lua51InstructionMode = "iABC" | "iABx" | "iAsBx" | "unknown";

export interface Lua51DecodedInstruction {
  readonly offset: number;
  readonly pc: number;
  readonly raw: number;
  readonly rawHex: string;
  readonly opcode: number;
  readonly opcodeName: string;
  readonly mode: Lua51InstructionMode;
  readonly A: number;
  readonly B: number;
  readonly C: number;
  readonly Bx: number;
  readonly sBx: number;
  /** Direct target for JMP/FORLOOP/FORPREP; otherwise null. */
  readonly branchTarget: number | null;
}

export interface Lua51LocalVariable {
  readonly name: Lua51String | null;
  readonly startPc: number;
  readonly endPc: number;
  readonly offset: number;
}

export interface Lua51Prototype {
  readonly path: string;
  readonly depth: number;
  readonly offset: number;
  readonly endOffset: number;
  readonly source: Lua51String | null;
  readonly lineDefined: number;
  readonly lastLineDefined: number;
  readonly upvalueCount: number;
  readonly parameterCount: number;
  readonly varargFlags: number;
  readonly maxStackSize: number;
  readonly instructions: readonly Lua51DecodedInstruction[];
  readonly constants: readonly Lua51Constant[];
  readonly prototypes: readonly Lua51Prototype[];
  readonly lineInfo: readonly number[];
  readonly locals: readonly Lua51LocalVariable[];
  readonly upvalueNames: readonly (Lua51String | null)[];
}

export interface Lua51ChunkStats {
  readonly prototypeCount: number;
  readonly instructionCount: number;
  readonly constantCount: number;
  readonly stringBytes: number;
  readonly lineInfoCount: number;
  readonly localCount: number;
  readonly upvalueNameCount: number;
}

export interface Lua51Chunk {
  readonly header: Lua51Header;
  readonly main: Lua51Prototype;
  readonly inputByteLength: number;
  readonly bytesConsumed: number;
  readonly stats: Lua51ChunkStats;
  readonly diagnostics: readonly Lua51Diagnostic[];
}

export type Lua51ParseResult =
  | {
      readonly ok: true;
      readonly chunk: Lua51Chunk;
      readonly diagnostics: readonly Lua51Diagnostic[];
      readonly bytesConsumed: number;
    }
  | {
      readonly ok: false;
      readonly chunk: Lua51Chunk | null;
      readonly diagnostics: readonly Lua51Diagnostic[];
      readonly bytesConsumed: number;
    };

export interface Lua51DisassemblyResult {
  readonly text: string;
  readonly diagnostics: readonly Lua51Diagnostic[];
  readonly truncated: boolean;
}

export interface Lua51InspectionResult {
  readonly ok: boolean;
  readonly chunk: Lua51Chunk | null;
  readonly auditText: string | null;
  readonly auditTruncated: boolean;
  readonly diagnostics: readonly Lua51Diagnostic[];
  readonly bytesConsumed: number;
}

interface OpcodeDescriptor {
  readonly name: string;
  readonly mode: Exclude<Lua51InstructionMode, "unknown">;
}

const OPCODES: readonly OpcodeDescriptor[] = Object.freeze([
  { name: "MOVE", mode: "iABC" },
  { name: "LOADK", mode: "iABx" },
  { name: "LOADBOOL", mode: "iABC" },
  { name: "LOADNIL", mode: "iABC" },
  { name: "GETUPVAL", mode: "iABC" },
  { name: "GETGLOBAL", mode: "iABx" },
  { name: "GETTABLE", mode: "iABC" },
  { name: "SETGLOBAL", mode: "iABx" },
  { name: "SETUPVAL", mode: "iABC" },
  { name: "SETTABLE", mode: "iABC" },
  { name: "NEWTABLE", mode: "iABC" },
  { name: "SELF", mode: "iABC" },
  { name: "ADD", mode: "iABC" },
  { name: "SUB", mode: "iABC" },
  { name: "MUL", mode: "iABC" },
  { name: "DIV", mode: "iABC" },
  { name: "MOD", mode: "iABC" },
  { name: "POW", mode: "iABC" },
  { name: "UNM", mode: "iABC" },
  { name: "NOT", mode: "iABC" },
  { name: "LEN", mode: "iABC" },
  { name: "CONCAT", mode: "iABC" },
  { name: "JMP", mode: "iAsBx" },
  { name: "EQ", mode: "iABC" },
  { name: "LT", mode: "iABC" },
  { name: "LE", mode: "iABC" },
  { name: "TEST", mode: "iABC" },
  { name: "TESTSET", mode: "iABC" },
  { name: "CALL", mode: "iABC" },
  { name: "TAILCALL", mode: "iABC" },
  { name: "RETURN", mode: "iABC" },
  { name: "FORLOOP", mode: "iAsBx" },
  { name: "FORPREP", mode: "iAsBx" },
  { name: "TFORLOOP", mode: "iABC" },
  { name: "SETLIST", mode: "iABC" },
  { name: "CLOSE", mode: "iABC" },
  { name: "CLOSURE", mode: "iABx" },
  { name: "VARARG", mode: "iABC" },
]);

const UTF8_DECODER = new TextDecoder("utf-8", { fatal: false });
const MAXARG_BX = 0x3ffff;
const MAXARG_SBX = MAXARG_BX >>> 1;
const BITRK = 1 << 8;
const MAXINDEXRK = BITRK - 1;

class ParseAbort {
  constructor(readonly diagnostic: Lua51Diagnostic) {}
}

class BoundedReader {
  offset = 0;

  constructor(
    readonly bytes: Uint8Array,
    private readonly abort: (
      code: string,
      message: string,
      offset: number,
    ) => never,
  ) {}

  get remaining(): number {
    return this.bytes.length - this.offset;
  }

  readByte(label: string): number {
    const offset = this.offset;
    if (this.remaining < 1) {
      this.abort(
        "LUA51_UNEXPECTED_EOF",
        `Unexpected end of input while reading ${label}; needed 1 byte.`,
        offset,
      );
    }
    const value = this.bytes[this.offset];
    this.offset += 1;
    return value ?? 0;
  }

  readBytes(count: number, label: string): Uint8Array {
    const offset = this.offset;
    if (!Number.isSafeInteger(count) || count < 0) {
      this.abort(
        "LUA51_INVALID_LENGTH",
        `Invalid byte length ${String(count)} while reading ${label}.`,
        offset,
      );
    }
    if (count > this.remaining) {
      this.abort(
        "LUA51_UNEXPECTED_EOF",
        `Unexpected end of input while reading ${label}; needed ${count} bytes, only ${this.remaining} remain.`,
        offset,
      );
    }
    const value = this.bytes.slice(this.offset, this.offset + count);
    this.offset += count;
    return value;
  }

  readUnsignedBig(
    size: number,
    endianness: Lua51Endianness,
    label: string,
  ): bigint {
    const bytes = this.readBytes(size, label);
    let value = 0n;
    if (endianness === "little") {
      for (let index = bytes.length - 1; index >= 0; index -= 1) {
        value = (value << 8n) | BigInt(bytes[index] ?? 0);
      }
    } else {
      for (const byte of bytes) {
        value = (value << 8n) | BigInt(byte);
      }
    }
    return value;
  }

  readSignedBig(
    size: number,
    endianness: Lua51Endianness,
    label: string,
  ): bigint {
    const unsigned = this.readUnsignedBig(size, endianness, label);
    const bitCount = BigInt(size * 8);
    const signBit = 1n << (bitCount - 1n);
    return (unsigned & signBit) === 0n ? unsigned : unsigned - (1n << bitCount);
  }
}

interface MutableStats {
  prototypeCount: number;
  instructionCount: number;
  constantCount: number;
  stringBytes: number;
  lineInfoCount: number;
  localCount: number;
  upvalueNameCount: number;
}

class Lua51Parser {
  private readonly reader: BoundedReader;
  private readonly diagnostics: Lua51Diagnostic[] = [];
  private diagnosticsSuppressed = false;
  private currentPrototypePath: string | null = null;
  private currentPc: number | null = null;
  private header: Lua51Header | null = null;
  private readonly stats: MutableStats = {
    prototypeCount: 0,
    instructionCount: 0,
    constantCount: 0,
    stringBytes: 0,
    lineInfoCount: 0,
    localCount: 0,
    upvalueNameCount: 0,
  };

  constructor(
    private readonly input: Uint8Array,
    private readonly limits: Readonly<Lua51Limits>,
  ) {
    this.reader = new BoundedReader(input, (code, message, offset) =>
      this.fail(code, message, offset),
    );
  }

  run(): Lua51ParseResult {
    try {
      const header = this.parseHeader();
      this.header = header;
      const main = this.parsePrototype("0", 0);

      if (this.reader.remaining !== 0) {
        this.addDiagnostic({
          code: "LUA51_TRAILING_BYTES",
          severity: "error",
          message: `${this.reader.remaining} trailing byte(s) remain after the main prototype.`,
          offset: this.reader.offset,
          prototypePath: null,
          pc: null,
        });
      }

      const diagnostics = this.finalDiagnostics();
      const stats: Lua51ChunkStats = { ...this.stats };
      const chunk: Lua51Chunk = {
        header,
        main,
        inputByteLength: this.input.length,
        bytesConsumed: this.reader.offset,
        stats,
        diagnostics,
      };
      const ok = !diagnostics.some(
        (diagnostic) => diagnostic.severity === "error",
      );
      if (ok) {
        return {
          ok: true,
          chunk,
          diagnostics,
          bytesConsumed: this.reader.offset,
        };
      }
      return {
        ok: false,
        chunk,
        diagnostics,
        bytesConsumed: this.reader.offset,
      };
    } catch (error: unknown) {
      if (!(error instanceof ParseAbort)) {
        throw error;
      }
      this.addDiagnostic(error.diagnostic);
      return {
        ok: false,
        chunk: null,
        diagnostics: this.finalDiagnostics(),
        bytesConsumed: this.reader.offset,
      };
    }
  }

  private parseHeader(): Lua51Header {
    const signatureOffset = this.reader.offset;
    const signature = this.reader.readBytes(4, "Lua signature");
    if (
      signature[0] !== LUA51_SIGNATURE[0] ||
      signature[1] !== LUA51_SIGNATURE[1] ||
      signature[2] !== LUA51_SIGNATURE[2] ||
      signature[3] !== LUA51_SIGNATURE[3]
    ) {
      this.fail(
        "LUA51_INVALID_SIGNATURE",
        `Expected Lua signature 1b4c7561, found ${bytesToHex(signature)}.`,
        signatureOffset,
      );
    }

    const versionOffset = this.reader.offset;
    const version = this.reader.readByte("version");
    if (version !== 0x51) {
      this.fail(
        "LUA51_UNSUPPORTED_VERSION",
        `Expected Lua 5.1 version byte 0x51, found 0x${hexByte(version)}.`,
        versionOffset,
      );
    }

    const formatOffset = this.reader.offset;
    const format = this.reader.readByte("format");
    if (format !== 0) {
      this.fail(
        "LUA51_UNSUPPORTED_FORMAT",
        `Expected official format 0, found ${format}.`,
        formatOffset,
      );
    }

    const endianOffset = this.reader.offset;
    const endianFlag = this.reader.readByte("endianness");
    if (endianFlag !== 0 && endianFlag !== 1) {
      this.fail(
        "LUA51_INVALID_ENDIANNESS",
        `Endianness byte must be 0 (big) or 1 (little), found ${endianFlag}.`,
        endianOffset,
      );
    }
    const endianness: Lua51Endianness =
      endianFlag === 1 ? "little" : "big";

    const intSizeOffset = this.reader.offset;
    const intSize = this.reader.readByte("sizeof(int)");
    this.requireIntegerScalarSize(intSize, "int", intSizeOffset);

    const sizeTOffset = this.reader.offset;
    const sizeTSize = this.reader.readByte("sizeof(size_t)");
    this.requireUnsignedScalarSize(sizeTSize, "size_t", sizeTOffset);

    const instructionSizeOffset = this.reader.offset;
    const instructionSize = this.reader.readByte("sizeof(Instruction)");
    if (instructionSize !== 4) {
      this.fail(
        "LUA51_UNSUPPORTED_INSTRUCTION_SIZE",
        `Lua 5.1 instructions must be 4 bytes for this decoder; header declares ${instructionSize}.`,
        instructionSizeOffset,
      );
    }

    const numberSizeOffset = this.reader.offset;
    const numberSize = this.reader.readByte("sizeof(lua_Number)");

    const integralOffset = this.reader.offset;
    const integralFlag = this.reader.readByte("lua_Number integral flag");
    if (integralFlag !== 0 && integralFlag !== 1) {
      this.fail(
        "LUA51_INVALID_NUMBER_FORMAT",
        `lua_Number integral flag must be 0 or 1, found ${integralFlag}.`,
        integralOffset,
      );
    }

    if (integralFlag === 0) {
      if (numberSize !== 4 && numberSize !== 8) {
        this.fail(
          "LUA51_UNSUPPORTED_NUMBER_SIZE",
          `Floating lua_Number must be 4 or 8 bytes; header declares ${numberSize}.`,
          numberSizeOffset,
        );
      }
    } else {
      this.requireIntegerScalarSize(
        numberSize,
        "integral lua_Number",
        numberSizeOffset,
      );
    }

    return {
      signatureHex: "1b4c7561",
      version: 0x51,
      format: 0,
      endianness,
      intSize,
      sizeTSize,
      instructionSize: 4,
      numberSize,
      numberKind: integralFlag === 1 ? "integer" : "float",
      rawIntegralFlag: integralFlag,
    };
  }

  private parsePrototype(path: string, depth: number): Lua51Prototype {
    if (depth > this.limits.maxPrototypeDepth) {
      this.fail(
        "LUA51_LIMIT_PROTOTYPE_DEPTH",
        `Prototype depth ${depth} exceeds configured maximum ${this.limits.maxPrototypeDepth}.`,
        this.reader.offset,
        path,
      );
    }
    if (this.stats.prototypeCount >= this.limits.maxPrototypes) {
      this.fail(
        "LUA51_LIMIT_PROTOTYPES",
        `Prototype count exceeds configured maximum ${this.limits.maxPrototypes}.`,
        this.reader.offset,
        path,
      );
    }
    this.stats.prototypeCount += 1;

    const previousPath = this.currentPrototypePath;
    const previousPc = this.currentPc;
    this.currentPrototypePath = path;
    this.currentPc = null;
    const offset = this.reader.offset;

    try {
      const source = this.readLuaString(`${path} source`);
      const lineDefined = this.readInt(`${path} lineDefined`);
      const lastLineDefined = this.readInt(`${path} lastLineDefined`);
      const upvalueCount = this.reader.readByte(`${path} upvalueCount`);
      const parameterCount = this.reader.readByte(`${path} parameterCount`);
      const varargFlags = this.reader.readByte(`${path} varargFlags`);
      const maxStackSize = this.reader.readByte(`${path} maxStackSize`);

      if ((varargFlags & ~0x07) !== 0) {
        this.addCurrentDiagnostic(
          "LUA51_INVALID_VARARG_FLAGS",
          "error",
          `Prototype ${path} has unsupported vararg flag bits 0x${hexByte(varargFlags)}.`,
          offset,
        );
      }
      if (maxStackSize === 0 || maxStackSize > 250) {
        this.addCurrentDiagnostic(
          "LUA51_INVALID_MAX_STACK",
          "error",
          `Prototype ${path} maxStackSize ${maxStackSize} is outside the Lua 5.1 range 1..250.`,
          offset,
        );
      }
      if (parameterCount > maxStackSize) {
        this.addCurrentDiagnostic(
          "LUA51_PARAMETERS_EXCEED_STACK",
          "error",
          `Prototype ${path} has ${parameterCount} parameter(s) but maxStackSize is ${maxStackSize}.`,
          offset,
        );
      }
      if (upvalueCount > 60) {
        this.addCurrentDiagnostic(
          "LUA51_NONCANONICAL_UPVALUE_COUNT",
          "warning",
          `Prototype ${path} declares ${upvalueCount} upvalues; stock Lua 5.1 limits functions to 60.`,
          offset,
        );
      }
      if (lineDefined < 0 || lastLineDefined < 0) {
        this.addCurrentDiagnostic(
          "LUA51_NEGATIVE_SOURCE_LINE",
          "warning",
          `Prototype ${path} contains a negative source line range ${lineDefined}..${lastLineDefined}.`,
          offset,
        );
      }

      const instructionCount = this.readCount(
        `${path} instruction count`,
        this.limits.maxInstructionsPerPrototype,
        4,
        "LUA51_LIMIT_INSTRUCTIONS_PER_PROTOTYPE",
      );
      this.reserveTotal(
        "instruction",
        instructionCount,
        "instructionCount",
        this.limits.maxInstructionsTotal,
        "LUA51_LIMIT_INSTRUCTIONS_TOTAL",
      );
      const instructions: Lua51DecodedInstruction[] = [];
      for (let pc = 0; pc < instructionCount; pc += 1) {
        this.currentPc = pc;
        const instructionOffset = this.reader.offset;
        const raw = Number(
          this.reader.readUnsignedBig(4, this.requireHeader().endianness, "instruction"),
        );
        instructions.push(
          decodeLua51InstructionAtOffset(raw, pc, instructionOffset),
        );
      }
      this.currentPc = null;

      const constantCount = this.readCount(
        `${path} constant count`,
        this.limits.maxConstantsPerPrototype,
        1,
        "LUA51_LIMIT_CONSTANTS_PER_PROTOTYPE",
      );
      this.reserveTotal(
        "constant",
        constantCount,
        "constantCount",
        this.limits.maxConstantsTotal,
        "LUA51_LIMIT_CONSTANTS_TOTAL",
      );
      const constants: Lua51Constant[] = [];
      for (let index = 0; index < constantCount; index += 1) {
        constants.push(this.parseConstant(path, index));
      }

      const minimumPrototypeBytes =
        this.requireHeader().sizeTSize + this.requireHeader().intSize * 8 + 4;
      const childCount = this.readCount(
        `${path} child prototype count`,
        this.limits.maxChildPrototypesPerPrototype,
        minimumPrototypeBytes,
        "LUA51_LIMIT_CHILD_PROTOTYPES",
      );
      if (
        this.stats.prototypeCount + childCount >
        this.limits.maxPrototypes
      ) {
        this.fail(
          "LUA51_LIMIT_PROTOTYPES",
          `Adding ${childCount} direct child prototype(s) would exceed configured maximum ${this.limits.maxPrototypes}.`,
          this.reader.offset,
          path,
        );
      }
      const prototypes: Lua51Prototype[] = [];
      for (let index = 0; index < childCount; index += 1) {
        prototypes.push(
          this.parsePrototype(`${path}.${index}`, depth + 1),
        );
        this.currentPrototypePath = path;
        this.currentPc = null;
      }

      const lineInfoCount = this.readCount(
        `${path} line-info count`,
        this.limits.maxLineInfoTotal,
        this.requireHeader().intSize,
        "LUA51_LIMIT_LINE_INFO",
      );
      this.reserveTotal(
        "line-info",
        lineInfoCount,
        "lineInfoCount",
        this.limits.maxLineInfoTotal,
        "LUA51_LIMIT_LINE_INFO",
      );
      const lineInfo: number[] = [];
      for (let index = 0; index < lineInfoCount; index += 1) {
        const lineOffset = this.reader.offset;
        const line = this.readInt(`${path} lineInfo[${index}]`);
        lineInfo.push(line);
        if (line < 0) {
          this.addCurrentDiagnostic(
            "LUA51_NEGATIVE_DEBUG_LINE",
            "warning",
            `Prototype ${path} lineInfo[${index}] is negative (${line}).`,
            lineOffset,
          );
        }
      }

      const minimumLocalBytes =
        this.requireHeader().sizeTSize + this.requireHeader().intSize * 2;
      const localCount = this.readCount(
        `${path} local variable count`,
        this.limits.maxLocalsTotal,
        minimumLocalBytes,
        "LUA51_LIMIT_LOCALS",
      );
      this.reserveTotal(
        "local",
        localCount,
        "localCount",
        this.limits.maxLocalsTotal,
        "LUA51_LIMIT_LOCALS",
      );
      const locals: Lua51LocalVariable[] = [];
      for (let index = 0; index < localCount; index += 1) {
        const localOffset = this.reader.offset;
        const name = this.readLuaString(`${path} local[${index}] name`);
        const startPc = this.readInt(`${path} local[${index}] startPc`);
        const endPc = this.readInt(`${path} local[${index}] endPc`);
        locals.push({ name, startPc, endPc, offset: localOffset });
      }

      const upvalueNameCount = this.readCount(
        `${path} upvalue-name count`,
        this.limits.maxUpvalueNamesTotal,
        this.requireHeader().sizeTSize,
        "LUA51_LIMIT_UPVALUE_NAMES",
      );
      this.reserveTotal(
        "upvalue name",
        upvalueNameCount,
        "upvalueNameCount",
        this.limits.maxUpvalueNamesTotal,
        "LUA51_LIMIT_UPVALUE_NAMES",
      );
      const upvalueNames: (Lua51String | null)[] = [];
      for (let index = 0; index < upvalueNameCount; index += 1) {
        upvalueNames.push(
          this.readLuaString(`${path} upvalueName[${index}]`),
        );
      }

      const prototype: Lua51Prototype = {
        path,
        depth,
        offset,
        endOffset: this.reader.offset,
        source,
        lineDefined,
        lastLineDefined,
        upvalueCount,
        parameterCount,
        varargFlags,
        maxStackSize,
        instructions,
        constants,
        prototypes,
        lineInfo,
        locals,
        upvalueNames,
      };
      this.validatePrototype(prototype);
      return prototype;
    } finally {
      this.currentPrototypePath = previousPath;
      this.currentPc = previousPc;
    }
  }

  private parseConstant(path: string, index: number): Lua51Constant {
    const offset = this.reader.offset;
    const tag = this.reader.readByte(`${path} constant[${index}] tag`);
    switch (tag) {
      case 0:
        return { type: "nil", offset };
      case 1: {
        const rawValue = this.reader.readByte(
          `${path} constant[${index}] boolean`,
        );
        if (rawValue !== 0 && rawValue !== 1) {
          this.fail(
            "LUA51_INVALID_BOOLEAN",
            `Boolean constant ${index} in prototype ${path} must be encoded as 0 or 1, found ${rawValue}.`,
            offset,
            path,
          );
        }
        return {
          type: "boolean",
          offset,
          value: rawValue === 1,
          rawValue,
        };
      }
      case 3: {
        const numberOffset = this.reader.offset;
        const rawBytes = this.reader.readBytes(
          this.requireHeader().numberSize,
          `${path} constant[${index}] lua_Number`,
        );
        const value = decodeLuaNumber(rawBytes, this.requireHeader());
        return {
          type: "number",
          offset,
          kind: this.requireHeader().numberKind,
          value,
          rawBytes,
          rawHex: bytesToHex(rawBytes),
        };
      }
      case 4: {
        const value = this.readLuaString(
          `${path} constant[${index}] string`,
        );
        if (value === null) {
          this.fail(
            "LUA51_NULL_STRING_CONSTANT",
            `String constant ${index} in prototype ${path} has a zero encoded length.`,
            offset,
            path,
          );
        }
        return { type: "string", offset, value };
      }
      default:
        this.fail(
          "LUA51_INVALID_CONSTANT_TAG",
          `Unsupported constant tag ${tag} at constant ${index} in prototype ${path}.`,
          offset,
          path,
        );
    }
  }

  private validatePrototype(prototype: Lua51Prototype): void {
    const dataPcs = collectSetListDataPcs(prototype);
    const codeLength = prototype.instructions.length;

    if (
      prototype.lineInfo.length !== 0 &&
      prototype.lineInfo.length !== codeLength
    ) {
      this.addDiagnostic({
        code: "LUA51_DEBUG_LINE_COUNT_MISMATCH",
        severity: "warning",
        message: `Prototype ${prototype.path} has ${prototype.lineInfo.length} line entries for ${codeLength} instructions.`,
        offset: prototype.offset,
        prototypePath: prototype.path,
        pc: null,
      });
    }
    if (
      prototype.upvalueNames.length !== 0 &&
      prototype.upvalueNames.length !== prototype.upvalueCount
    ) {
      this.addDiagnostic({
        code: "LUA51_DEBUG_UPVALUE_COUNT_MISMATCH",
        severity: "warning",
        message: `Prototype ${prototype.path} has ${prototype.upvalueNames.length} upvalue names but declares ${prototype.upvalueCount} upvalues.`,
        offset: prototype.offset,
        prototypePath: prototype.path,
        pc: null,
      });
    }

    for (let index = 0; index < prototype.locals.length; index += 1) {
      const local = prototype.locals[index];
      if (local === undefined) {
        continue;
      }
      if (local.name === null) {
        this.addDiagnostic({
          code: "LUA51_NULL_LOCAL_NAME",
          severity: "error",
          message: `Prototype ${prototype.path} local[${index}] has a zero-length name encoding.`,
          offset: local.offset,
          prototypePath: prototype.path,
          pc: null,
        });
      }
      if (
        local.startPc < 0 ||
        local.endPc < local.startPc ||
        local.endPc > codeLength
      ) {
        this.addDiagnostic({
          code: "LUA51_INVALID_LOCAL_RANGE",
          severity: "error",
          message: `Prototype ${prototype.path} local[${index}] range ${local.startPc}..${local.endPc} is outside code range 0..${codeLength}.`,
          offset: local.offset,
          prototypePath: prototype.path,
          pc: null,
        });
      }
    }

    for (let index = 0; index < prototype.upvalueNames.length; index += 1) {
      if (prototype.upvalueNames[index] === null) {
        this.addDiagnostic({
          code: "LUA51_NULL_UPVALUE_NAME",
          severity: "error",
          message: `Prototype ${prototype.path} upvalueName[${index}] has a zero-length encoding.`,
          offset: prototype.offset,
          prototypePath: prototype.path,
          pc: null,
        });
      }
    }

    for (const instruction of prototype.instructions) {
      if (dataPcs.has(instruction.pc)) {
        continue;
      }
      const descriptor = OPCODES[instruction.opcode];
      if (descriptor === undefined) {
        this.addInstructionDiagnostic(
          prototype,
          instruction,
          "LUA51_INVALID_OPCODE",
          "error",
          `Opcode ${instruction.opcode} is not defined by Lua 5.1.`,
        );
        continue;
      }

      this.validateInstructionRegisters(prototype, instruction);
      this.validateInstructionReferences(
        prototype,
        instruction,
        dataPcs,
      );
    }
  }

  private validateInstructionRegisters(
    prototype: Lua51Prototype,
    instruction: Lua51DecodedInstruction,
  ): void {
    const opcode = instruction.opcode;
    const checkA = opcode !== 22 && opcode !== 23 && opcode !== 24 && opcode !== 25;
    if (checkA) {
      this.checkRegister(prototype, instruction, instruction.A, "A");
    }

    switch (opcode) {
      case 0:
      case 3:
      case 18:
      case 19:
      case 20:
      case 27:
        this.checkRegister(prototype, instruction, instruction.B, "B");
        break;
      case 4:
      case 8:
        if (instruction.B >= prototype.upvalueCount) {
          this.addInstructionDiagnostic(
            prototype,
            instruction,
            "LUA51_UPVALUE_OUT_OF_RANGE",
            "error",
            `Operand B=${instruction.B} is outside ${prototype.upvalueCount} declared upvalue(s).`,
          );
        }
        break;
      case 6:
      case 11:
        this.checkRegister(prototype, instruction, instruction.B, "B");
        this.checkRk(prototype, instruction, instruction.C, "C");
        break;
      case 9:
      case 12:
      case 13:
      case 14:
      case 15:
      case 16:
      case 17:
      case 23:
      case 24:
      case 25:
        this.checkRk(prototype, instruction, instruction.B, "B");
        this.checkRk(prototype, instruction, instruction.C, "C");
        break;
      case 21:
        this.checkRegister(prototype, instruction, instruction.B, "B");
        this.checkRegister(prototype, instruction, instruction.C, "C");
        if (instruction.B > instruction.C) {
          this.addInstructionDiagnostic(
            prototype,
            instruction,
            "LUA51_INVALID_CONCAT_RANGE",
            "error",
            `CONCAT register range B=${instruction.B}..C=${instruction.C} is reversed.`,
          );
        }
        break;
      default:
        break;
    }

    if (opcode === 3 && instruction.A > instruction.B) {
      this.addInstructionDiagnostic(
        prototype,
        instruction,
        "LUA51_INVALID_LOADNIL_RANGE",
        "error",
        `LOADNIL register range A=${instruction.A}..B=${instruction.B} is reversed.`,
      );
    }
    if (opcode === 11) {
      this.checkRegister(prototype, instruction, instruction.A + 1, "A+1");
    }
    if (opcode === 31 || opcode === 32) {
      this.checkRegister(prototype, instruction, instruction.A + 3, "A+3");
    }
    if (opcode === 33) {
      const highest = instruction.A + 2 + instruction.C;
      this.checkRegister(prototype, instruction, highest, "A+2+C");
    }
  }

  private validateInstructionReferences(
    prototype: Lua51Prototype,
    instruction: Lua51DecodedInstruction,
    dataPcs: ReadonlySet<number>,
  ): void {
    const opcode = instruction.opcode;
    if (opcode === 1 || opcode === 5 || opcode === 7) {
      const constant = prototype.constants[instruction.Bx];
      if (constant === undefined) {
        this.addInstructionDiagnostic(
          prototype,
          instruction,
          "LUA51_CONSTANT_OUT_OF_RANGE",
          "error",
          `Bx=${instruction.Bx} is outside ${prototype.constants.length} constant(s).`,
        );
      } else if (
        (opcode === 5 || opcode === 7) &&
        constant.type !== "string"
      ) {
        this.addInstructionDiagnostic(
          prototype,
          instruction,
          "LUA51_GLOBAL_NAME_NOT_STRING",
          "error",
          `${instruction.opcodeName} requires a string constant, but K[${instruction.Bx}] is ${constant.type}.`,
        );
      }
    }

    if (
      instruction.branchTarget !== null &&
      (instruction.branchTarget < 0 ||
        instruction.branchTarget >= prototype.instructions.length)
    ) {
      this.addInstructionDiagnostic(
        prototype,
        instruction,
        "LUA51_BRANCH_OUT_OF_RANGE",
        "error",
        `Branch target ${instruction.branchTarget} is outside code range 0..${Math.max(0, prototype.instructions.length - 1)}.`,
      );
    } else if (
      instruction.branchTarget !== null &&
      dataPcs.has(instruction.branchTarget)
    ) {
      this.addInstructionDiagnostic(
        prototype,
        instruction,
        "LUA51_BRANCH_TO_DATA_WORD",
        "error",
        `Branch target ${instruction.branchTarget} points to a SETLIST data word.`,
      );
    }

    if (opcode === 34 && instruction.C === 0) {
      const extraPc = instruction.pc + 1;
      if (extraPc >= prototype.instructions.length) {
        this.addInstructionDiagnostic(
          prototype,
          instruction,
          "LUA51_MISSING_SETLIST_EXTRA",
          "error",
          "SETLIST with C=0 requires one following raw data word.",
        );
      }
    }

    if (opcode === 36) {
      const child = prototype.prototypes[instruction.Bx];
      if (child === undefined) {
        this.addInstructionDiagnostic(
          prototype,
          instruction,
          "LUA51_PROTOTYPE_OUT_OF_RANGE",
          "error",
          `CLOSURE Bx=${instruction.Bx} is outside ${prototype.prototypes.length} child prototype(s).`,
        );
        return;
      }
      for (let index = 0; index < child.upvalueCount; index += 1) {
        const bindingPc = instruction.pc + 1 + index;
        const binding = prototype.instructions[bindingPc];
        if (binding === undefined) {
          this.addInstructionDiagnostic(
            prototype,
            instruction,
            "LUA51_MISSING_CLOSURE_BINDING",
            "error",
            `CLOSURE for child ${instruction.Bx} requires ${child.upvalueCount} binding instruction(s); binding ${index} is missing.`,
          );
          break;
        }
        if (dataPcs.has(bindingPc)) {
          this.addInstructionDiagnostic(
            prototype,
            binding,
            "LUA51_INVALID_CLOSURE_BINDING",
            "error",
            `CLOSURE binding ${index} overlaps a SETLIST data word.`,
          );
          continue;
        }
        if (binding.opcode !== 0 && binding.opcode !== 4) {
          this.addInstructionDiagnostic(
            prototype,
            binding,
            "LUA51_INVALID_CLOSURE_BINDING",
            "error",
            `CLOSURE binding ${index} must be MOVE or GETUPVAL, found ${binding.opcodeName}.`,
          );
        } else if (binding.opcode === 0) {
          this.checkRegister(prototype, binding, binding.B, "B");
        } else if (binding.B >= prototype.upvalueCount) {
          this.addInstructionDiagnostic(
            prototype,
            binding,
            "LUA51_UPVALUE_OUT_OF_RANGE",
            "error",
            `CLOSURE GETUPVAL binding B=${binding.B} is outside ${prototype.upvalueCount} parent upvalue(s).`,
          );
        }
      }
    }
  }

  private checkRegister(
    prototype: Lua51Prototype,
    instruction: Lua51DecodedInstruction,
    register: number,
    operand: string,
  ): void {
    if (register >= prototype.maxStackSize) {
      this.addInstructionDiagnostic(
        prototype,
        instruction,
        "LUA51_REGISTER_OUT_OF_RANGE",
        "error",
        `Operand ${operand}=R${register} is outside maxStackSize ${prototype.maxStackSize}.`,
      );
    }
  }

  private checkRk(
    prototype: Lua51Prototype,
    instruction: Lua51DecodedInstruction,
    operandValue: number,
    operand: string,
  ): void {
    if ((operandValue & BITRK) !== 0) {
      const constantIndex = operandValue & MAXINDEXRK;
      if (constantIndex >= prototype.constants.length) {
        this.addInstructionDiagnostic(
          prototype,
          instruction,
          "LUA51_CONSTANT_OUT_OF_RANGE",
          "error",
          `Operand ${operand}=K[${constantIndex}] is outside ${prototype.constants.length} constant(s).`,
        );
      }
    } else {
      this.checkRegister(prototype, instruction, operandValue, operand);
    }
  }

  private addInstructionDiagnostic(
    prototype: Lua51Prototype,
    instruction: Lua51DecodedInstruction,
    code: string,
    severity: Lua51DiagnosticSeverity,
    message: string,
  ): void {
    this.addDiagnostic({
      code,
      severity,
      message,
      offset: instruction.offset,
      prototypePath: prototype.path,
      pc: instruction.pc,
    });
  }

  private readLuaString(label: string): Lua51String | null {
    const offset = this.reader.offset;
    const header = this.requireHeader();
    const encodedLength = this.reader.readUnsignedBig(
      header.sizeTSize,
      header.endianness,
      `${label} length`,
    );
    if (encodedLength === 0n) {
      return null;
    }
    if (encodedLength > BigInt(Number.MAX_SAFE_INTEGER)) {
      this.fail(
        "LUA51_INVALID_STRING_LENGTH",
        `${label} length exceeds JavaScript's exact integer range.`,
        offset,
      );
    }
    const byteLengthWithTerminator = Number(encodedLength);
    const payloadLength = byteLengthWithTerminator - 1;
    if (payloadLength > this.limits.maxStringBytes) {
      this.fail(
        "LUA51_LIMIT_STRING_BYTES",
        `${label} payload length ${payloadLength} exceeds configured per-string maximum ${this.limits.maxStringBytes}.`,
        offset,
      );
    }
    if (
      this.stats.stringBytes + payloadLength >
      this.limits.maxStringBytesTotal
    ) {
      this.fail(
        "LUA51_LIMIT_STRING_BYTES_TOTAL",
        `${label} would make total decoded string bytes exceed configured maximum ${this.limits.maxStringBytesTotal}.`,
        offset,
      );
    }
    const encoded = this.reader.readBytes(
      byteLengthWithTerminator,
      `${label} bytes`,
    );
    if (encoded[encoded.length - 1] !== 0) {
      this.fail(
        "LUA51_STRING_MISSING_TERMINATOR",
        `${label} does not end with the required NUL byte.`,
        offset,
      );
    }
    const bytes = encoded.slice(0, -1);
    this.stats.stringBytes += bytes.length;
    return {
      offset,
      bytes,
      utf8: UTF8_DECODER.decode(bytes),
    };
  }

  private readInt(label: string): number {
    const offset = this.reader.offset;
    const header = this.requireHeader();
    const value = this.reader.readSignedBig(
      header.intSize,
      header.endianness,
      label,
    );
    if (
      value < BigInt(Number.MIN_SAFE_INTEGER) ||
      value > BigInt(Number.MAX_SAFE_INTEGER)
    ) {
      this.fail(
        "LUA51_INTEGER_OUT_OF_RANGE",
        `${label} cannot be represented exactly as a JavaScript number.`,
        offset,
      );
    }
    return Number(value);
  }

  private readCount(
    label: string,
    perContainerLimit: number,
    minimumBytesPerItem: number,
    limitCode: string,
  ): number {
    const offset = this.reader.offset;
    const count = this.readInt(label);
    if (count < 0) {
      this.fail(
        "LUA51_NEGATIVE_COUNT",
        `${label} is negative (${count}).`,
        offset,
      );
    }
    if (count > perContainerLimit) {
      this.fail(
        limitCode,
        `${label} ${count} exceeds configured maximum ${perContainerLimit}.`,
        offset,
      );
    }
    if (
      minimumBytesPerItem > 0 &&
      count > Math.floor(this.reader.remaining / minimumBytesPerItem)
    ) {
      this.fail(
        "LUA51_COUNT_EXCEEDS_REMAINING_BYTES",
        `${label} ${count} requires at least ${count * minimumBytesPerItem} bytes, but only ${this.reader.remaining} remain.`,
        offset,
      );
    }
    return count;
  }

  private reserveTotal(
    label: string,
    count: number,
    field: keyof MutableStats,
    maximum: number,
    code: string,
  ): void {
    const current = this.stats[field];
    if (current + count > maximum) {
      this.fail(
        code,
        `Total ${label} count would exceed configured maximum ${maximum}.`,
        this.reader.offset,
      );
    }
    this.stats[field] = current + count;
  }

  private requireHeader(): Lua51Header {
    if (this.header === null) {
      throw new Error("Internal error: Lua 5.1 header has not been parsed.");
    }
    return this.header;
  }

  private requireIntegerScalarSize(
    size: number,
    label: string,
    offset: number,
  ): void {
    if (size !== 1 && size !== 2 && size !== 4 && size !== 8) {
      this.fail(
        "LUA51_UNSUPPORTED_SCALAR_SIZE",
        `${label} size must be 1, 2, 4, or 8 bytes; header declares ${size}.`,
        offset,
      );
    }
  }

  private requireUnsignedScalarSize(
    size: number,
    label: string,
    offset: number,
  ): void {
    this.requireIntegerScalarSize(size, label, offset);
  }

  private addCurrentDiagnostic(
    code: string,
    severity: Lua51DiagnosticSeverity,
    message: string,
    offset: number,
  ): void {
    this.addDiagnostic({
      code,
      severity,
      message,
      offset,
      prototypePath: this.currentPrototypePath,
      pc: this.currentPc,
    });
  }

  private addDiagnostic(diagnostic: Lua51Diagnostic): void {
    if (this.diagnostics.length < this.limits.maxDiagnostics) {
      this.diagnostics.push(diagnostic);
    } else {
      this.diagnosticsSuppressed = true;
    }
  }

  private finalDiagnostics(): readonly Lua51Diagnostic[] {
    if (this.diagnosticsSuppressed) {
      const limitDiagnostic: Lua51Diagnostic = {
        code: "LUA51_LIMIT_DIAGNOSTICS",
        severity: "error",
        message: `Diagnostic count reached configured maximum ${this.limits.maxDiagnostics}; remaining diagnostics were suppressed.`,
        offset: this.reader.offset,
        prototypePath: this.currentPrototypePath,
        pc: this.currentPc,
      };
      if (this.diagnostics.length === 0) {
        this.diagnostics.push(limitDiagnostic);
      } else {
        this.diagnostics[this.diagnostics.length - 1] = limitDiagnostic;
      }
      this.diagnosticsSuppressed = false;
    }
    return this.diagnostics.slice();
  }

  private fail(
    code: string,
    message: string,
    offset: number,
    prototypePath: string | null = this.currentPrototypePath,
  ): never {
    throw new ParseAbort({
      code,
      severity: "error",
      message,
      offset,
      prototypePath,
      pc: this.currentPc,
    });
  }
}

class AuditWriter {
  private readonly lines: string[] = [];
  private charCount = 0;
  truncated = false;

  constructor(
    private readonly maxLines: number,
    private readonly maxChars: number,
  ) {}

  line(value: string): void {
    if (this.truncated) {
      return;
    }
    const separatorChars = this.lines.length === 0 ? 0 : 1;
    if (
      this.lines.length + 1 > this.maxLines ||
      this.charCount + separatorChars + value.length > this.maxChars
    ) {
      this.truncated = true;
      return;
    }
    this.lines.push(value);
    this.charCount += separatorChars + value.length;
  }

  finish(): string {
    if (this.truncated) {
      const marker = "; ... audit truncated by configured output limit ...";
      while (
        this.lines.length > 0 &&
        (this.lines.length + 1 > this.maxLines ||
          this.charCount + 1 + marker.length > this.maxChars)
      ) {
        const removed = this.lines.pop();
        if (removed !== undefined) {
          this.charCount -= removed.length;
          if (this.lines.length > 0) {
            this.charCount -= 1;
          }
        }
      }
      const separatorChars = this.lines.length === 0 ? 0 : 1;
      if (
        this.lines.length + 1 <= this.maxLines &&
        this.charCount + separatorChars + marker.length <= this.maxChars
      ) {
        this.lines.push(marker);
      }
    }
    return this.lines.join("\n");
  }
}

/**
 * Fast signature/version sniff. This does not replace parseLua51Chunk.
 */
export function isLua51Bytecode(input: Uint8Array): boolean {
  return (
    input.length >= 5 &&
    input[0] === LUA51_SIGNATURE[0] &&
    input[1] === LUA51_SIGNATURE[1] &&
    input[2] === LUA51_SIGNATURE[2] &&
    input[3] === LUA51_SIGNATURE[3] &&
    input[4] === 0x51
  );
}

/**
 * Parse and validate one complete stock-format Lua 5.1 binary chunk.
 * Malformed/untrusted bytes are reported as diagnostics, never executed.
 */
export function parseLua51Chunk(
  input: Uint8Array,
  options?: Lua51Options,
): Lua51ParseResult {
  const limitResult = resolveLimits(options);
  if ("diagnostic" in limitResult) {
    return {
      ok: false,
      chunk: null,
      diagnostics: [limitResult.diagnostic],
      bytesConsumed: 0,
    };
  }
  if (!(input instanceof Uint8Array)) {
    return {
      ok: false,
      chunk: null,
      diagnostics: [
        {
          code: "LUA51_INVALID_INPUT_TYPE",
          severity: "error",
          message: "Lua 5.1 input must be a Uint8Array.",
          offset: 0,
          prototypePath: null,
          pc: null,
        },
      ],
      bytesConsumed: 0,
    };
  }
  if (input.length > limitResult.limits.maxInputBytes) {
    return {
      ok: false,
      chunk: null,
      diagnostics: [
        {
          code: "LUA51_LIMIT_INPUT_BYTES",
          severity: "error",
          message: `Input length ${input.length} exceeds configured maximum ${limitResult.limits.maxInputBytes}.`,
          offset: 0,
          prototypePath: null,
          pc: null,
        },
      ],
      bytesConsumed: 0,
    };
  }
  return new Lua51Parser(input, limitResult.limits).run();
}

/**
 * Decode the fixed 32-bit Lua 5.1 instruction fields without context.
 */
export function decodeLua51Instruction(
  raw: number,
  pc: number,
): Lua51DecodedInstruction {
  return decodeLua51InstructionAtOffset(raw, pc, -1);
}

/**
 * Produce deterministic, bounded exact-audit text for an already parsed chunk.
 */
export function disassembleLua51Chunk(
  chunk: Lua51Chunk,
  options?: Lua51Options,
): Lua51DisassemblyResult {
  const limitResult = resolveLimits(options);
  if ("diagnostic" in limitResult) {
    return {
      text: "",
      diagnostics: [...chunk.diagnostics, limitResult.diagnostic],
      truncated: true,
    };
  }

  const writer = new AuditWriter(
    limitResult.limits.maxAuditLines,
    limitResult.limits.maxAuditChars,
  );
  const header = chunk.header;
  writer.line("; Lua 5.1 bytecode exact static audit");
  writer.line(
    `; header signature=${header.signatureHex} version=0x51 format=0 endianness=${header.endianness} int=${header.intSize} size_t=${header.sizeTSize} instruction=${header.instructionSize} number=${header.numberSize} number_kind=${header.numberKind}`,
  );
  writer.line(
    `; input_bytes=${chunk.inputByteLength} consumed=${chunk.bytesConsumed} prototypes=${chunk.stats.prototypeCount} instructions=${chunk.stats.instructionCount} constants=${chunk.stats.constantCount}`,
  );
  writePrototypeAudit(writer, chunk.main);
  writer.line(`.diagnostics ${chunk.diagnostics.length}`);
  for (const diagnostic of chunk.diagnostics) {
    const location = [
      `offset=0x${diagnostic.offset.toString(16)}`,
      diagnostic.prototypePath === null
        ? "proto=-"
        : `proto=${diagnostic.prototypePath}`,
      diagnostic.pc === null ? "pc=-" : `pc=${diagnostic.pc}`,
    ].join(" ");
    writer.line(
      `  ${diagnostic.severity.toUpperCase()} ${diagnostic.code} ${location} ${diagnostic.message}`,
    );
  }

  const text = writer.finish();
  if (!writer.truncated) {
    return {
      text,
      diagnostics: chunk.diagnostics,
      truncated: false,
    };
  }
  const outputDiagnostic: Lua51Diagnostic = {
    code: "LUA51_LIMIT_AUDIT_OUTPUT",
    severity: "error",
    message: `Disassembly exceeded configured output limit (${limitResult.limits.maxAuditLines} lines or ${limitResult.limits.maxAuditChars} characters).`,
    offset: chunk.bytesConsumed,
    prototypePath: null,
    pc: null,
  };
  return {
    text,
    diagnostics: [...chunk.diagnostics, outputDiagnostic],
    truncated: true,
  };
}

/**
 * Parse, validate, and generate bounded audit text in one call.
 */
export function inspectLua51Bytecode(
  input: Uint8Array,
  options?: Lua51Options,
): Lua51InspectionResult {
  const parsed = parseLua51Chunk(input, options);
  if (parsed.chunk === null) {
    return {
      ok: false,
      chunk: null,
      auditText: null,
      auditTruncated: false,
      diagnostics: parsed.diagnostics,
      bytesConsumed: parsed.bytesConsumed,
    };
  }
  const disassembly = disassembleLua51Chunk(parsed.chunk, options);
  const ok =
    parsed.ok &&
    !disassembly.truncated &&
    !disassembly.diagnostics.some(
      (diagnostic) => diagnostic.severity === "error",
    );
  return {
    ok,
    chunk: parsed.chunk,
    auditText: disassembly.text,
    auditTruncated: disassembly.truncated,
    diagnostics: disassembly.diagnostics,
    bytesConsumed: parsed.bytesConsumed,
  };
}

function decodeLua51InstructionAtOffset(
  raw: number,
  pc: number,
  offset: number,
): Lua51DecodedInstruction {
  const word = raw >>> 0;
  const opcode = word & 0x3f;
  const A = (word >>> 6) & 0xff;
  const C = (word >>> 14) & 0x1ff;
  const B = (word >>> 23) & 0x1ff;
  const Bx = (word >>> 14) & MAXARG_BX;
  const sBx = Bx - MAXARG_SBX;
  const descriptor = OPCODES[opcode];
  const branchTarget =
    opcode === 22 || opcode === 31 || opcode === 32
      ? pc + 1 + sBx
      : null;
  return {
    offset,
    pc,
    raw: word,
    rawHex: word.toString(16).padStart(8, "0"),
    opcode,
    opcodeName: descriptor?.name ?? `INVALID_${opcode}`,
    mode: descriptor?.mode ?? "unknown",
    A,
    B,
    C,
    Bx,
    sBx,
    branchTarget,
  };
}

function decodeLuaNumber(
  rawBytes: Uint8Array,
  header: Lua51Header,
): number | bigint {
  if (header.numberKind === "integer") {
    let unsigned = 0n;
    if (header.endianness === "little") {
      for (let index = rawBytes.length - 1; index >= 0; index -= 1) {
        unsigned = (unsigned << 8n) | BigInt(rawBytes[index] ?? 0);
      }
    } else {
      for (const byte of rawBytes) {
        unsigned = (unsigned << 8n) | BigInt(byte);
      }
    }
    const bitCount = BigInt(rawBytes.length * 8);
    const signBit = 1n << (bitCount - 1n);
    return (unsigned & signBit) === 0n
      ? unsigned
      : unsigned - (1n << bitCount);
  }

  const copy = rawBytes.slice();
  const view = new DataView(copy.buffer, copy.byteOffset, copy.byteLength);
  return rawBytes.length === 4
    ? view.getFloat32(0, header.endianness === "little")
    : view.getFloat64(0, header.endianness === "little");
}

function collectSetListDataPcs(
  prototype: Lua51Prototype,
): ReadonlySet<number> {
  const dataPcs = new Set<number>();
  for (const instruction of prototype.instructions) {
    if (
      !dataPcs.has(instruction.pc) &&
      instruction.opcode === 34 &&
      instruction.C === 0 &&
      instruction.pc + 1 < prototype.instructions.length
    ) {
      dataPcs.add(instruction.pc + 1);
    }
  }
  return dataPcs;
}

function collectClosureBindingAnnotations(
  prototype: Lua51Prototype,
): ReadonlyMap<number, string> {
  const annotations = new Map<number, string>();
  const dataPcs = collectSetListDataPcs(prototype);
  for (const instruction of prototype.instructions) {
    if (dataPcs.has(instruction.pc) || instruction.opcode !== 36) {
      continue;
    }
    const child = prototype.prototypes[instruction.Bx];
    if (child === undefined) {
      continue;
    }
    for (let index = 0; index < child.upvalueCount; index += 1) {
      const pc = instruction.pc + 1 + index;
      if (pc >= prototype.instructions.length) {
        break;
      }
      annotations.set(
        pc,
        `closure_bind owner_pc=${instruction.pc} child=${instruction.Bx} upvalue=${index}`,
      );
    }
  }
  return annotations;
}

function writePrototypeAudit(
  writer: AuditWriter,
  prototype: Lua51Prototype,
): void {
  const indent = "  ".repeat(prototype.depth);
  const bodyIndent = `${indent}  `;
  writer.line(
    `${indent}.prototype ${prototype.path} offset=0x${prototype.offset.toString(16)} end=0x${prototype.endOffset.toString(16)}`,
  );
  writer.line(
    `${bodyIndent}source=${prototype.source === null ? "<inherited>" : quoteLuaBytes(prototype.source.bytes)}`,
  );
  writer.line(
    `${bodyIndent}lines=${prototype.lineDefined}..${prototype.lastLineDefined} upvalues=${prototype.upvalueCount} params=${prototype.parameterCount} vararg=0x${hexByte(prototype.varargFlags)} maxstack=${prototype.maxStackSize}`,
  );
  writer.line(`${bodyIndent}.code ${prototype.instructions.length}`);

  const setListDataPcs = collectSetListDataPcs(prototype);
  const closureAnnotations = collectClosureBindingAnnotations(prototype);
  for (const instruction of prototype.instructions) {
    const pcLabel = instruction.pc.toString().padStart(6, "0");
    if (setListDataPcs.has(instruction.pc)) {
      writer.line(
        `${bodyIndent}  [${pcLabel}] raw=0x${instruction.rawHex} SETLIST_EXTRA value=${instruction.raw}`,
      );
      continue;
    }
    const fields =
      instruction.mode === "iABC"
        ? `A=${instruction.A} B=${instruction.B} C=${instruction.C}`
        : instruction.mode === "iABx"
          ? `A=${instruction.A} Bx=${instruction.Bx}`
          : instruction.mode === "iAsBx"
            ? `A=${instruction.A} sBx=${formatSigned(instruction.sBx)} target=${String(instruction.branchTarget)}`
            : `A=${instruction.A} B=${instruction.B} C=${instruction.C} Bx=${instruction.Bx}`;
    const annotations = instructionAnnotations(prototype, instruction);
    const closureAnnotation = closureAnnotations.get(instruction.pc);
    if (closureAnnotation !== undefined) {
      annotations.push(closureAnnotation);
    }
    writer.line(
      `${bodyIndent}  [${pcLabel}] raw=0x${instruction.rawHex} ${instruction.opcodeName} ${fields}${annotations.length === 0 ? "" : ` ; ${annotations.join(" ")}`}`,
    );
  }

  writer.line(`${bodyIndent}.constants ${prototype.constants.length}`);
  for (let index = 0; index < prototype.constants.length; index += 1) {
    const constant = prototype.constants[index];
    if (constant !== undefined) {
      writer.line(
        `${bodyIndent}  K[${index}] ${formatConstant(constant)}`,
      );
    }
  }

  writer.line(`${bodyIndent}.children ${prototype.prototypes.length}`);
  for (const child of prototype.prototypes) {
    writePrototypeAudit(writer, child);
  }

  writer.line(`${bodyIndent}.debug lineinfo=${prototype.lineInfo.length}`);
  for (let pc = 0; pc < prototype.lineInfo.length; pc += 1) {
    writer.line(`${bodyIndent}  line[${pc}]=${String(prototype.lineInfo[pc])}`);
  }
  writer.line(`${bodyIndent}.locals ${prototype.locals.length}`);
  for (let index = 0; index < prototype.locals.length; index += 1) {
    const local = prototype.locals[index];
    if (local !== undefined) {
      writer.line(
        `${bodyIndent}  local[${index}] name=${local.name === null ? "<null>" : quoteLuaBytes(local.name.bytes)} range=${local.startPc}..${local.endPc}`,
      );
    }
  }
  writer.line(`${bodyIndent}.upvalue_names ${prototype.upvalueNames.length}`);
  for (let index = 0; index < prototype.upvalueNames.length; index += 1) {
    const name = prototype.upvalueNames[index];
    writer.line(
      `${bodyIndent}  upvalue[${index}]=${name === null || name === undefined ? "<null>" : quoteLuaBytes(name.bytes)}`,
    );
  }
  writer.line(`${indent}.endprototype ${prototype.path}`);
}

function instructionAnnotations(
  prototype: Lua51Prototype,
  instruction: Lua51DecodedInstruction,
): string[] {
  const annotations: string[] = [];
  if (instruction.opcode === 1 || instruction.opcode === 5 || instruction.opcode === 7) {
    const constant = prototype.constants[instruction.Bx];
    annotations.push(
      constant === undefined
        ? `constant=K[${instruction.Bx}]<out-of-range>`
        : `constant=K[${instruction.Bx}](${formatConstantBrief(constant)})`,
    );
  }
  if (instruction.opcode === 36) {
    annotations.push(`child=${instruction.Bx}`);
  }
  if (instruction.opcode === 34 && instruction.C === 0) {
    annotations.push(`extra_pc=${instruction.pc + 1}`);
  }
  if (
    instruction.opcode === 23 ||
    instruction.opcode === 24 ||
    instruction.opcode === 25 ||
    instruction.opcode === 26 ||
    instruction.opcode === 27 ||
    instruction.opcode === 33 ||
    (instruction.opcode === 2 && instruction.C !== 0)
  ) {
    annotations.push(`skip_target=${instruction.pc + 2}`);
  }
  return annotations;
}

function formatConstant(constant: Lua51Constant): string {
  switch (constant.type) {
    case "nil":
      return "nil";
    case "boolean":
      return `boolean value=${constant.value ? "true" : "false"} raw=${constant.rawValue}`;
    case "number":
      return `number kind=${constant.kind} value=${formatLuaNumberValue(constant.value)} raw=0x${constant.rawHex}`;
    case "string":
      return `string bytes=${constant.value.bytes.length} value=${quoteLuaBytes(constant.value.bytes)}`;
  }
}

function formatConstantBrief(constant: Lua51Constant): string {
  switch (constant.type) {
    case "nil":
      return "nil";
    case "boolean":
      return constant.value ? "true" : "false";
    case "number":
      return formatLuaNumberValue(constant.value);
    case "string":
      return quoteLuaBytes(constant.value.bytes);
  }
}

function formatLuaNumberValue(value: number | bigint): string {
  if (typeof value === "bigint") {
    return value.toString(10);
  }
  if (Number.isNaN(value)) {
    return "nan";
  }
  if (value === Number.POSITIVE_INFINITY) {
    return "+inf";
  }
  if (value === Number.NEGATIVE_INFINITY) {
    return "-inf";
  }
  if (Object.is(value, -0)) {
    return "-0";
  }
  return String(value);
}

function quoteLuaBytes(bytes: Uint8Array): string {
  let value = '"';
  for (const byte of bytes) {
    if (byte === 0x22) {
      value += '\\"';
    } else if (byte === 0x5c) {
      value += "\\\\";
    } else if (byte >= 0x20 && byte <= 0x7e) {
      value += String.fromCharCode(byte);
    } else {
      value += `\\x${hexByte(byte)}`;
    }
  }
  return `${value}"`;
}

function resolveLimits(
  options: Lua51Options | undefined,
):
  | { readonly limits: Readonly<Lua51Limits> }
  | { readonly diagnostic: Lua51Diagnostic } {
  const limits: Lua51Limits = {
    ...DEFAULT_LUA51_LIMITS,
    ...(options?.limits ?? {}),
  };
  for (const [name, value] of Object.entries(limits)) {
    if (!Number.isSafeInteger(value) || value <= 0) {
      return {
        diagnostic: {
          code: "LUA51_INVALID_LIMIT",
          severity: "error",
          message: `Configured limit ${name} must be a positive safe integer, found ${String(value)}.`,
          offset: 0,
          prototypePath: null,
          pc: null,
        },
      };
    }
  }
  return { limits: Object.freeze(limits) };
}

function formatSigned(value: number): string {
  return value >= 0 ? `+${value}` : String(value);
}

function hexByte(value: number): string {
  return (value & 0xff).toString(16).padStart(2, "0");
}

function bytesToHex(bytes: Uint8Array): string {
  let result = "";
  for (const byte of bytes) {
    result += hexByte(byte);
  }
  return result;
}
