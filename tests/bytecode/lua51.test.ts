import { describe, expect, it } from "vitest";

import {
  decodeLua51Instruction,
  disassembleLua51Chunk,
  inspectLua51Bytecode,
  isLua51Bytecode,
  parseLua51Chunk,
  type Lua51Endianness,
} from "../../src/core/bytecode/lua51";

type ConstantSpec =
  | { readonly type: "nil" }
  | { readonly type: "boolean"; readonly value: boolean }
  | { readonly type: "number"; readonly value: number }
  | { readonly type: "string"; readonly value: string };

interface LocalSpec {
  readonly name: string | null;
  readonly startPc: number;
  readonly endPc: number;
}

interface PrototypeSpec {
  readonly source: string | null;
  readonly lineDefined: number;
  readonly lastLineDefined: number;
  readonly upvalueCount: number;
  readonly parameterCount: number;
  readonly varargFlags: number;
  readonly maxStackSize: number;
  readonly code: readonly number[];
  readonly constants: readonly ConstantSpec[];
  readonly children: readonly PrototypeSpec[];
  readonly lineInfo: readonly number[];
  readonly locals: readonly LocalSpec[];
  readonly upvalueNames: readonly (string | null)[];
}

interface ChunkFormat {
  readonly endianness: Lua51Endianness;
  readonly intSize: 1 | 2 | 4 | 8;
  readonly sizeTSize: 1 | 2 | 4 | 8;
  readonly numberSize: 4 | 8;
}

interface BuiltChunk {
  readonly bytes: Uint8Array;
  readonly mainCodeCountOffset: number;
  readonly mainCodeOffset: number;
  readonly mainSourceTerminatorOffset: number | null;
}

const DEFAULT_FORMAT: ChunkFormat = {
  endianness: "little",
  intSize: 4,
  sizeTSize: 8,
  numberSize: 8,
};

const RETURN = encodeABC(30, 0, 1, 0);

class ByteWriter {
  readonly bytes: number[] = [];

  get length(): number {
    return this.bytes.length;
  }

  byte(value: number): void {
    this.bytes.push(value & 0xff);
  }

  unsigned(
    value: number | bigint,
    size: number,
    endianness: Lua51Endianness,
  ): void {
    let remaining = BigInt(value);
    const encoded = new Array<number>(size).fill(0);
    for (let index = 0; index < size; index += 1) {
      encoded[index] = Number(remaining & 0xffn);
      remaining >>= 8n;
    }
    if (endianness === "little") {
      this.bytes.push(...encoded);
    } else {
      this.bytes.push(...encoded.reverse());
    }
  }

  signed(
    value: number,
    size: number,
    endianness: Lua51Endianness,
  ): void {
    this.unsigned(BigInt.asUintN(size * 8, BigInt(value)), size, endianness);
  }

  float(
    value: number,
    size: 4 | 8,
    endianness: Lua51Endianness,
  ): void {
    const encoded = new Uint8Array(size);
    const view = new DataView(
      encoded.buffer,
      encoded.byteOffset,
      encoded.byteLength,
    );
    if (size === 4) {
      view.setFloat32(0, value, endianness === "little");
    } else {
      view.setFloat64(0, value, endianness === "little");
    }
    this.bytes.push(...encoded);
  }

  luaString(
    value: string | null,
    format: ChunkFormat,
  ): number | null {
    if (value === null) {
      this.unsigned(0, format.sizeTSize, format.endianness);
      return null;
    }
    const encoded = new TextEncoder().encode(value);
    this.unsigned(
      encoded.length + 1,
      format.sizeTSize,
      format.endianness,
    );
    this.bytes.push(...encoded);
    const terminatorOffset = this.length;
    this.byte(0);
    return terminatorOffset;
  }
}

function prototype(
  overrides: Partial<PrototypeSpec> = {},
): PrototypeSpec {
  return {
    source: "@minimal.lua",
    lineDefined: 0,
    lastLineDefined: 0,
    upvalueCount: 0,
    parameterCount: 0,
    varargFlags: 2,
    maxStackSize: 2,
    code: [RETURN],
    constants: [],
    children: [],
    lineInfo: [],
    locals: [],
    upvalueNames: [],
    ...overrides,
  };
}

function buildChunk(
  main: PrototypeSpec = prototype(),
  format: ChunkFormat = DEFAULT_FORMAT,
): BuiltChunk {
  const writer = new ByteWriter();
  writer.bytes.push(0x1b, 0x4c, 0x75, 0x61);
  writer.byte(0x51);
  writer.byte(0);
  writer.byte(format.endianness === "little" ? 1 : 0);
  writer.byte(format.intSize);
  writer.byte(format.sizeTSize);
  writer.byte(4);
  writer.byte(format.numberSize);
  writer.byte(0);

  const rootLayout = writePrototype(writer, main, format);
  return {
    bytes: Uint8Array.from(writer.bytes),
    mainCodeCountOffset: rootLayout.codeCountOffset,
    mainCodeOffset: rootLayout.codeOffset,
    mainSourceTerminatorOffset: rootLayout.sourceTerminatorOffset,
  };
}

function writePrototype(
  writer: ByteWriter,
  spec: PrototypeSpec,
  format: ChunkFormat,
): {
  readonly codeCountOffset: number;
  readonly codeOffset: number;
  readonly sourceTerminatorOffset: number | null;
} {
  const sourceTerminatorOffset = writer.luaString(spec.source, format);
  writer.signed(spec.lineDefined, format.intSize, format.endianness);
  writer.signed(spec.lastLineDefined, format.intSize, format.endianness);
  writer.byte(spec.upvalueCount);
  writer.byte(spec.parameterCount);
  writer.byte(spec.varargFlags);
  writer.byte(spec.maxStackSize);

  const codeCountOffset = writer.length;
  writer.signed(spec.code.length, format.intSize, format.endianness);
  const codeOffset = writer.length;
  for (const instruction of spec.code) {
    writer.unsigned(instruction >>> 0, 4, format.endianness);
  }

  writer.signed(spec.constants.length, format.intSize, format.endianness);
  for (const constant of spec.constants) {
    switch (constant.type) {
      case "nil":
        writer.byte(0);
        break;
      case "boolean":
        writer.byte(1);
        writer.byte(constant.value ? 1 : 0);
        break;
      case "number":
        writer.byte(3);
        writer.float(
          constant.value,
          format.numberSize,
          format.endianness,
        );
        break;
      case "string":
        writer.byte(4);
        writer.luaString(constant.value, format);
        break;
    }
  }

  writer.signed(spec.children.length, format.intSize, format.endianness);
  for (const child of spec.children) {
    writePrototype(writer, child, format);
  }

  writer.signed(spec.lineInfo.length, format.intSize, format.endianness);
  for (const line of spec.lineInfo) {
    writer.signed(line, format.intSize, format.endianness);
  }

  writer.signed(spec.locals.length, format.intSize, format.endianness);
  for (const local of spec.locals) {
    writer.luaString(local.name, format);
    writer.signed(local.startPc, format.intSize, format.endianness);
    writer.signed(local.endPc, format.intSize, format.endianness);
  }

  writer.signed(spec.upvalueNames.length, format.intSize, format.endianness);
  for (const name of spec.upvalueNames) {
    writer.luaString(name, format);
  }

  return {
    codeCountOffset,
    codeOffset,
    sourceTerminatorOffset,
  };
}

function encodeABC(opcode: number, A: number, B: number, C: number): number {
  return (
    ((opcode & 0x3f) |
      ((A & 0xff) << 6) |
      ((C & 0x1ff) << 14) |
      ((B & 0x1ff) << 23)) >>>
    0
  );
}

function encodeABx(opcode: number, A: number, Bx: number): number {
  return (
    ((opcode & 0x3f) | ((A & 0xff) << 6) | ((Bx & 0x3ffff) << 14)) >>>
    0
  );
}

function encodeAsBx(opcode: number, A: number, sBx: number): number {
  return encodeABx(opcode, A, sBx + 131_071);
}

function replaceUint32(
  input: Uint8Array,
  offset: number,
  value: number,
  endianness: Lua51Endianness = "little",
): Uint8Array {
  const copy = input.slice();
  const view = new DataView(copy.buffer, copy.byteOffset, copy.byteLength);
  view.setUint32(offset, value >>> 0, endianness === "little");
  return copy;
}

function diagnosticCodes(
  result: ReturnType<typeof parseLua51Chunk>,
): string[] {
  return result.diagnostics.map((diagnostic) => diagnostic.code);
}

describe("Lua 5.1 bytecode parser", () => {
  it("parses a synthetic minimal little-endian chunk exactly", () => {
    const built = buildChunk();

    expect(isLua51Bytecode(built.bytes)).toBe(true);
    const result = parseLua51Chunk(built.bytes);

    expect(result.ok).toBe(true);
    expect(result.bytesConsumed).toBe(built.bytes.length);
    expect(result.chunk).not.toBeNull();
    expect(result.chunk?.header).toMatchObject({
      signatureHex: "1b4c7561",
      version: 0x51,
      format: 0,
      endianness: "little",
      intSize: 4,
      sizeTSize: 8,
      instructionSize: 4,
      numberSize: 8,
      numberKind: "float",
    });
    expect(result.chunk?.stats).toEqual({
      prototypeCount: 1,
      instructionCount: 1,
      constantCount: 0,
      stringBytes: 12,
      lineInfoCount: 0,
      localCount: 0,
      upvalueNameCount: 0,
    });
    expect(result.chunk?.main.source?.utf8).toBe("@minimal.lua");
    expect(result.chunk?.main.instructions[0]).toMatchObject({
      pc: 0,
      raw: RETURN,
      opcode: 30,
      opcodeName: "RETURN",
      mode: "iABC",
      A: 0,
      B: 1,
      C: 0,
    });
  });

  it("honors big-endian scalar sizes declared by the header", () => {
    const format: ChunkFormat = {
      endianness: "big",
      intSize: 4,
      sizeTSize: 4,
      numberSize: 4,
    };
    const built = buildChunk(
      prototype({
        constants: [{ type: "number", value: 1.5 }],
        code: [encodeABx(1, 0, 0), RETURN],
      }),
      format,
    );

    const result = parseLua51Chunk(built.bytes);

    expect(result.ok).toBe(true);
    expect(result.chunk?.header.endianness).toBe("big");
    expect(result.chunk?.header.sizeTSize).toBe(4);
    expect(result.chunk?.header.numberSize).toBe(4);
    expect(result.chunk?.main.constants[0]).toMatchObject({
      type: "number",
      kind: "float",
      value: 1.5,
    });
    expect(result.chunk?.main.instructions[0]?.opcodeName).toBe("LOADK");
  });

  it("parses constants, children, locals, line arrays, and upvalue names", () => {
    const child = prototype({
      source: null,
      upvalueCount: 1,
      code: [RETURN],
      lineInfo: [9],
      upvalueNames: ["captured"],
    });
    const code = [
      encodeABx(1, 0, 2),
      encodeABx(36, 1, 0),
      encodeABC(0, 0, 0, 0),
      RETURN,
    ];
    const built = buildChunk(
      prototype({
        code,
        constants: [
          { type: "nil" },
          { type: "boolean", value: true },
          { type: "number", value: 42.25 },
          { type: "string", value: "hello\u0000bytes" },
        ],
        children: [child],
        lineInfo: [3, 3, 3, 4],
        locals: [{ name: "value", startPc: 0, endPc: 4 }],
      }),
    );

    const result = parseLua51Chunk(built.bytes);

    expect(result.ok).toBe(true);
    expect(result.chunk?.stats).toMatchObject({
      prototypeCount: 2,
      instructionCount: 5,
      constantCount: 4,
      lineInfoCount: 5,
      localCount: 1,
      upvalueNameCount: 1,
    });
    expect(result.chunk?.main.constants.map((constant) => constant.type)).toEqual([
      "nil",
      "boolean",
      "number",
      "string",
    ]);
    expect(result.chunk?.main.prototypes[0]?.source).toBeNull();
    expect(result.chunk?.main.prototypes[0]?.upvalueNames[0]?.utf8).toBe(
      "captured",
    );
    expect(result.chunk?.main.locals[0]).toMatchObject({
      startPc: 0,
      endPc: 4,
    });
  });

  it.each([
    [0, 0x00, "LUA51_INVALID_SIGNATURE"],
    [4, 0x52, "LUA51_UNSUPPORTED_VERSION"],
    [5, 0x01, "LUA51_UNSUPPORTED_FORMAT"],
    [6, 0x02, "LUA51_INVALID_ENDIANNESS"],
    [7, 0x03, "LUA51_UNSUPPORTED_SCALAR_SIZE"],
    [8, 0x03, "LUA51_UNSUPPORTED_SCALAR_SIZE"],
    [9, 0x08, "LUA51_UNSUPPORTED_INSTRUCTION_SIZE"],
    [10, 0x10, "LUA51_UNSUPPORTED_NUMBER_SIZE"],
    [11, 0x02, "LUA51_INVALID_NUMBER_FORMAT"],
  ] as const)(
    "rejects malformed header byte %i",
    (offset, replacement, expectedCode) => {
      const bytes = buildChunk().bytes.slice();
      bytes[offset] = replacement;

      const result = parseLua51Chunk(bytes);

      expect(result.ok).toBe(false);
      expect(result.chunk).toBeNull();
      expect(diagnosticCodes(result)).toContain(expectedCode);
    },
  );

  it("rejects a string without its declared trailing NUL", () => {
    const built = buildChunk();
    const bytes = built.bytes.slice();
    expect(built.mainSourceTerminatorOffset).not.toBeNull();
    bytes[built.mainSourceTerminatorOffset ?? 0] = 0x78;

    const result = parseLua51Chunk(bytes);

    expect(result.ok).toBe(false);
    expect(diagnosticCodes(result)).toContain(
      "LUA51_STRING_MISSING_TERMINATOR",
    );
  });

  it("fails safely at every truncated prefix", () => {
    const bytes = buildChunk(
      prototype({
        constants: [{ type: "string", value: "payload" }],
        lineInfo: [1],
      }),
    ).bytes;

    for (let length = 0; length < bytes.length; length += 1) {
      const prefix = bytes.slice(0, length);
      const result = parseLua51Chunk(prefix);
      expect(result.ok, `prefix length ${length}`).toBe(false);
      expect(result.bytesConsumed, `prefix length ${length}`).toBeLessThanOrEqual(
        length,
      );
    }
  });

  it("rejects negative and oversized counts before iterating or allocating", () => {
    const built = buildChunk();
    const negative = replaceUint32(
      built.bytes,
      built.mainCodeCountOffset,
      0xffff_ffff,
    );
    const oversized = replaceUint32(
      built.bytes,
      built.mainCodeCountOffset,
      0x7fff_ffff,
    );

    expect(diagnosticCodes(parseLua51Chunk(negative))).toContain(
      "LUA51_NEGATIVE_COUNT",
    );
    expect(diagnosticCodes(parseLua51Chunk(oversized))).toContain(
      "LUA51_LIMIT_INSTRUCTIONS_PER_PROTOTYPE",
    );
  });

  it("enforces configurable input, string, instruction, total, and depth limits", () => {
    const twoInstructions = buildChunk(
      prototype({ code: [encodeABC(0, 0, 0, 0), RETURN] }),
    );
    expect(
      diagnosticCodes(
        parseLua51Chunk(twoInstructions.bytes, {
          limits: { maxInputBytes: twoInstructions.bytes.length - 1 },
        }),
      ),
    ).toContain("LUA51_LIMIT_INPUT_BYTES");
    expect(
      diagnosticCodes(
        parseLua51Chunk(twoInstructions.bytes, {
          limits: { maxStringBytes: 4 },
        }),
      ),
    ).toContain("LUA51_LIMIT_STRING_BYTES");
    expect(
      diagnosticCodes(
        parseLua51Chunk(twoInstructions.bytes, {
          limits: { maxInstructionsPerPrototype: 1 },
        }),
      ),
    ).toContain("LUA51_LIMIT_INSTRUCTIONS_PER_PROTOTYPE");

    const nested = buildChunk(
      prototype({
        children: [
          prototype({
            source: null,
            children: [prototype({ source: null })],
          }),
        ],
      }),
    );
    expect(
      diagnosticCodes(
        parseLua51Chunk(nested.bytes, {
          limits: { maxPrototypeDepth: 1 },
        }),
      ),
    ).toContain("LUA51_LIMIT_PROTOTYPE_DEPTH");
    expect(
      diagnosticCodes(
        parseLua51Chunk(nested.bytes, {
          limits: { maxInstructionsTotal: 2 },
        }),
      ),
    ).toContain("LUA51_LIMIT_INSTRUCTIONS_TOTAL");
  });

  it("rejects trailing bytes instead of silently accepting a prefix chunk", () => {
    const valid = buildChunk().bytes;
    const withTrailingByte = new Uint8Array(valid.length + 1);
    withTrailingByte.set(valid);
    withTrailingByte[valid.length] = 0xaa;

    const result = parseLua51Chunk(withTrailingByte);

    expect(result.ok).toBe(false);
    expect(result.chunk).not.toBeNull();
    expect(diagnosticCodes(result)).toContain("LUA51_TRAILING_BYTES");
  });
});

describe("Lua 5.1 instruction validation and audit text", () => {
  it("decodes exact fields and direct branch targets", () => {
    expect(decodeLua51Instruction(encodeABC(12, 3, 256, 2), 7)).toMatchObject({
      opcode: 12,
      opcodeName: "ADD",
      mode: "iABC",
      A: 3,
      B: 256,
      C: 2,
    });
    expect(decodeLua51Instruction(encodeAsBx(22, 0, -2), 7)).toMatchObject({
      opcodeName: "JMP",
      mode: "iAsBx",
      sBx: -2,
      branchTarget: 6,
    });
  });

  it("emits stable raw instruction text, targets, constants, and diagnostics", () => {
    const built = buildChunk(
      prototype({
        code: [encodeABx(1, 0, 0), encodeAsBx(22, 0, 0), RETURN],
        constants: [{ type: "string", value: "audit" }],
      }),
    );
    const inspection = inspectLua51Bytecode(built.bytes);

    expect(inspection.ok).toBe(true);
    expect(inspection.auditText).toContain(
      "; Lua 5.1 bytecode exact static audit",
    );
    expect(inspection.auditText).toContain(
      "raw=0x00000001 LOADK A=0 Bx=0",
    );
    expect(inspection.auditText).toContain("JMP A=0 sBx=+0 target=2");
    expect(inspection.auditText).toContain('K[0] string bytes=5 value="audit"');
    expect(inspection.auditText).toContain(".diagnostics 0");
  });

  it("marks SETLIST extra words as data instead of decoding them as opcodes", () => {
    const arbitraryDataWord = 0xffff_ffff;
    const built = buildChunk(
      prototype({
        code: [
          encodeABC(34, 0, 1, 0),
          arbitraryDataWord,
          RETURN,
        ],
      }),
    );
    const result = parseLua51Chunk(built.bytes);
    const audit =
      result.chunk === null ? null : disassembleLua51Chunk(result.chunk);

    expect(result.ok).toBe(true);
    expect(audit?.text).toContain(
      "raw=0xffffffff SETLIST_EXTRA value=4294967295",
    );
    expect(audit?.diagnostics.map((diagnostic) => diagnostic.code)).not.toContain(
      "LUA51_INVALID_OPCODE",
    );
  });

  it("diagnoses unknown opcodes, invalid branches, and missing SETLIST data", () => {
    const unknownBuilt = buildChunk();
    const unknown = replaceUint32(
      unknownBuilt.bytes,
      unknownBuilt.mainCodeOffset,
      0x3f,
    );
    expect(diagnosticCodes(parseLua51Chunk(unknown))).toContain(
      "LUA51_INVALID_OPCODE",
    );

    const invalidBranch = buildChunk(
      prototype({ code: [encodeAsBx(22, 0, 10), RETURN] }),
    );
    expect(diagnosticCodes(parseLua51Chunk(invalidBranch.bytes))).toContain(
      "LUA51_BRANCH_OUT_OF_RANGE",
    );

    const missingSetList = buildChunk(
      prototype({ code: [encodeABC(34, 0, 1, 0)] }),
    );
    expect(diagnosticCodes(parseLua51Chunk(missingSetList.bytes))).toContain(
      "LUA51_MISSING_SETLIST_EXTRA",
    );
  });

  it("bounds diagnostics and audit output with explicit limit diagnostics", () => {
    const invalidCode = Array.from({ length: 10 }, () => 0x3f);
    const parsed = parseLua51Chunk(
      buildChunk(prototype({ code: invalidCode })).bytes,
      { limits: { maxDiagnostics: 2 } },
    );
    expect(parsed.ok).toBe(false);
    expect(parsed.diagnostics).toHaveLength(2);
    expect(parsed.diagnostics[1]?.code).toBe("LUA51_LIMIT_DIAGNOSTICS");

    const valid = parseLua51Chunk(buildChunk().bytes);
    expect(valid.chunk).not.toBeNull();
    const disassembly =
      valid.chunk === null
        ? null
        : disassembleLua51Chunk(valid.chunk, {
            limits: { maxAuditChars: 120, maxAuditLines: 3 },
          });
    expect(disassembly?.truncated).toBe(true);
    expect(
      disassembly?.diagnostics.map((diagnostic) => diagnostic.code),
    ).toContain("LUA51_LIMIT_AUDIT_OUTPUT");
    expect(disassembly?.text.length).toBeLessThanOrEqual(120);
  });
});
