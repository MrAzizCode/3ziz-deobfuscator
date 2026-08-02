import { describe, expect, it } from "vitest";

import { devirtualizeSection } from "../../src/core/devirt";
import { inlineSingleUseTemporaries } from "../../src/core/devirt/lift";
import { renderStatements, type LuaStatement } from "../../src/core/devirt/lua-ast";
import { decodeJnkieRecordStream } from "../../src/core/recovery/jnkie-record-decoder";
import { parseLuau } from "../../src/core/source/luau-parser";

function uleb(value: number): number[] {
  const bytes: number[] = [];
  let remaining = value;
  do {
    const byte = remaining % 128;
    remaining = Math.floor(remaining / 128);
    bytes.push(remaining > 0 ? byte | 0x80 : byte);
  } while (remaining > 0);
  return bytes;
}

/** A channel word packs `payload * 8 + mode`; mode 2 is a constant reference. */
const reg = (index: number): number => index * 8 + 7;
const konst = (index: number): number => index * 8 + 2;
const child = (index: number): number => index * 8 + 4;
const NONE = 7;

interface ProtoSpec {
  readonly instructions: readonly (readonly number[])[];
  readonly captures?: readonly number[];
  readonly maxStack?: number;
}

/**
 * Assemble a record stream with zero count biases so the decoder reads it
 * without needing a profile. Constants use tag 110 (string) and tag 1
 * (negative-u8 integer), matching the decoder's tag ranges.
 */
function buildStream(
  strings: readonly string[],
  prototypes: readonly ProtoSpec[],
  rootIndex: number,
): Uint8Array {
  const bytes: number[] = [];
  bytes.push(...uleb(strings.length));
  bytes.push(0);
  for (const text of strings) {
    bytes.push(110);
    bytes.push(...uleb(text.length));
    for (const character of text) bytes.push(character.charCodeAt(0));
  }
  bytes.push(...uleb(prototypes.length));
  for (const prototype of prototypes) {
    bytes.push(...uleb(prototype.instructions.length));
    for (const words of prototype.instructions) {
      for (const word of words) bytes.push(...uleb(word));
    }
    bytes.push(...uleb(0)); // selector
    const captures = prototype.captures ?? [];
    bytes.push(...uleb(captures.length));
    for (const capture of captures) bytes.push(...uleb(capture));
    bytes.push(...uleb(prototype.maxStack ?? 8));
  }
  bytes.push(...uleb(rootIndex));
  return Uint8Array.from(bytes);
}

const ZERO_BIAS_FORMAT = {
  schemaVersion: 1,
  constantCountBias: 0,
  prototypeCountBias: 0,
  instructionCountBias: 0,
  indexBase: 1,
  byteRangeConvention: "zero-based-half-open",
} as const;

function decode(bytes: Uint8Array) {
  return decodeJnkieRecordStream(bytes, {
    format: ZERO_BIAS_FORMAT,
    decodeNestedSection: false,
    rejectTrailingBytes: true,
    limits: {
      maxInputBytes: 65_536,
      maxConstants: 256,
      maxConstantValueBytes: 4_096,
      maxPrototypes: 256,
      maxInstructionsPerPrototype: 4_096,
      maxInstructionsTotal: 16_384,
      maxCapturesPerPrototype: 64,
      maxCapturesTotal: 256,
    },
  });
}

/** `print("hello")` as the VM encodes it. */
function helloWorldStream(): Uint8Array {
  return buildStream(
    ["print", "hello"],
    [
      {
        instructions: [
          // 271 LOAD_ENVIRONMENT_KEY: R[Q] = ENVIRONMENT[K(A)]
          [konst(1), 271, NONE, reg(1)],
          // 71 LOAD_CONSTANT: R[N] = K(A)
          [konst(2), 71, reg(2), NONE],
          // 20 CALL_ONE_ARGUMENT_NO_RESULTS: base = N
          [NONE, 20, reg(1), NONE],
          // 118 RETURN_ZERO_RESULTS
          [NONE, 118, NONE, NONE],
        ],
      },
    ],
    1,
  );
}

describe("devirtualization to Lua", () => {
  it("recovers a call through a real global name", () => {
    const records = decode(helloWorldStream());
    const result = devirtualizeSection(records.primarySection);

    expect(result.reparses).toBe(true);
    expect(result.coverage.unresolvedInstructions).toBe(0);
    expect(result.coverage.provenRatio).toBe(1);
    // The environment key is a string constant, so the global keeps its name
    // and the temporaries fold away.
    expect(result.lua).toContain('print("hello")');
    expect(result.coverage.resolvedGlobalNames).toContain("print");
  });

  it("always emits Lua that re-parses", () => {
    const records = decode(helloWorldStream());
    const result = devirtualizeSection(records.primarySection);
    expect(() => parseLuau(result.lua)).not.toThrow();
  });

  it("preserves an unproven opcode instead of guessing", () => {
    // Opcode 999 is not in the proven handler table.
    const records = decode(
      buildStream(
        ["x"],
        [{ instructions: [[reg(1), 999, reg(2), reg(3)], [NONE, 118, NONE, NONE]] }],
        1,
      ),
    );
    const result = devirtualizeSection(records.primarySection);

    expect(result.coverage.unresolvedInstructions).toBe(1);
    expect(result.lua).toContain("[3ziz] unresolved VM op 999");
    // Operands and byte provenance survive so the record can be re-examined.
    expect(result.lua).toMatch(/A=1\/7 N=2\/7 Q=3\/7 @bytes\[\d+,\d+\)/);
    expect(result.reparses).toBe(true);
    expect(result.warnings.join(" ")).toMatch(/never proved/);
  });

  it("emits child prototypes before the closure that references them", () => {
    const records = decode(
      buildStream(
        ["k"],
        [
          // Prototype 1 is the leaf; prototype 2 closes over it.
          { instructions: [[NONE, 118, NONE, NONE]] },
          {
            instructions: [
              // 84 CREATE_CLOSURE: R[A] = CLOSURE(N)
              [reg(1), 84, child(1), NONE],
              [NONE, 118, NONE, NONE],
            ],
          },
        ],
        2,
      ),
    );
    const result = devirtualizeSection(records.primarySection);

    expect(result.reparses).toBe(true);
    expect(result.lua.indexOf("local function fn1(")).toBeLessThan(
      result.lua.indexOf("local function fn2("),
    );
    expect(result.lua).toContain("v1 = fn1");
    expect(result.lua.trimEnd().endsWith("return fn2")).toBe(true);
  });

  it("states what it did not recover in the header", () => {
    const records = decode(helloWorldStream());
    const { lua } = devirtualizeSection(records.primarySection, {
      sourceLabel: "unit fixture",
    });
    expect(lua).toContain("not the");
    expect(lua).toContain("original file");
    expect(lua).toContain("synthesized here");
    expect(lua).toContain("submitted code was never executed");
    expect(lua).toContain("source: unit fixture");
  });
});

describe("single-use temporary inlining", () => {
  const nameOf = (text: string) => ({ kind: "name", name: text }) as const;

  it("folds a chained lookup into one expression", () => {
    const statements: LuaStatement[] = [
      { kind: "assign", targets: [nameOf("v5")], values: [nameOf("game")] },
      {
        kind: "assign",
        targets: [nameOf("v6")],
        values: [
          { kind: "index", object: nameOf("v5"), key: { kind: "literal", text: '"Workspace"' } },
        ],
      },
    ];
    expect(renderStatements(inlineSingleUseTemporaries(statements))).toBe(
      "v6 = game.Workspace",
    );
  });

  it("will not move a call across a statement boundary", () => {
    // Folding here would change when the call runs relative to the store.
    const statements: LuaStatement[] = [
      {
        kind: "assign",
        targets: [nameOf("v1")],
        values: [{ kind: "call", callee: nameOf("f"), args: [] }],
      },
      { kind: "assign", targets: [nameOf("v2")], values: [nameOf("v1")] },
    ];
    expect(inlineSingleUseTemporaries(statements)).toHaveLength(2);
  });

  it("will not fold an operator expression into a prefix position", () => {
    // `(v1 < v2)[k] = v3` is not valid Lua, whatever the VM encoded.
    const statements: LuaStatement[] = [
      {
        kind: "assign",
        targets: [nameOf("v9")],
        values: [{ kind: "binary", operator: "<", left: nameOf("v1"), right: nameOf("v2") }],
      },
      {
        kind: "assign",
        targets: [
          { kind: "index", object: nameOf("v9"), key: { kind: "literal", text: "1" } },
        ],
        values: [nameOf("v3")],
      },
    ];
    const folded = inlineSingleUseTemporaries(statements);
    expect(folded).toHaveLength(2);
    expect(() => parseLuau(`local v1,v2,v3,v9\n${renderStatements(folded)}`)).not.toThrow();
  });

  it("leaves a temporary alone when it is read more than once", () => {
    const statements: LuaStatement[] = [
      { kind: "assign", targets: [nameOf("v1")], values: [nameOf("t")] },
      {
        kind: "assign",
        targets: [nameOf("v2")],
        values: [{ kind: "binary", operator: "+", left: nameOf("v1"), right: nameOf("v1") }],
      },
    ];
    expect(inlineSingleUseTemporaries(statements)).toHaveLength(2);
  });
});
