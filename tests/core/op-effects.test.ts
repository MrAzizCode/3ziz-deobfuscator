import { describe, expect, it } from "vitest";

import { knownSemantic } from "../../src/core/recovery/jnkie-semantic-emitter";
import {
  provenOpcodes,
  resolveOpEffect,
  type JnkieOpEffect,
} from "../../src/core/recovery/op-effects";
import type {
  JnkieDecodedInstruction,
  JnkieInstructionChannel,
} from "../../src/core/recovery/jnkie-record-model";

const EMPTY_RANGE = { start: 0, end: 0 } as const;

function channel(
  payload: number,
  overrides: Partial<JnkieInstructionChannel> = {},
): JnkieInstructionChannel {
  return {
    mode: 7,
    payload,
    resolvedValue: payload,
    constantIndex: null,
    childPrototypeIndex: null,
    ...overrides,
  };
}

function instruction(
  rawOpcode: number,
  a: JnkieInstructionChannel,
  n: JnkieInstructionChannel,
  q: JnkieInstructionChannel,
): JnkieDecodedInstruction {
  return {
    pc: 1,
    rawOpcode,
    byteRange: EMPTY_RANGE,
    wordByteRanges: [EMPTY_RANGE, EMPTY_RANGE, EMPTY_RANGE, EMPTY_RANGE],
    rawWords: [0, rawOpcode, 0, 0],
    channels: { A: a, N: n, Q: q },
  };
}

function plain(rawOpcode: number, a: number, n: number, q: number) {
  return instruction(rawOpcode, channel(a), channel(n), channel(q));
}

function effectOf(op: JnkieDecodedInstruction): JnkieOpEffect {
  const resolved = resolveOpEffect(op, 0);
  if (resolved === null) throw new Error(`opcode ${op.rawOpcode} did not resolve`);
  return resolved.effect;
}

describe("typed opcode effects", () => {
  it("resolves exactly the opcodes the pseudocode emitter proves", () => {
    // Drift between the two tables would silently shrink devirtualization
    // coverage or invent an effect the emitter never proved.
    for (let opcode = 0; opcode < 300; opcode += 1) {
      const op = plain(opcode, 3, 5, 7);
      const typed = resolveOpEffect(op, 0);
      const rendered = knownSemantic(op, 0);
      expect(
        typed === null,
        `opcode ${opcode} resolution disagrees with the emitter`,
      ).toBe(rendered === null);
      if (typed !== null && rendered !== null) {
        expect(typed.name, `opcode ${opcode} name`).toBe(rendered.name);
      }
    }
  });

  it("lists every opcode it resolves", () => {
    const listed = [...provenOpcodes()].sort((left, right) => left - right);
    const actual: number[] = [];
    for (let opcode = 0; opcode < 300; opcode += 1) {
      if (resolveOpEffect(plain(opcode, 1, 2, 3), 0) !== null) actual.push(opcode);
    }
    expect(listed).toEqual(actual);
    expect(new Set(listed).size).toBe(listed.length);
  });

  it("refuses selectors the handler table was never proven for", () => {
    expect(resolveOpEffect(plain(187, 1, 2, 3), 3)).toBeNull();
  });

  it("reads operand channels in the emitter's precedence order", () => {
    // Constant beats prototype beats resolved value beats raw payload.
    const constantChannel = channel(9, { constantIndex: 4, childPrototypeIndex: 2 });
    const loadConstant = effectOf(
      instruction(71, constantChannel, channel(6), channel(0)),
    );
    expect(loadConstant).toEqual({
      kind: "assign",
      target: 6,
      expression: { kind: "value", value: { kind: "constant", index: 4 } },
    });

    const prototypeChannel = channel(9, { childPrototypeIndex: 12 });
    const closure = effectOf(
      instruction(84, channel(2), prototypeChannel, channel(0)),
    );
    expect(closure).toEqual({
      kind: "assign",
      target: 2,
      expression: { kind: "closure", prototype: { kind: "prototype", index: 12 } },
    });
  });

  it("models register motion and table access", () => {
    expect(effectOf(plain(187, 4, 9, 0))).toEqual({
      kind: "assign",
      target: 9,
      expression: { kind: "value", value: { kind: "register", index: 4 } },
    });
    expect(effectOf(plain(215, 1, 2, 3))).toEqual({
      kind: "assign",
      target: 3,
      expression: {
        kind: "table-get",
        table: { kind: "register", index: 2 },
        key: { kind: "register", index: 1 },
      },
    });
    expect(effectOf(plain(253, 1, 2, 3))).toEqual({
      kind: "table-set",
      table: { kind: "register", index: 3 },
      key: { kind: "register", index: 2 },
      value: { kind: "register", index: 1 },
    });
    expect(effectOf(plain(97, 5, 8, 0))).toEqual({
      kind: "self",
      target: 5,
      object: 8,
      key: { kind: "number", value: 0 },
    });
  });

  it("keeps operand order for non-commutative arithmetic", () => {
    // SUBTRACT_REG_REG is `R[a] = R[q] - R[n]`: swapping these would silently
    // negate every subtraction in the recovered source.
    expect(effectOf(plain(34, 1, 2, 3))).toEqual({
      kind: "assign",
      target: 1,
      expression: {
        kind: "binary",
        operator: "sub",
        left: { kind: "register", index: 3 },
        right: { kind: "register", index: 2 },
      },
    });
    expect(effectOf(plain(263, 4, 5, 6))).toEqual({
      kind: "assign",
      target: 5,
      expression: {
        kind: "binary",
        operator: "sub",
        left: { kind: "number", value: 6 },
        right: { kind: "register", index: 4 },
      },
    });
  });

  it("resolves jump targets to the instruction after the encoded one", () => {
    expect(effectOf(plain(136, 0, 41, 0))).toEqual({ kind: "jump", target: 42 });
    expect(effectOf(plain(21, 7, 41, 0))).toEqual({
      kind: "test",
      operand: 7,
      expect: "truthy",
      target: 42,
    });
    expect(effectOf(plain(161, 41, 2, 3))).toEqual({
      kind: "compare-jump",
      operator: "lt",
      left: { kind: "register", index: 2 },
      right: { kind: "register", index: 3 },
      target: 42,
    });
  });

  it("decodes the biased generic call encoding", () => {
    // count 0 is open, 1 is empty, otherwise count - 1.
    expect(effectOf(plain(62, 10, 0, 1))).toEqual({
      kind: "call",
      base: 10,
      arguments: { kind: "to-top", first: 11 },
      results: { kind: "none", newTop: 9 },
    });
    expect(effectOf(plain(62, 10, 1, 0))).toEqual({
      kind: "call",
      base: 10,
      arguments: { kind: "fixed", first: 11, count: 0 },
      results: { kind: "all", first: 10 },
    });
    expect(effectOf(plain(62, 10, 4, 3))).toEqual({
      kind: "call",
      base: 10,
      arguments: { kind: "fixed", first: 11, count: 3 },
      results: { kind: "fixed", first: 10, count: 2 },
    });
  });

  it("models returns, varargs, and bulk table stores", () => {
    expect(effectOf(plain(118, 0, 0, 0))).toEqual({
      kind: "return",
      values: { kind: "none" },
      closesUpvalues: true,
    });
    expect(effectOf(plain(79, 0, 6, 4))).toEqual({
      kind: "return",
      values: { kind: "fixed", first: 6, count: 3 },
      closesUpvalues: true,
    });
    expect(effectOf(plain(154, 3, 0, 8))).toEqual({
      kind: "vararg",
      first: 8,
      count: 3,
      source: "cursor",
    });
    expect(effectOf(plain(75, 2, 5, 9))).toEqual({
      kind: "table-move",
      destination: 2,
      sourceFirst: 3,
      sourceLast: 7,
      destinationFirst: 10,
    });
  });
});
