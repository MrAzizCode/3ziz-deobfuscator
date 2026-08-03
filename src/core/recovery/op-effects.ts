/**
 * Typed model of the Luraph VM handler effects that the pseudocode emitter
 * proved for the known dispatcher.
 *
 * `jnkie-semantic-emitter` renders those effects straight to audit text, which
 * is the right shape for an evidence view but useless to anything that needs
 * to reason about the program - a decompiler cannot pattern-match on prose.
 * This module states the same effects as data.
 *
 * It is deliberately additive: the emitter's text path is untouched and its
 * artifacts stay byte-identical.  `tests/core/op-effects.test.ts` renders every
 * effect back to text and compares it against the emitter across every
 * instruction of the authorized sample, so the two cannot drift apart.
 */

import {
  type JnkieDecodedInstruction,
  type JnkieInstructionChannel,
} from "./jnkie-record-model";

/** A value an effect reads: a register, a pool constant, or a literal. */
export type JnkieValue =
  | { readonly kind: "register"; readonly index: number }
  | { readonly kind: "constant"; readonly index: number }
  | { readonly kind: "prototype"; readonly index: number }
  | { readonly kind: "number"; readonly value: number };

export type JnkieBinaryOperator =
  | "add"
  | "sub"
  | "mul"
  | "div"
  | "mod"
  | "eq"
  | "ne"
  | "lt"
  | "le"
  | "gt"
  | "ge"
  | "rshift";

/** The value produced into a destination register. */
export type JnkieExpression =
  | { readonly kind: "value"; readonly value: JnkieValue }
  | { readonly kind: "nil" }
  | { readonly kind: "new-table"; readonly arrayCapacity: number }
  | { readonly kind: "closure"; readonly prototype: JnkieValue }
  | { readonly kind: "environment"; readonly key: JnkieValue }
  | { readonly kind: "upvalue"; readonly index: number }
  | { readonly kind: "runtime-slot"; readonly index: number }
  | {
      readonly kind: "table-get";
      readonly table: JnkieValue;
      readonly key: JnkieValue;
    }
  | { readonly kind: "length"; readonly operand: JnkieValue }
  | {
      readonly kind: "binary";
      readonly operator: JnkieBinaryOperator;
      readonly left: JnkieValue;
      readonly right: JnkieValue;
    };

/**
 * How a call names its arguments.  `fixed` covers the common encodings where
 * the count is immediate; `to-top` is the open form that consumes every
 * register up to the VM's stack top.
 */
export type JnkieCallArguments =
  | { readonly kind: "fixed"; readonly first: number; readonly count: number }
  | { readonly kind: "to-top"; readonly first: number };

export type JnkieCallResults =
  | { readonly kind: "none"; readonly newTop: number }
  | { readonly kind: "fixed"; readonly first: number; readonly count: number }
  | { readonly kind: "all"; readonly first: number };

export type JnkieReturnValues =
  | { readonly kind: "none" }
  | { readonly kind: "fixed"; readonly first: number; readonly count: number };

export type JnkieOpEffect =
  | {
      readonly kind: "assign";
      readonly target: number;
      readonly expression: JnkieExpression;
    }
  | {
      readonly kind: "table-set";
      readonly table: JnkieValue;
      readonly key: JnkieValue;
      readonly value: JnkieValue;
    }
  /** `R[target+1] = R[object]; R[target] = R[object][key]` for method calls. */
  | {
      readonly kind: "self";
      readonly target: number;
      readonly object: number;
      readonly key: JnkieValue;
    }
  | {
      readonly kind: "call";
      readonly base: number;
      readonly arguments: JnkieCallArguments;
      readonly results: JnkieCallResults;
    }
  | {
      readonly kind: "tailcall";
      readonly base: number;
      readonly arguments: JnkieCallArguments;
    }
  | {
      readonly kind: "return";
      readonly values: JnkieReturnValues;
      readonly closesUpvalues: boolean;
    }
  | { readonly kind: "jump"; readonly target: number }
  | {
      readonly kind: "test";
      readonly operand: number;
      readonly expect: "truthy" | "falsy";
      readonly target: number;
    }
  | {
      readonly kind: "compare-jump";
      readonly operator: JnkieBinaryOperator;
      readonly left: JnkieValue;
      readonly right: JnkieValue;
      readonly target: number;
    }
  /** Numeric `for` setup; `base` is the control-variable register. */
  | {
      readonly kind: "for-prep";
      readonly base: number;
      readonly target: number;
    }
  | {
      readonly kind: "for-loop";
      readonly variable: number;
      readonly target: number;
    }
  | {
      readonly kind: "vararg";
      readonly first: number;
      readonly count: number;
      readonly source: "incoming-prefix" | "cursor";
    }
  /** Bulk array store, Lua's SETLIST. */
  | {
      readonly kind: "table-move";
      readonly destination: number;
      readonly sourceFirst: number;
      readonly sourceLast: number;
      readonly destinationFirst: number;
    }
  | {
      readonly kind: "clear-range";
      readonly first: number;
      readonly last: number;
    };

export interface JnkieResolvedOp {
  /** Stable handler name, matching the pseudocode emitter's vocabulary. */
  readonly name: string;
  readonly effect: JnkieOpEffect;
}

function register(index: number): JnkieValue {
  return { kind: "register", index };
}

/**
 * Mode 7 is the register addressing mode.
 *
 * Measured across the authorized sample, 96-98% of mode-7 payloads fall inside
 * their prototype's declared frame, against 10-15% for mode 2 (a constant
 * index, payloads up to 2,335) and 32-65% for modes 3 and 6 (relative program
 * counters).  Reading a payload as a register without checking the mode
 * invents registers that cannot exist - a frame of 30 slots does not have a
 * register 2,315.
 */
const REGISTER_MODE = 7;

function isRegisterChannel(channel: JnkieInstructionChannel): boolean {
  return channel.mode === REGISTER_MODE;
}

/** Every register index an effect names. */
function registerIndices(effect: JnkieOpEffect): readonly number[] {
  const out: number[] = [];
  const take = (value: JnkieValue): void => {
    if (value.kind === "register") out.push(value.index);
  };
  switch (effect.kind) {
    case "assign": {
      out.push(effect.target);
      const expression = effect.expression;
      if (expression.kind === "value") take(expression.value);
      else if (expression.kind === "table-get") {
        take(expression.table);
        take(expression.key);
      } else if (expression.kind === "binary") {
        take(expression.left);
        take(expression.right);
      } else if (expression.kind === "length") take(expression.operand);
      break;
    }
    case "table-set":
      take(effect.table);
      take(effect.key);
      take(effect.value);
      break;
    case "self":
      // The receiver copy lands in target + 1.
      out.push(effect.target, effect.target + 1, effect.object);
      take(effect.key);
      break;
    case "call":
      out.push(effect.base);
      // Range ends matter as much as bases: an argument or result count read
      // from a non-register channel would span thousands of slots.
      if (effect.arguments.kind === "fixed") {
        out.push(effect.arguments.first + Math.max(0, effect.arguments.count - 1));
      } else {
        out.push(effect.arguments.first);
      }
      if (effect.results.kind === "fixed") {
        out.push(effect.results.first + Math.max(0, effect.results.count - 1));
      } else if (effect.results.kind === "all") {
        out.push(effect.results.first);
      }
      break;
    case "tailcall":
      out.push(effect.base);
      if (effect.arguments.kind === "fixed") {
        out.push(effect.arguments.first + Math.max(0, effect.arguments.count - 1));
      } else {
        out.push(effect.arguments.first);
      }
      break;
    case "vararg":
      out.push(effect.first, effect.first + Math.max(0, effect.count - 1));
      break;
    case "test":
      out.push(effect.operand);
      break;
    case "compare-jump":
      take(effect.left);
      take(effect.right);
      break;
    case "clear-range":
      out.push(effect.first, effect.last);
      break;
    case "table-move":
      out.push(effect.destination, effect.sourceLast);
      break;
    case "return":
      if (effect.values.kind === "fixed") {
        out.push(
          effect.values.first,
          effect.values.first + Math.max(0, effect.values.count - 1),
        );
      }
      break;
    default:
      break;
  }
  return out;
}

/**
 * Reject an effect that names a register no operand could have supplied.
 *
 * Handlers read operand payloads positionally, so a channel carrying a
 * constant index or a relative program counter would otherwise be lifted as a
 * register.  Every genuine register comes from a mode-7 channel, and handlers
 * only ever offset one by a small fixed amount (`base + 1`, `q + 3`), so an
 * index beyond the largest mode-7 payload plus that slack did not come from
 * this instruction and the effect is not trustworthy.
 */
const REGISTER_OFFSET_SLACK = 4;

function effectRegistersArePlausible(
  effect: JnkieOpEffect,
  channels: readonly JnkieInstructionChannel[],
): boolean {
  let ceiling = -1;
  for (const channel of channels) {
    if (isRegisterChannel(channel) && channel.payload > ceiling) {
      ceiling = channel.payload;
    }
  }
  if (ceiling < 0) return false;
  const limit = ceiling + REGISTER_OFFSET_SLACK;
  for (const index of registerIndices(effect)) {
    if (!Number.isFinite(index) || index < 0 || index > limit) return false;
  }
  return true;
}

function literal(value: number): JnkieValue {
  return { kind: "number", value };
}

/**
 * Resolve one operand channel, matching the emitter's `auxiliary()` precedence:
 * a constant reference wins, then a child prototype, then the resolved value,
 * then the raw payload.
 */
function auxiliary(channel: JnkieInstructionChannel): JnkieValue {
  if (channel.constantIndex !== null) {
    return { kind: "constant", index: channel.constantIndex };
  }
  if (channel.childPrototypeIndex !== null) {
    return { kind: "prototype", index: channel.childPrototypeIndex };
  }
  if (channel.resolvedValue !== null) return literal(channel.resolvedValue);
  return literal(channel.payload);
}

/**
 * Resolve a branch destination.
 *
 * The operand's `mode` is its addressing mode, and the record decoder has
 * already applied it: mode 1 and 7 are absolute, mode 3 is relative forward
 * (`pc + payload`), and mode 6 is relative backward (`pc - payload`).  Reading
 * the raw payload instead treats every branch as absolute, which sends all
 * 4,720 forward-relative and 1,902 backward-relative jumps in the authorized
 * sample to the wrong instruction.
 *
 * The trailing `+ 1` is the dispatcher's post-increment.
 */
function jumpTarget(channel: JnkieInstructionChannel): number {
  const resolved = channel.resolvedValue ?? channel.payload;
  return resolved + 1;
}

function assign(target: number, expression: JnkieExpression): JnkieOpEffect {
  return { kind: "assign", target, expression };
}

function binary(
  target: number,
  operator: JnkieBinaryOperator,
  left: JnkieValue,
  right: JnkieValue,
): JnkieOpEffect {
  return assign(target, { kind: "binary", operator, left, right });
}

/**
 * The generic call encoding stores `argCount` and `resultCount` biased by one,
 * with zero meaning "open" in both directions.
 */
function genericArguments(base: number, encoded: number): JnkieCallArguments {
  if (encoded === 0) return { kind: "to-top", first: base + 1 };
  return { kind: "fixed", first: base + 1, count: encoded - 1 };
}

function genericResults(base: number, encoded: number): JnkieCallResults {
  if (encoded === 0) return { kind: "all", first: base };
  if (encoded === 1) return { kind: "none", newTop: base - 1 };
  return { kind: "fixed", first: base, count: encoded - 1 };
}

/**
 * Map one decoded instruction to its proven effect, or null when the handler
 * was never proven for this dispatcher.  Callers must treat null as unknown
 * and preserve the raw record rather than guessing.
 */
export function resolveOpEffect(
  instruction: JnkieDecodedInstruction,
  selector: number,
): JnkieResolvedOp | null {
  const resolved = resolveHandler(instruction, selector);
  if (resolved === null) return null;
  // Reject an effect naming a register no operand of this instruction supplied.
  const { A, N, Q } = instruction.channels;
  return effectRegistersArePlausible(resolved.effect, [A, N, Q])
    ? resolved
    : null;
}

function resolveHandler(
  instruction: JnkieDecodedInstruction,
  selector: number,
): JnkieResolvedOp | null {
  // The handler table is proven for selector zero only.
  if (selector !== 0) return null;

  const { A, N, Q } = instruction.channels;
  const a = A.payload;
  const n = N.payload;
  const q = Q.payload;
  const K = auxiliary(A);
  const M = auxiliary(N);
  const P = auxiliary(Q);

  switch (instruction.rawOpcode) {
    // ---------------------------------------------------------- data motion
    case 187:
      return { name: "MOVE", effect: assign(n, { kind: "value", value: register(a) }) };
    case 71:
      return { name: "LOAD_CONSTANT", effect: assign(n, { kind: "value", value: K }) };
    case 25:
      return { name: "LOAD_NIL", effect: assign(q, { kind: "nil" }) };
    case 267:
      return { name: "LOAD_UPVALUE", effect: assign(q, { kind: "upvalue", index: a }) };
    case 271:
      return {
        name: "LOAD_ENVIRONMENT_KEY",
        effect: assign(q, { kind: "environment", key: K }),
      };
    case 120:
      return {
        name: "LOAD_RUNTIME_SLOT",
        effect: assign(q, { kind: "runtime-slot", index: a }),
      };
    case 84:
      return { name: "CREATE_CLOSURE", effect: assign(a, { kind: "closure", prototype: M }) };

    // --------------------------------------------------------------- tables
    case 1:
      return {
        name: "NEW_TABLE_WITH_ARRAY_CAPACITY",
        effect: assign(a, { kind: "new-table", arrayCapacity: q }),
      };
    case 188:
      return { name: "NEW_TABLE", effect: assign(q, { kind: "new-table", arrayCapacity: 0 }) };
    case 155:
      return {
        name: "GET_TABLE_CONST",
        effect: assign(n, { kind: "table-get", table: register(q), key: K }),
      };
    case 215:
      return {
        name: "GET_TABLE_REG",
        effect: assign(q, { kind: "table-get", table: register(n), key: register(a) }),
      };
    case 9:
      return {
        name: "SET_TABLE_CONST",
        effect: { kind: "table-set", table: register(n), key: P, value: K },
      };
    case 126:
      return {
        name: "SET_TABLE",
        effect: { kind: "table-set", table: register(a), key: P, value: register(n) },
      };
    case 253:
      return {
        name: "SET_TABLE_REG",
        effect: {
          kind: "table-set",
          table: register(q),
          key: register(n),
          value: register(a),
        },
      };
    case 97:
      return { name: "SELF_LOOKUP", effect: { kind: "self", target: a, object: n, key: P } };
    case 75:
      return {
        name: "TABLE_MOVE",
        effect: {
          kind: "table-move",
          destination: a,
          sourceFirst: a + 1,
          sourceLast: a + n,
          destinationFirst: q + 1,
        },
      };
    case 162:
      return { name: "LENGTH", effect: assign(n, { kind: "length", operand: register(q) }) };

    // ----------------------------------------------------------- arithmetic
    case 125:
      return { name: "ADD_REG_REG", effect: binary(n, "add", register(a), register(q)) };
    case 59:
      return { name: "ADD_REG_CONST", effect: binary(q, "add", register(n), K) };
    case 10:
      return { name: "ADD_CONST_REG", effect: binary(n, "add", K, register(q)) };
    case 135:
      return { name: "ADD_CONST_CONST", effect: binary(n, "add", K, P) };
    case 34:
      return { name: "SUBTRACT_REG_REG", effect: binary(a, "sub", register(q), register(n)) };
    case 252:
      return { name: "SUBTRACT_REG_CONST", effect: binary(a, "sub", register(q), M) };
    case 263:
      return { name: "SUBTRACT_CONST_REG", effect: binary(n, "sub", P, register(a)) };
    case 137:
      return { name: "SUBTRACT_CONST_CONST", effect: binary(q, "sub", M, K) };
    case 250:
      return { name: "MULTIPLY_REG_REG", effect: binary(a, "mul", register(q), register(n)) };
    case 266:
      return { name: "MULTIPLY_REG_CONST", effect: binary(n, "mul", register(q), K) };
    case 72:
      return { name: "MULTIPLY_CONST_CONST", effect: binary(n, "mul", P, K) };
    case 212:
      return { name: "DIVIDE_REG_CONST", effect: binary(q, "div", register(n), K) };
    case 230:
      return { name: "MODULO_REG_CONST", effect: binary(n, "mod", register(q), K) };
    case 143:
      return {
        name: "RIGHT_SHIFT_REG_REG",
        effect: binary(n, "rshift", register(a), register(q)),
      };
    case 164:
      return {
        name: "RIGHT_SHIFT_REG_IMMEDIATE",
        effect: binary(a, "rshift", register(n), P),
      };

    // ---------------------------------------------------------- comparisons
    case 127:
      return { name: "COMPARE_REG_EQ_REG", effect: binary(n, "eq", register(a), register(q)) };
    case 41:
      return { name: "COMPARE_REG_EQ_CONST", effect: binary(n, "eq", register(q), K) };
    case 5:
      return { name: "COMPARE_REG_NE_REG", effect: binary(q, "ne", register(a), register(n)) };
    case 147:
      return { name: "COMPARE_REG_NE_CONST", effect: binary(q, "ne", register(a), M) };
    case 198:
      return { name: "COMPARE_REG_LT_REG", effect: binary(a, "lt", register(n), register(q)) };
    case 255:
      return { name: "COMPARE_REG_LT_CONST", effect: binary(q, "lt", register(n), K) };
    case 14:
      return { name: "COMPARE_REG_LE_REG", effect: binary(n, "le", register(a), register(q)) };
    case 22:
      return { name: "COMPARE_REG_LE_CONST", effect: binary(q, "le", register(n), K) };
    case 77:
      return { name: "COMPARE_CONST_LE_REG", effect: binary(a, "le", P, register(n)) };
    case 208:
      return { name: "COMPARE_REG_GT_REG", effect: binary(a, "gt", register(n), register(q)) };
    case 138:
      return { name: "COMPARE_REG_GT_CONST", effect: binary(a, "gt", register(n), P) };
    case 105:
      return { name: "COMPARE_REG_GE_REG", effect: binary(q, "ge", register(a), register(n)) };
    case 150:
      return { name: "COMPARE_REG_GE_CONST", effect: binary(a, "ge", register(q), M) };

    // -------------------------------------------------------- control flow
    case 136:
      return { name: "JUMP", effect: { kind: "jump", target: jumpTarget(N) } };
    case 21:
      return {
        name: "JUMP_IF_TRUTHY",
        effect: { kind: "test", operand: a, expect: "truthy", target: jumpTarget(N) },
      };
    case 58:
      return {
        name: "JUMP_IF_FALSY",
        effect: { kind: "test", operand: a, expect: "falsy", target: jumpTarget(N) },
      };
    case 69:
      return {
        name: "JUMP_IF_REG_LE_CONST",
        effect: {
          kind: "compare-jump",
          operator: "le",
          left: register(a),
          right: M,
          target: jumpTarget(Q),
        },
      };
    case 144:
      return {
        name: "JUMP_IF_REG_NE_CONST",
        effect: {
          kind: "compare-jump",
          operator: "ne",
          left: register(q),
          right: K,
          target: jumpTarget(N),
        },
      };
    case 161:
      return {
        name: "JUMP_IF_REG_LT_REG",
        effect: {
          kind: "compare-jump",
          operator: "lt",
          left: register(n),
          right: register(q),
          target: jumpTarget(A),
        },
      };
    case 199:
      return {
        name: "JUMP_IF_REG_GE_CONST",
        effect: {
          kind: "compare-jump",
          operator: "ge",
          left: register(q),
          right: K,
          target: jumpTarget(N),
        },
      };
    case 216:
      return {
        name: "JUMP_IF_REG_NE_REG",
        effect: {
          kind: "compare-jump",
          operator: "ne",
          left: register(q),
          right: register(a),
          target: jumpTarget(N),
        },
      };
    case 176:
      return {
        name: "NUMERIC_FOR_PREP",
        effect: { kind: "for-prep", base: q, target: jumpTarget(A) },
      };
    case 73:
      return {
        name: "NUMERIC_FOR_LOOP",
        effect: { kind: "for-loop", variable: q + 3, target: jumpTarget(A) },
      };

    // --------------------------------------------------------------- calls
    case 62:
      return {
        name: "CALL_GENERIC",
        effect: {
          kind: "call",
          base: a,
          arguments: genericArguments(a, n),
          results: genericResults(a, q),
        },
      };
    case 131:
      return {
        name: "CALL_ZERO_ARGUMENTS_NO_RESULTS",
        effect: {
          kind: "call",
          base: n,
          arguments: { kind: "fixed", first: n + 1, count: 0 },
          results: { kind: "none", newTop: n - 1 },
        },
      };
    case 20:
      return {
        name: "CALL_ONE_ARGUMENT_NO_RESULTS",
        effect: {
          kind: "call",
          base: n,
          arguments: { kind: "fixed", first: n + 1, count: 1 },
          results: { kind: "none", newTop: n - 1 },
        },
      };
    case 193:
      return {
        name: "CALL_TWO_ARGUMENTS_NO_RESULTS",
        effect: {
          kind: "call",
          base: n,
          arguments: { kind: "fixed", first: n + 1, count: 2 },
          results: { kind: "none", newTop: n - 1 },
        },
      };
    case 233:
      return {
        name: "CALL_RANGE_NO_RESULTS",
        effect: {
          kind: "call",
          base: a,
          arguments: { kind: "fixed", first: a + 1, count: q - 1 },
          results: { kind: "none", newTop: a - 1 },
        },
      };
    case 259:
      return {
        name: "CALL_ZERO_ARGUMENTS_ONE_RESULT",
        effect: {
          kind: "call",
          base: q,
          arguments: { kind: "fixed", first: q + 1, count: 0 },
          results: { kind: "fixed", first: q, count: 1 },
        },
      };
    case 251:
      return {
        name: "CALL_ONE_ARGUMENT_ONE_RESULT",
        effect: {
          kind: "call",
          base: a,
          arguments: { kind: "fixed", first: a + 1, count: 1 },
          results: { kind: "fixed", first: a, count: 1 },
        },
      };
    case 87:
      return {
        name: "CALL_TWO_ARGUMENTS_ONE_RESULT",
        effect: {
          kind: "call",
          base: q,
          arguments: { kind: "fixed", first: q + 1, count: 2 },
          results: { kind: "fixed", first: q, count: 1 },
        },
      };
    case 36:
      return {
        name: "CALL_RANGE_ONE_RESULT",
        effect: {
          kind: "call",
          base: n,
          arguments: { kind: "fixed", first: n + 1, count: q - 1 },
          results: { kind: "fixed", first: n, count: 1 },
        },
      };
    case 123:
      return {
        name: "CALL_OPEN_ARGUMENTS_ONE_RESULT",
        effect: {
          kind: "call",
          base: n,
          arguments: { kind: "to-top", first: n + 1 },
          results: { kind: "fixed", first: n, count: 1 },
        },
      };
    case 50:
      return {
        name: "TAILCALL_ONE_ARGUMENT",
        effect: {
          kind: "tailcall",
          base: n,
          arguments: { kind: "fixed", first: n + 1, count: 1 },
        },
      };

    // ------------------------------------------------------------- returns
    case 118:
      return {
        name: "RETURN_ZERO_RESULTS_CLOSE_UPVALUES",
        effect: { kind: "return", values: { kind: "none" }, closesUpvalues: true },
      };
    case 219:
      return {
        name: "RETURN_ONE_RESULT_CLOSE_UPVALUES",
        effect: {
          kind: "return",
          values: { kind: "fixed", first: q, count: 1 },
          closesUpvalues: true,
        },
      };
    case 79:
      return {
        name: "RETURN_RANGE_CLOSE_UPVALUES",
        effect: {
          kind: "return",
          values: { kind: "fixed", first: n, count: q - 1 },
          closesUpvalues: true,
        },
      };

    // ------------------------------------------------------------- varargs
    case 129:
      return {
        name: "COPY_INCOMING_VARARGS_PREFIX",
        effect: { kind: "vararg", first: 1, count: q, source: "incoming-prefix" },
      };
    case 154:
      return {
        name: "COPY_VARARGS",
        effect: { kind: "vararg", first: q, count: a, source: "cursor" },
      };

    // ---------------------------------------------------------- housekeeping
    case 192:
      return { name: "CLEAR_REGISTER_RANGE", effect: { kind: "clear-range", first: a, last: q } };

    default:
      return null;
  }
}

/** Every opcode this module resolves, for coverage reporting. */
export function provenOpcodes(): readonly number[] {
  return [
    1, 5, 9, 10, 14, 20, 21, 22, 25, 34, 36, 41, 50, 58, 59, 62, 69, 71, 72, 73,
    75, 77, 79, 84, 87, 97, 105, 118, 120, 123, 125, 126, 127, 129, 131, 135,
    136, 137, 138, 143, 144, 147, 150, 154, 155, 161, 162, 164, 176, 187, 188,
    192, 193, 198, 199, 208, 212, 215, 216, 219, 230, 233, 250, 251, 252, 253,
    255, 259, 263, 266, 267, 271,
  ];
}
