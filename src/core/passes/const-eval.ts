/**
 * Total, side-effect-free evaluator for a whitelisted subset of Lua.
 *
 * Control-flow-flattened obfuscators drive a dispatcher with a state variable
 * whose next value is computed by dense integer arithmetic over a seed table.
 * Recovering the real control flow means computing those values - but the
 * project's rule is that submitted code is never executed, so this interprets
 * *our own AST* over *our own* value model instead of handing anything to a
 * Lua runtime.
 *
 * The subset is deliberately small and total: literals, arithmetic, bitwise,
 * comparison, concatenation, `and`/`or`/`not`, and reads of tables this
 * evaluator itself built. Anything else - a call, a vararg, an unknown name,
 * a metamethod-capable operand - returns `null`, meaning "not known", never a
 * guess.
 *
 * Lua 5.4 numeric semantics are followed: integers and floats are distinct,
 * integer arithmetic wraps at 64 bits, and bitwise operands must be integral.
 */

import type { LuauNode } from "../source/luau-parser";

export type LuaValue =
  | { readonly kind: "nil" }
  | { readonly kind: "boolean"; readonly value: boolean }
  | { readonly kind: "integer"; readonly value: bigint }
  | { readonly kind: "float"; readonly value: number }
  | { readonly kind: "string"; readonly value: string }
  | { readonly kind: "table"; readonly entries: ReadonlyMap<string, LuaValue> };

export const NIL: LuaValue = { kind: "nil" };

const TWO_64 = 1n << 64n;
const SIGN_BIT = 1n << 63n;

/** Wrap a big integer into Lua's signed 64-bit range. */
function wrap64(value: bigint): bigint {
  const masked = ((value % TWO_64) + TWO_64) % TWO_64;
  return masked >= SIGN_BIT ? masked - TWO_64 : masked;
}

export function integer(value: bigint): LuaValue {
  return { kind: "integer", value: wrap64(value) };
}

export function float(value: number): LuaValue {
  return { kind: "float", value };
}

export function boolean(value: boolean): LuaValue {
  return { kind: "boolean", value };
}

export function string(value: string): LuaValue {
  return { kind: "string", value };
}

/** Lua truthiness: only `nil` and `false` are falsy. */
export function isTruthy(value: LuaValue): boolean {
  if (value.kind === "nil") return false;
  if (value.kind === "boolean") return value.value;
  return true;
}

/** Canonical table key, so 1 and 1.0 address the same slot as in Lua. */
function tableKey(value: LuaValue): string | null {
  switch (value.kind) {
    case "integer":
      return `n:${value.value.toString()}`;
    case "float":
      if (!Number.isFinite(value.value)) return null;
      return Number.isInteger(value.value)
        ? `n:${BigInt(value.value).toString()}`
        : `f:${value.value}`;
    case "string":
      return `s:${value.value}`;
    case "boolean":
      return `b:${value.value}`;
    default:
      return null;
  }
}

/**
 * Read an integer literal exactly, without going through a double.
 * Returns null when the text is not an integer literal this evaluator models.
 */
function parseExactInteger(raw: string): bigint | null {
  try {
    if (/^0[xX][0-9a-fA-F]+$/.test(raw)) return wrap64(BigInt(raw));
    if (/^0[bB][01]+$/.test(raw)) return wrap64(BigInt(`0b${raw.slice(2)}`));
    if (/^\d+$/.test(raw)) return wrap64(BigInt(raw));
    return null;
  } catch {
    return null;
  }
}

export function numberToValue(raw: number): LuaValue {
  return Number.isInteger(raw) && Math.abs(raw) <= Number.MAX_SAFE_INTEGER
    ? integer(BigInt(raw))
    : float(raw);
}

/** Numeric view of a value, or null when it is not a number. */
function asNumber(value: LuaValue): { int: bigint | null; num: number } | null {
  if (value.kind === "integer") return { int: value.value, num: Number(value.value) };
  if (value.kind === "float") return { int: null, num: value.value };
  return null;
}

/** Bitwise operands must be integers, or floats with an exact integer value. */
function asInteger(value: LuaValue): bigint | null {
  if (value.kind === "integer") return value.value;
  if (value.kind === "float" && Number.isInteger(value.value)) {
    return BigInt(value.value);
  }
  return null;
}

export interface ConstEvalScope {
  /** Named bindings visible to the expression. */
  readonly variables: ReadonlyMap<string, LuaValue>;
}

export interface ConstEvalOptions {
  /** Abort after this many nodes so a hostile input cannot stall analysis. */
  readonly maxNodes?: number;
}

const DEFAULT_MAX_NODES = 200_000;

class Evaluator {
  private visited = 0;

  constructor(
    private readonly scope: ConstEvalScope,
    private readonly maxNodes: number,
  ) {}

  eval(node: LuauNode | null | undefined): LuaValue | null {
    if (node === null || node === undefined) return null;
    this.visited += 1;
    if (this.visited > this.maxNodes) return null;

    switch (node.type) {
      case "NumericLiteral":
        return this.numeric(node);
      case "StringLiteral":
        return string(String(node.value ?? ""));
      case "BooleanLiteral":
        return boolean(node.value === true);
      case "NilLiteral":
        return NIL;
      case "Identifier": {
        const found = this.scope.variables.get(String(node.name));
        return found ?? null;
      }
      case "ParenthesisExpression":
        return this.eval(node.expression as LuauNode);
      case "UnaryExpression":
        return this.unary(node);
      case "BinaryExpression":
        return this.binary(node);
      case "LogicalExpression":
        return this.logical(node);
      case "TableConstructorExpression":
        return this.table(node);
      case "IndexExpression": {
        const base = this.eval(node.base as LuauNode);
        const index = this.eval(node.index as LuauNode);
        return this.index(base, index);
      }
      case "MemberExpression": {
        // Only dot access is a plain read; `:` is a method call receiver.
        if (node.indexer !== ".") return null;
        const base = this.eval(node.base as LuauNode);
        const identifier = node.identifier as LuauNode | undefined;
        if (identifier === undefined) return null;
        return this.index(base, string(String(identifier.name)));
      }
      default:
        // Calls, varargs, closures, and anything else are not evaluable.
        return null;
    }
  }

  private numeric(node: LuauNode): LuaValue {
    const raw = String(node.raw ?? "").replace(/_/g, "");
    /*
     * A literal is an integer only when written without a fractional part or
     * exponent. `1` and `1.0` are different subtypes in Lua 5.4 and divide
     * differently, so the spelling has to be respected.
     *
     * The digits are re-read here rather than taken from the token's numeric
     * value: that value is a JavaScript double and silently loses precision
     * past 2^53, which would turn a 64-bit constant such as
     * 9223372036854775807 into a float and defeat the wrapping arithmetic
     * these dispatchers rely on.
     */
    const looksIntegral = !/[.eEpP]/.test(raw) || /^0[xX][0-9a-fA-F]+$/.test(raw);
    if (looksIntegral) {
      const exact = parseExactInteger(raw);
      if (exact !== null) return integer(exact);
    }
    return float(Number(node.value ?? 0));
  }

  private index(base: LuaValue | null, key: LuaValue | null): LuaValue | null {
    if (base === null || key === null) return null;
    if (base.kind !== "table") return null;
    const canonical = tableKey(key);
    if (canonical === null) return null;
    return base.entries.get(canonical) ?? NIL;
  }

  private table(node: LuauNode): LuaValue | null {
    const entries = new Map<string, LuaValue>();
    let arrayIndex = 1n;
    const fields = (node.fields as LuauNode[] | undefined) ?? [];
    for (const field of fields) {
      if (field.type === "TableValue") {
        const value = this.eval(field.value as LuauNode);
        if (value === null) return null;
        entries.set(`n:${arrayIndex.toString()}`, value);
        arrayIndex += 1n;
        continue;
      }
      if (field.type === "TableKey" || field.type === "TableKeyString") {
        const keyNode = field.key as LuauNode;
        const key =
          field.type === "TableKeyString"
            ? string(String(keyNode.name))
            : this.eval(keyNode);
        const value = this.eval(field.value as LuauNode);
        if (key === null || value === null) return null;
        const canonical = tableKey(key);
        if (canonical === null) return null;
        entries.set(canonical, value);
        continue;
      }
      return null;
    }
    return { kind: "table", entries };
  }

  private unary(node: LuauNode): LuaValue | null {
    const operator = String(node.operator);
    const operand = this.eval(node.argument as LuauNode);
    if (operand === null) return null;
    switch (operator) {
      case "not":
        return boolean(!isTruthy(operand));
      case "-": {
        if (operand.kind === "integer") return integer(-operand.value);
        if (operand.kind === "float") return float(-operand.value);
        return null;
      }
      case "~": {
        const value = asInteger(operand);
        return value === null ? null : integer(~value);
      }
      case "#":
        if (operand.kind === "string") return integer(BigInt(operand.value.length));
        // Table length depends on the array part's border; not modelled.
        return null;
      default:
        return null;
    }
  }

  private logical(node: LuauNode): LuaValue | null {
    const operator = String(node.operator);
    const left = this.eval(node.left as LuauNode);
    if (left === null) return null;
    // Lua short-circuits and yields the operand, not a boolean.
    if (operator === "and") {
      return isTruthy(left) ? this.eval(node.right as LuauNode) : left;
    }
    if (operator === "or") {
      return isTruthy(left) ? left : this.eval(node.right as LuauNode);
    }
    return null;
  }

  private binary(node: LuauNode): LuaValue | null {
    const operator = String(node.operator);
    const left = this.eval(node.left as LuauNode);
    const right = this.eval(node.right as LuauNode);
    if (left === null || right === null) return null;

    if (operator === "..") {
      const l = this.concatText(left);
      const r = this.concatText(right);
      return l === null || r === null ? null : string(l + r);
    }

    if (operator === "==" || operator === "~=") {
      const equal = this.equals(left, right);
      if (equal === null) return null;
      return boolean(operator === "==" ? equal : !equal);
    }

    if (["<", "<=", ">", ">="].includes(operator)) {
      return this.compare(operator, left, right);
    }

    if (["&", "|", "~", "<<", ">>"].includes(operator)) {
      const l = asInteger(left);
      const r = asInteger(right);
      if (l === null || r === null) return null;
      switch (operator) {
        case "&":
          return integer(l & r);
        case "|":
          return integer(l | r);
        case "~":
          return integer(l ^ r);
        case "<<":
          // Lua shifts by 64 or more produce zero, and negative shifts reverse.
          if (r <= -64n || r >= 64n) return integer(0n);
          return integer(r >= 0n ? l << r : this.logicalShiftRight(l, -r));
        case ">>":
          if (r <= -64n || r >= 64n) return integer(0n);
          return integer(r >= 0n ? this.logicalShiftRight(l, r) : l << -r);
        default:
          return null;
      }
    }

    return this.arithmetic(operator, left, right);
  }

  /** Lua's `>>` is logical, not arithmetic: it does not preserve the sign. */
  private logicalShiftRight(value: bigint, shift: bigint): bigint {
    const unsigned = ((value % TWO_64) + TWO_64) % TWO_64;
    return unsigned >> shift;
  }

  private concatText(value: LuaValue): string | null {
    if (value.kind === "string") return value.value;
    if (value.kind === "integer") return value.value.toString();
    if (value.kind === "float") {
      if (Number.isInteger(value.value)) return `${value.value}.0`;
      return String(value.value);
    }
    return null;
  }

  private equals(left: LuaValue, right: LuaValue): boolean | null {
    if (left.kind === "table" || right.kind === "table") {
      // Table equality is identity, which this model does not track.
      return null;
    }
    if (left.kind === "nil" && right.kind === "nil") return true;
    if (left.kind === "boolean" && right.kind === "boolean") {
      return left.value === right.value;
    }
    if (left.kind === "string" && right.kind === "string") {
      return left.value === right.value;
    }
    const l = asNumber(left);
    const r = asNumber(right);
    if (l !== null && r !== null) {
      if (l.int !== null && r.int !== null) return l.int === r.int;
      return l.num === r.num;
    }
    // Different types are simply unequal in Lua.
    return false;
  }

  private compare(
    operator: string,
    left: LuaValue,
    right: LuaValue,
  ): LuaValue | null {
    if (left.kind === "string" && right.kind === "string") {
      const order = left.value < right.value ? -1 : left.value > right.value ? 1 : 0;
      return boolean(this.orderHolds(operator, order));
    }
    const l = asNumber(left);
    const r = asNumber(right);
    if (l === null || r === null) return null;
    if (l.int !== null && r.int !== null) {
      const order = l.int < r.int ? -1 : l.int > r.int ? 1 : 0;
      return boolean(this.orderHolds(operator, order));
    }
    if (Number.isNaN(l.num) || Number.isNaN(r.num)) return boolean(false);
    const order = l.num < r.num ? -1 : l.num > r.num ? 1 : 0;
    return boolean(this.orderHolds(operator, order));
  }

  private orderHolds(operator: string, order: number): boolean {
    switch (operator) {
      case "<":
        return order < 0;
      case "<=":
        return order <= 0;
      case ">":
        return order > 0;
      case ">=":
        return order >= 0;
      default:
        return false;
    }
  }

  private arithmetic(
    operator: string,
    left: LuaValue,
    right: LuaValue,
  ): LuaValue | null {
    const l = asNumber(left);
    const r = asNumber(right);
    if (l === null || r === null) return null;
    const bothIntegers = l.int !== null && r.int !== null;

    switch (operator) {
      case "+":
        return bothIntegers ? integer(l.int! + r.int!) : float(l.num + r.num);
      case "-":
        return bothIntegers ? integer(l.int! - r.int!) : float(l.num - r.num);
      case "*":
        return bothIntegers ? integer(l.int! * r.int!) : float(l.num * r.num);
      case "/":
        // Division always produces a float in Lua 5.3+.
        return float(l.num / r.num);
      case "^":
        return float(l.num ** r.num);
      case "//": {
        if (bothIntegers) {
          if (r.int === 0n) return null;
          return integer(this.floorDivide(l.int!, r.int!));
        }
        return float(Math.floor(l.num / r.num));
      }
      case "%": {
        if (bothIntegers) {
          if (r.int === 0n) return null;
          return integer(this.modulo(l.int!, r.int!));
        }
        // Lua's modulo takes the sign of the divisor.
        const result = l.num - Math.floor(l.num / r.num) * r.num;
        return float(result);
      }
      default:
        return null;
    }
  }

  /** Integer division rounding toward negative infinity, as Lua does. */
  private floorDivide(left: bigint, right: bigint): bigint {
    let quotient = left / right;
    if (left % right !== 0n && (left < 0n) !== (right < 0n)) quotient -= 1n;
    return quotient;
  }

  private modulo(left: bigint, right: bigint): bigint {
    const remainder = left % right;
    if (remainder !== 0n && (remainder < 0n) !== (right < 0n)) {
      return remainder + right;
    }
    return remainder;
  }
}

/**
 * Evaluate one expression. Returns `null` whenever the result is not fully
 * determined by the supplied scope, which callers must treat as unknown.
 */
export function evaluateConstantExpression(
  node: LuauNode,
  scope: ConstEvalScope = { variables: new Map() },
  options: ConstEvalOptions = {},
): LuaValue | null {
  return new Evaluator(scope, options.maxNodes ?? DEFAULT_MAX_NODES).eval(node);
}

/** Render a value for diagnostics; never used to emit source. */
export function describeValue(value: LuaValue): string {
  switch (value.kind) {
    case "nil":
      return "nil";
    case "boolean":
      return value.value ? "true" : "false";
    case "integer":
      return value.value.toString();
    case "float":
      return Number.isInteger(value.value) ? `${value.value}.0` : String(value.value);
    case "string":
      return JSON.stringify(value.value);
    case "table":
      return `table(${value.entries.size})`;
  }
}

/** Convenience for callers that only care about an integer state value. */
export function asStateNumber(value: LuaValue | null): number | null {
  if (value === null) return null;
  if (value.kind === "integer") {
    const asNumberValue = Number(value.value);
    return Number.isSafeInteger(asNumberValue) ? asNumberValue : null;
  }
  if (value.kind === "float" && Number.isFinite(value.value)) return value.value;
  return null;
}
