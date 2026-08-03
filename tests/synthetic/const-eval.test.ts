import { describe, expect, it } from "vitest";

import {
  asStateNumber,
  describeValue,
  evaluateConstantExpression,
  type LuaValue,
} from "../../src/core/passes/const-eval";
import { parseLuau, type LuauNode } from "../../src/core/source/luau-parser";

/** Parse `return <expr>` and evaluate the expression. */
function evaluate(
  source: string,
  variables: ReadonlyMap<string, LuaValue> = new Map(),
): LuaValue | null {
  const chunk = parseLuau(`return ${source}`);
  const statement = chunk.body[0] as { arguments: LuauNode[] };
  return evaluateConstantExpression(statement.arguments[0]!, { variables });
}

function text(source: string): string {
  const value = evaluate(source);
  return value === null ? "<unknown>" : describeValue(value);
}

describe("constant expression evaluation", () => {
  it("keeps Lua's integer and float subtypes apart", () => {
    // 1 and 1.0 are different subtypes and divide differently.
    expect(text("1 + 2")).toBe("3");
    expect(text("1.0 + 2")).toBe("3.0");
    expect(text("7 // 2")).toBe("3");
    expect(text("7 / 2")).toBe("3.5");
    expect(text("4 / 2")).toBe("2.0");
  });

  it("wraps integer arithmetic at 64 bits", () => {
    expect(text("9223372036854775807 + 1")).toBe("-9223372036854775808");
    expect(text("-8432766656861699982 + 0")).toBe("-8432766656861699982");
  });

  it("implements Lua's shift and modulo rules", () => {
    // `>>` is logical, so a negative value does not keep its sign bits.
    expect(text("-1 >> 60")).toBe("15");
    expect(text("1 << 64")).toBe("0");
    expect(text("1 << -1")).toBe("0");
    // Modulo takes the sign of the divisor.
    expect(text("-1 % 5")).toBe("4");
    expect(text("1 % -5")).toBe("-4");
    expect(text("-7 // 2")).toBe("-4");
  });

  it("evaluates the operator mix these wrappers actually use", () => {
    // Shapes lifted from a real flattened dispatcher.
    expect(text("-0XB88a459 + ((8 >> 6) + 9 - 3 & 5)")).toBe("-193504341");
    expect(text("0x1.8Cp6")).toBe("99.0");
    expect(text("(1 | 9) - 9 << 15 >= 6 and 5 or 4")).toBe("4");
  });

  it("short-circuits and yields the operand, not a boolean", () => {
    expect(text("nil or 7")).toBe("7");
    expect(text("false and 7")).toBe("false");
    expect(text("3 and 4")).toBe("4");
    // Only nil and false are falsy: zero is truthy in Lua.
    expect(text("0 and 'yes'")).toBe('"yes"');
  });

  it("reads tables it built itself", () => {
    expect(text("({10, 20, 30})[2]")).toBe("20");
    expect(text("({ a = 5 }).a")).toBe("5");
    expect(text("({ [3] = 'x' })[3]")).toBe('"x"');
    // A missing key is nil, not unknown.
    expect(text("({1})[9]")).toBe("nil");
  });

  it("resolves the seed table a dispatcher indexes", () => {
    const seeds = evaluate("{24046, 3277425741, 0x2D498c0A, 3107294807}");
    expect(seeds).not.toBeNull();
    const scope = new Map([["v", seeds!]]);
    expect(describeValue(evaluate("v[3]", scope)!)).toBe("759794698");
    expect(describeValue(evaluate("(v[1] | v[4]) - v[4]", scope)!)).toBe("20904");
  });

  it("refuses anything it cannot know instead of guessing", () => {
    expect(evaluate("f()")).toBeNull();
    expect(evaluate("...")).toBeNull();
    expect(evaluate("unknownName")).toBeNull();
    expect(evaluate("function() end")).toBeNull();
    // A call anywhere inside poisons the whole expression.
    expect(evaluate("1 + f()")).toBeNull();
    // Division by integer zero has no integer result.
    expect(evaluate("1 // 0")).toBeNull();
    // Table identity is not modelled, so equality is unknown.
    expect(evaluate("({}) == ({})")).toBeNull();
  });

  it("compares across subtypes the way Lua does", () => {
    expect(text("1 == 1.0")).toBe("true");
    expect(text("'a' < 'b'")).toBe("true");
    expect(text("1 == '1'")).toBe("false");
    expect(text("(0/0) < 1")).toBe("false");
  });

  it("concatenates with Lua's number formatting", () => {
    expect(text("1 .. ''")).toBe('"1"');
    expect(text("1.0 .. ''")).toBe('"1.0"');
    expect(text("'a' .. 'b'")).toBe('"ab"');
  });

  it("bounds the work a hostile expression can cause", () => {
    const deep = `${"(".repeat(400)}1${")".repeat(400)}`;
    const chunk = parseLuau(`return ${deep}`);
    const statement = chunk.body[0] as { arguments: LuauNode[] };
    expect(
      evaluateConstantExpression(statement.arguments[0]!, { variables: new Map() }, { maxNodes: 50 }),
    ).toBeNull();
  });

  it("exposes an integer state value for dispatcher recovery", () => {
    expect(asStateNumber(evaluate("22"))).toBe(22);
    expect(asStateNumber(evaluate("0x1.8Cp6"))).toBe(99);
    expect(asStateNumber(evaluate("'x'"))).toBeNull();
    expect(asStateNumber(null)).toBeNull();
  });
});
