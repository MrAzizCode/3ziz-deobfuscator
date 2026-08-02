import { describe, expect, it } from "vitest";

import { lexLuau } from "../../src/core/source/luau-lexer";
import { LuauSyntaxError, parseLuau } from "../../src/core/source/luau-parser";

function statementTypes(source: string): string[] {
  return parseLuau(source).body.map((node) => String(node.type));
}

/** Collect every node type in the tree, the way parse-facts walks it. */
function nodeTypes(value: unknown, seen = new Set<object>()): string[] {
  if (value === null || typeof value !== "object" || seen.has(value)) return [];
  seen.add(value);
  const record = value as Record<string, unknown>;
  const found = typeof record.type === "string" ? [record.type] : [];
  for (const [key, child] of Object.entries(record)) {
    if (key === "loc" || key === "range") continue;
    if (Array.isArray(child)) {
      for (const item of child) found.push(...nodeTypes(item, seen));
    } else {
      found.push(...nodeTypes(child, seen));
    }
  }
  return found;
}

describe("Luau lexer", () => {
  it("reads numeric forms Lua 5.1 has no syntax for", () => {
    const numbers = lexLuau("0x1.8Cp6 0b1010 1_000_000 0X53ce 3e-2 .5")
      .tokens.filter((token) => token.type === "NumericLiteral")
      .map((token) => token.numeric);
    expect(numbers).toEqual([99.0, 10, 1_000_000, 0x53ce, 0.03, 0.5]);
  });

  it("resolves escapes, including Lua 5.1's lenient unknown escapes", () => {
    const [token] = lexLuau("'r\\101\\u{0061}d\\s\\116\\z r\\z in\\g'").tokens;
    expect(token?.value).toBe("readstring");
  });

  it("tracks brace depth so interpolation and tables do not confuse it", () => {
    const values = lexLuau("`a{ {1,2} }b`")
      .tokens.filter((token) => token.type === "InterpolatedStringPart")
      .map((token) => token.value);
    expect(values).toEqual(["a", "b"]);
  });

  it("keeps comments without treating them as code", () => {
    const { comments, tokens } = lexLuau("--[[ block ]] local a --line");
    expect(comments.map((comment) => comment.value.trim())).toEqual([
      "block",
      "line",
    ]);
    expect(tokens.map((token) => token.value)).toEqual(["local", "a", ""]);
  });
});

describe("Luau parser", () => {
  it("parses the Lua 5.1 statement forms", () => {
    expect(statementTypes("local a, b = 1, 2")).toEqual(["LocalStatement"]);
    expect(statementTypes("a.b.c = 1")).toEqual(["AssignmentStatement"]);
    expect(statementTypes("f(1)(2)")).toEqual(["CallStatement"]);
    expect(statementTypes("for i = 1, 10, 2 do end")).toEqual([
      "ForNumericStatement",
    ]);
    expect(statementTypes("for k, v in pairs(t) do end")).toEqual([
      "ForGenericStatement",
    ]);
    expect(statementTypes("repeat until true")).toEqual(["RepeatStatement"]);
    expect(statementTypes("function a.b:c() end")).toEqual([
      "FunctionDeclaration",
    ]);
  });

  it("represents Luau-only syntax with its own node types", () => {
    expect(nodeTypes(parseLuau("while true do continue end"))).toContain(
      "ContinueStatement",
    );
    expect(nodeTypes(parseLuau("x += 1"))).toContain(
      "CompoundAssignmentStatement",
    );
    expect(nodeTypes(parseLuau("local s = `v={x}`"))).toContain(
      "InterpolatedStringExpression",
    );
    expect(nodeTypes(parseLuau("local n = v :: number"))).toContain(
      "TypeCastExpression",
    );
    expect(nodeTypes(parseLuau("export type T = { a: number }"))).toContain(
      "TypeAliasStatement",
    );
  });

  it("consumes a type annotation without swallowing the next statement", () => {
    // A span that ran long here would absorb `type Bar` into the first alias.
    expect(
      statementTypes("type Foo = { x: number }\ntype Bar = string\nlocal z = 1"),
    ).toEqual(["TypeAliasStatement", "TypeAliasStatement", "LocalStatement"]);
    expect(
      statementTypes("local a: Map<string, Array<number>> = t\nreturn a"),
    ).toEqual(["LocalStatement", "ReturnStatement"]);
    expect(statementTypes("local f: (a: number) -> string? = g\nreturn f")).toEqual([
      "LocalStatement",
      "ReturnStatement",
    ]);
  });

  it("treats contextual keywords as names where a name is meant", () => {
    // `continue` and `type` are not reserved words in Luau.
    expect(statementTypes("local continue = 1")).toEqual(["LocalStatement"]);
    expect(statementTypes("continue(1)")).toEqual(["CallStatement"]);
    expect(statementTypes("type.x = 1")).toEqual(["AssignmentStatement"]);
  });

  it("applies Lua's operator precedence and associativity", () => {
    const ast = parseLuau("return 1 + 2 * 3 ^ 2 ^ 3 .. 'x'");
    const [statement] = ast.body;
    const expression = (statement as { arguments: unknown[] }).arguments[0] as {
      operator: string;
      left: { operator: string };
    };
    // `..` is lowest here, and `^` is right associative under `*`.
    expect(expression.operator).toBe("..");
    expect(expression.left.operator).toBe("+");
  });

  it("keeps parentheses that truncate multiple results", () => {
    expect(nodeTypes(parseLuau("return (f())"))).toContain(
      "ParenthesisExpression",
    );
  });

  it("reports the position of a genuine syntax error", () => {
    expect(() => parseLuau("local = 1")).toThrow(LuauSyntaxError);
    expect(() => parseLuau("if x then")).toThrow(/Expected 'end'/);
    expect(() => parseLuau("local a = ")).toThrow(/end of input/);
    try {
      parseLuau("local a = 1\nlocal = 2");
      expect.unreachable("expected a syntax error");
    } catch (error) {
      expect((error as LuauSyntaxError).line).toBe(2);
    }
  });

  it("bounds the tree it will build", () => {
    expect(() => parseLuau("local a = 1 local b = 2", { maxNodes: 3 })).toThrow(
      /node limit exceeded/,
    );
  });
});
