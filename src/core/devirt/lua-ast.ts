/**
 * A small Lua expression and statement model with a faithful renderer.
 *
 * The devirtualizer builds this tree instead of concatenating strings so that
 * precedence, parenthesization, and identifier validity are decided in one
 * place.  Output is emitted as Luau/Lua 5.4-compatible source: `goto` and
 * labels are used for regions that could not be proven structurable, which is
 * valid syntax rather than a comment that hides the control flow.
 */

/** Operator precedence, mirroring the parser's table. */
const BINARY_PRECEDENCE: Readonly<Record<string, number>> = {
  or: 1,
  and: 2,
  "<": 3,
  ">": 3,
  "<=": 3,
  ">=": 3,
  "~=": 3,
  "==": 3,
  "|": 4,
  "~": 5,
  "&": 6,
  "<<": 7,
  ">>": 7,
  "..": 9,
  "+": 10,
  "-": 10,
  "*": 11,
  "/": 11,
  "//": 11,
  "%": 11,
  "^": 14,
};

const UNARY_PRECEDENCE = 12;
const RIGHT_ASSOCIATIVE: ReadonlySet<string> = new Set(["..", "^"]);
const LUA_KEYWORDS: ReadonlySet<string> = new Set([
  "and", "break", "do", "else", "elseif", "end", "false", "for", "function",
  "goto", "if", "in", "local", "nil", "not", "or", "repeat", "return", "then",
  "true", "until", "while", "continue",
]);

export type LuaExpression =
  /** A bare name: a local, a global, or a parameter. */
  | { readonly kind: "name"; readonly name: string }
  | { readonly kind: "literal"; readonly text: string }
  | { readonly kind: "vararg" }
  | { readonly kind: "table"; readonly fields: readonly LuaExpression[] }
  | {
      readonly kind: "index";
      readonly object: LuaExpression;
      readonly key: LuaExpression;
    }
  | {
      readonly kind: "call";
      readonly callee: LuaExpression;
      readonly args: readonly LuaExpression[];
      /** Set for `obj:name(...)` method calls. */
      readonly method?: string;
    }
  | {
      readonly kind: "binary";
      readonly operator: string;
      readonly left: LuaExpression;
      readonly right: LuaExpression;
    }
  | {
      readonly kind: "unary";
      readonly operator: string;
      readonly operand: LuaExpression;
    }
  | { readonly kind: "function"; readonly body: LuaFunction }
  /** Text that could not be modelled; rendered verbatim. */
  | { readonly kind: "raw"; readonly text: string };

export type LuaStatement =
  | {
      readonly kind: "local";
      readonly names: readonly string[];
      readonly values: readonly LuaExpression[];
    }
  | {
      readonly kind: "assign";
      readonly targets: readonly LuaExpression[];
      readonly values: readonly LuaExpression[];
    }
  | { readonly kind: "call"; readonly call: LuaExpression }
  | { readonly kind: "return"; readonly values: readonly LuaExpression[] }
  | { readonly kind: "break" }
  | { readonly kind: "goto"; readonly label: string }
  | { readonly kind: "label"; readonly name: string }
  | { readonly kind: "comment"; readonly text: string }
  | { readonly kind: "do"; readonly body: readonly LuaStatement[] }
  | {
      readonly kind: "if";
      readonly condition: LuaExpression;
      readonly then: readonly LuaStatement[];
      readonly else?: readonly LuaStatement[];
    }
  | {
      readonly kind: "while";
      readonly condition: LuaExpression;
      readonly body: readonly LuaStatement[];
    }
  | {
      readonly kind: "numeric-for";
      readonly variable: string;
      readonly start: LuaExpression;
      readonly limit: LuaExpression;
      readonly step: LuaExpression | null;
      readonly body: readonly LuaStatement[];
    };

export interface LuaFunction {
  readonly parameters: readonly string[];
  readonly isVararg: boolean;
  readonly body: readonly LuaStatement[];
}

export function name(text: string): LuaExpression {
  return { kind: "name", name: text };
}

export function literal(text: string): LuaExpression {
  return { kind: "literal", text };
}

export function isValidIdentifier(text: string): boolean {
  return /^[A-Za-z_]\w*$/.test(text) && !LUA_KEYWORDS.has(text);
}

/** Render a Lua string literal with escapes that survive a round trip. */
export function quoteLuaString(value: string): string {
  const out: string[] = ['"'];
  for (const character of value) {
    const code = character.codePointAt(0) ?? 0;
    if (character === '"') out.push('\\"');
    else if (character === "\\") out.push("\\\\");
    else if (character === "\n") out.push("\\n");
    else if (character === "\r") out.push("\\r");
    else if (character === "\t") out.push("\\t");
    else if (code < 0x20 || code === 0x7f) out.push(`\\${code}`);
    else if (code > 0xff) out.push(character);
    else out.push(character);
  }
  out.push('"');
  return out.join("");
}

/** Render a Lua number so it re-parses to the same value. */
export function formatLuaNumber(value: number): string {
  if (Number.isNaN(value)) return "(0/0)";
  if (value === Number.POSITIVE_INFINITY) return "math.huge";
  if (value === Number.NEGATIVE_INFINITY) return "-math.huge";
  if (Object.is(value, -0)) return "-0";
  if (Number.isInteger(value) && Math.abs(value) < 1e15) return String(value);
  return String(value);
}

function precedenceOf(expression: LuaExpression): number {
  if (expression.kind === "binary") {
    return BINARY_PRECEDENCE[expression.operator] ?? 0;
  }
  if (expression.kind === "unary") return UNARY_PRECEDENCE;
  // Primary expressions never need parentheses from precedence alone.
  return 100;
}

/**
 * A prefix expression (the target of a call or index) must be a name, an
 * index, a call, or a parenthesized expression - never a bare literal or
 * operator expression.
 */
function needsPrefixParentheses(expression: LuaExpression): boolean {
  return (
    expression.kind !== "name" &&
    expression.kind !== "index" &&
    expression.kind !== "call" &&
    expression.kind !== "raw"
  );
}

export function renderExpression(
  expression: LuaExpression,
  parentPrecedence = 0,
  indent = 0,
): string {
  switch (expression.kind) {
    case "name":
      return expression.name;
    case "literal":
      return expression.text;
    case "raw":
      return expression.text;
    case "vararg":
      return "...";
    case "table": {
      if (expression.fields.length === 0) return "{}";
      const fields = expression.fields
        .map((field) => renderExpression(field, 0, indent))
        .join(", ");
      return `{ ${fields} }`;
    }
    case "index": {
      const object = renderPrefix(expression.object, indent);
      if (
        expression.key.kind === "literal" &&
        /^"[A-Za-z_]\w*"$/.test(expression.key.text)
      ) {
        const identifier = expression.key.text.slice(1, -1);
        if (isValidIdentifier(identifier)) return `${object}.${identifier}`;
      }
      return `${object}[${renderExpression(expression.key, 0, indent)}]`;
    }
    case "call": {
      const callee = renderPrefix(expression.callee, indent);
      const args = expression.args
        .map((argument) => renderExpression(argument, 0, indent))
        .join(", ");
      if (expression.method !== undefined) {
        return `${callee}:${expression.method}(${args})`;
      }
      return `${callee}(${args})`;
    }
    case "unary": {
      const operand = renderExpression(
        expression.operand,
        UNARY_PRECEDENCE,
        indent,
      );
      const spacer = /^[A-Za-z_]/.test(expression.operator) ? " " : "";
      const text = `${expression.operator}${spacer}${operand}`;
      return UNARY_PRECEDENCE < parentPrecedence ? `(${text})` : text;
    }
    case "binary": {
      const precedence = BINARY_PRECEDENCE[expression.operator] ?? 0;
      const rightAssociative = RIGHT_ASSOCIATIVE.has(expression.operator);
      const left = renderExpression(
        expression.left,
        rightAssociative ? precedence + 1 : precedence,
        indent,
      );
      const right = renderExpression(
        expression.right,
        rightAssociative ? precedence : precedence + 1,
        indent,
      );
      const text = `${left} ${expression.operator} ${right}`;
      return precedence < parentPrecedence ? `(${text})` : text;
    }
    case "function":
      return renderFunction(expression.body, indent);
    default:
      return "nil";
  }
}

function renderPrefix(expression: LuaExpression, indent: number): string {
  const text = renderExpression(expression, 0, indent);
  return needsPrefixParentheses(expression) ? `(${text})` : text;
}

function renderFunction(fn: LuaFunction, indent: number): string {
  const parameters = [...fn.parameters];
  if (fn.isVararg) parameters.push("...");
  const header = `function(${parameters.join(", ")})`;
  if (fn.body.length === 0) return `${header} end`;
  const body = renderStatements(fn.body, indent + 1);
  return `${header}\n${body}\n${"\t".repeat(indent)}end`;
}

export function renderStatements(
  statements: readonly LuaStatement[],
  indent = 0,
): string {
  const pad = "\t".repeat(indent);
  const lines: string[] = [];
  for (const statement of statements) {
    lines.push(...renderStatement(statement, indent, pad));
  }
  return lines.join("\n");
}

function renderStatement(
  statement: LuaStatement,
  indent: number,
  pad: string,
): string[] {
  switch (statement.kind) {
    case "comment":
      return statement.text
        .split("\n")
        .map((line) => `${pad}-- ${line}`);
    case "local": {
      const names = statement.names.join(", ");
      if (statement.values.length === 0) return [`${pad}local ${names}`];
      const values = statement.values
        .map((value) => renderExpression(value, 0, indent))
        .join(", ");
      return [`${pad}local ${names} = ${values}`];
    }
    case "assign": {
      const targets = statement.targets
        .map((target) => renderExpression(target, 0, indent))
        .join(", ");
      const values = statement.values
        .map((value) => renderExpression(value, 0, indent))
        .join(", ");
      return [`${pad}${targets} = ${values}`];
    }
    case "call":
      return [`${pad}${renderExpression(statement.call, 0, indent)}`];
    case "return": {
      if (statement.values.length === 0) return [`${pad}return`];
      const values = statement.values
        .map((value) => renderExpression(value, 0, indent))
        .join(", ");
      return [`${pad}return ${values}`];
    }
    case "break":
      return [`${pad}break`];
    case "goto":
      return [`${pad}goto ${statement.label}`];
    case "label":
      return [`${pad}::${statement.name}::`];
    case "do":
      return [
        `${pad}do`,
        renderStatements(statement.body, indent + 1),
        `${pad}end`,
      ].filter((line) => line.length > 0);
    case "if": {
      const lines = [
        `${pad}if ${renderExpression(statement.condition, 0, indent)} then`,
      ];
      const then = renderStatements(statement.then, indent + 1);
      if (then.length > 0) lines.push(then);
      if (statement.else !== undefined && statement.else.length > 0) {
        lines.push(`${pad}else`);
        lines.push(renderStatements(statement.else, indent + 1));
      }
      lines.push(`${pad}end`);
      return lines;
    }
    case "while": {
      const lines = [
        `${pad}while ${renderExpression(statement.condition, 0, indent)} do`,
      ];
      const body = renderStatements(statement.body, indent + 1);
      if (body.length > 0) lines.push(body);
      lines.push(`${pad}end`);
      return lines;
    }
    case "numeric-for": {
      const parts = [
        renderExpression(statement.start, 0, indent),
        renderExpression(statement.limit, 0, indent),
      ];
      if (statement.step !== null) {
        parts.push(renderExpression(statement.step, 0, indent));
      }
      const lines = [
        `${pad}for ${statement.variable} = ${parts.join(", ")} do`,
      ];
      const body = renderStatements(statement.body, indent + 1);
      if (body.length > 0) lines.push(body);
      lines.push(`${pad}end`);
      return lines;
    }
    default:
      return [];
  }
}
