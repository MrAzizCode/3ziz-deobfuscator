/**
 * Recursive-descent parser for Lua 5.1 through Luau.
 *
 * The AST deliberately mirrors `luaparse`'s node shapes so existing consumers
 * (`parse-facts`, cleanup passes, the devirtualizer's output check) treat both
 * front ends identically.  Luau-only syntax is represented with additional
 * node types rather than being silently dropped:
 *
 * - `ContinueStatement` for Luau's contextual `continue`;
 * - `CompoundAssignmentStatement` for `+=` and friends;
 * - `InterpolatedStringExpression` for backtick strings;
 * - `TypeCastExpression` for `expr :: T`;
 * - `TypeAliasStatement` for `type X = T`.
 *
 * Type annotations are parsed as balanced spans and retained as source text.
 * Recovering Luau's full type grammar is not needed to analyze what a script
 * *does*, and inventing a partial type model would be a fidelity claim this
 * project does not make.
 *
 * Nothing here evaluates the parsed program.
 */

import {
  lexLuau,
  LuauSyntaxError,
  type LuauComment,
  type LuauSourceLocation,
  type LuauToken,
} from "./luau-lexer";

export { LuauSyntaxError } from "./luau-lexer";

export interface LuauNodeBase {
  readonly type: string;
  readonly range: readonly [number, number];
  readonly loc: LuauSourceLocation;
}

/** Structural alias; consumers walk this generically like a luaparse tree. */
export interface LuauNode extends LuauNodeBase {
  readonly [key: string]: unknown;
}

export interface LuauChunk extends LuauNodeBase {
  readonly type: "Chunk";
  readonly body: readonly LuauNode[];
  readonly comments: readonly LuauComment[];
}

/**
 * A type annotation, retained by source range.  See `readTypeSpan` for why the
 * type itself is not modelled.
 */
export interface TypeSpan {
  readonly range: readonly [number, number];
  readonly loc: LuauSourceLocation;
}

export interface ParseLuauOptions {
  /** Abort once this many nodes have been built. */
  readonly maxNodes?: number;
}

const DEFAULT_MAX_NODES = 2_000_000;

/** Binary operator precedence, mirroring Lua's own table. */
const BINARY_PRECEDENCE: Readonly<Record<string, readonly [number, number]>> = {
  or: [1, 1],
  and: [2, 2],
  "<": [3, 3],
  ">": [3, 3],
  "<=": [3, 3],
  ">=": [3, 3],
  "~=": [3, 3],
  "==": [3, 3],
  "|": [4, 4],
  "~": [5, 5],
  "&": [6, 6],
  "<<": [7, 7],
  ">>": [7, 7],
  // Concatenation is right associative.
  "..": [9, 8],
  "+": [10, 10],
  "-": [10, 10],
  "*": [11, 11],
  "/": [11, 11],
  "//": [11, 11],
  "%": [11, 11],
  // Exponentiation is right associative and binds tighter than unary.
  "^": [14, 13],
};

const UNARY_PRECEDENCE = 12;

const COMPOUND_OPERATORS: ReadonlySet<string> = new Set([
  "+=",
  "-=",
  "*=",
  "/=",
  "//=",
  "%=",
  "^=",
  "..=",
  "<<=",
  ">>=",
]);

/** Tokens that can only appear where a statement list has ended. */
const BLOCK_TERMINATORS: ReadonlySet<string> = new Set([
  "end",
  "else",
  "elseif",
  "until",
]);

class Parser {
  private index = 0;
  private nodeCount = 0;
  private readonly maxNodes: number;

  constructor(
    private readonly tokens: readonly LuauToken[],
    private readonly comments: readonly LuauComment[],
    options: ParseLuauOptions,
  ) {
    this.maxNodes = options.maxNodes ?? DEFAULT_MAX_NODES;
  }

  parseChunk(): LuauChunk {
    const body = this.parseBlock();
    const token = this.peek();
    if (token.type !== "EOF") {
      this.fail(`Unexpected ${this.describe(token)} after the chunk body.`);
    }
    const end = this.tokens[this.tokens.length - 1]!;
    return {
      type: "Chunk",
      body,
      comments: this.comments,
      range: [0, end.range[1]],
      loc: { start: { line: 1, column: 0 }, end: end.loc.end },
    };
  }

  // ---------------------------------------------------------------- helpers

  private peek(offset = 0): LuauToken {
    return (
      this.tokens[this.index + offset] ?? this.tokens[this.tokens.length - 1]!
    );
  }

  private next(): LuauToken {
    const token = this.peek();
    if (token.type !== "EOF") this.index += 1;
    return token;
  }

  private at(value: string, type?: LuauToken["type"]): boolean {
    const token = this.peek();
    if (type !== undefined && token.type !== type) return false;
    if (token.type !== "Keyword" && token.type !== "Punctuator" && type === undefined) {
      return false;
    }
    return token.value === value;
  }

  private accept(value: string): LuauToken | null {
    if (this.at(value)) return this.next();
    return null;
  }

  private expect(value: string): LuauToken {
    if (this.at(value)) return this.next();
    this.fail(`Expected '${value}' but found ${this.describe(this.peek())}.`);
  }

  private expectName(): LuauToken {
    const token = this.peek();
    if (token.type !== "Identifier") {
      this.fail(`Expected a name but found ${this.describe(token)}.`);
    }
    return this.next();
  }

  private describe(token: LuauToken): string {
    if (token.type === "EOF") return "end of input";
    return `'${token.raw.length > 24 ? `${token.raw.slice(0, 24)}...` : token.raw}'`;
  }

  private fail(message: string, token: LuauToken = this.peek()): never {
    throw new LuauSyntaxError(
      message,
      token.range[0],
      token.loc.start.line,
      token.loc.start.column,
    );
  }

  private node<T extends Record<string, unknown>>(
    fields: T,
    start: LuauToken,
    endIndexToken: LuauToken = this.tokens[this.index - 1] ?? start,
  ): LuauNode {
    this.nodeCount += 1;
    if (this.nodeCount > this.maxNodes) {
      throw new LuauSyntaxError(
        `AST node limit exceeded (${this.maxNodes}).`,
        start.range[0],
        start.loc.start.line,
        start.loc.start.column,
      );
    }
    return {
      ...fields,
      range: [start.range[0], endIndexToken.range[1]],
      loc: { start: start.loc.start, end: endIndexToken.loc.end },
    } as unknown as LuauNode;
  }

  // ------------------------------------------------------------- statements

  private parseBlock(): LuauNode[] {
    const body: LuauNode[] = [];
    for (;;) {
      const token = this.peek();
      if (token.type === "EOF") break;
      if (token.type === "Keyword" && BLOCK_TERMINATORS.has(token.value)) break;
      if (token.type === "Keyword" && token.value === "return") {
        body.push(this.parseReturn());
        break;
      }
      const statement = this.parseStatement();
      if (statement !== null) body.push(statement);
    }
    return body;
  }

  private parseStatement(): LuauNode | null {
    const token = this.peek();
    if (token.type === "Punctuator") {
      if (token.value === ";") {
        this.next();
        return null;
      }
      if (token.value === "::") return this.parseLabel();
    }
    if (token.type === "Keyword") {
      switch (token.value) {
        case "local":
          return this.parseLocal();
        case "if":
          return this.parseIf();
        case "while":
          return this.parseWhile();
        case "do":
          return this.parseDo();
        case "for":
          return this.parseFor();
        case "repeat":
          return this.parseRepeat();
        case "function":
          return this.parseFunctionStatement();
        case "break": {
          this.next();
          return this.node({ type: "BreakStatement" }, token);
        }
        default:
          break;
      }
    }
    if (token.type === "Identifier") {
      // `continue`, `type`, and `export` are contextual: they are statements
      // only when the following token cannot continue an expression.
      if (token.value === "continue" && this.startsNewStatement(1)) {
        this.next();
        return this.node({ type: "ContinueStatement" }, token);
      }
      if (token.value === "goto" && this.peek(1).type === "Identifier") {
        this.next();
        const label = this.expectName();
        return this.node(
          { type: "GotoStatement", label: this.identifier(label) },
          token,
        );
      }
      if (token.value === "type" && this.peek(1).type === "Identifier") {
        return this.parseTypeAlias(token, false);
      }
      if (
        token.value === "export" &&
        this.peek(1).type === "Identifier" &&
        this.peek(1).value === "type"
      ) {
        this.next();
        return this.parseTypeAlias(this.peek(), true);
      }
    }
    return this.parseExpressionStatement();
  }

  /**
   * Decide whether the token at `offset` begins a new statement, which is how
   * a contextual keyword like `continue` is told apart from a variable of the
   * same name being called or indexed.
   */
  private startsNewStatement(offset: number): boolean {
    const token = this.peek(offset);
    if (token.type === "EOF") return true;
    if (token.type === "Keyword") return !BLOCK_TERMINATORS.has(token.value)
      ? true
      : true;
    if (token.type === "Punctuator") {
      return !["(", "[", ".", ":", ",", "=", "{"].includes(token.value) &&
        !COMPOUND_OPERATORS.has(token.value);
    }
    // A string literal directly after a name is a call: `continue "x"`.
    return token.type !== "StringLiteral";
  }

  private parseLabel(): LuauNode {
    const start = this.expect("::");
    const name = this.expectName();
    this.expect("::");
    return this.node(
      { type: "LabelStatement", label: this.identifier(name) },
      start,
    );
  }

  private parseReturn(): LuauNode {
    const start = this.expect("return");
    const args: LuauNode[] = [];
    if (!this.blockEnded() && !this.at(";")) {
      do {
        args.push(this.parseExpression());
      } while (this.accept(",") !== null);
    }
    this.accept(";");
    return this.node({ type: "ReturnStatement", arguments: args }, start);
  }

  private blockEnded(): boolean {
    const token = this.peek();
    if (token.type === "EOF") return true;
    return token.type === "Keyword" && BLOCK_TERMINATORS.has(token.value);
  }

  private parseLocal(): LuauNode {
    const start = this.expect("local");
    if (this.at("function")) {
      this.next();
      const name = this.expectName();
      const body = this.parseFunctionBody();
      return this.node(
        {
          type: "FunctionDeclaration",
          identifier: this.identifier(name),
          isLocal: true,
          parameters: body.parameters,
          body: body.body,
          returnTypeAnnotation: body.returnTypeAnnotation,
        },
        start,
      );
    }
    const variables: LuauNode[] = [];
    const init: LuauNode[] = [];
    do {
      const name = this.expectName();
      variables.push(this.identifier(name, this.parseOptionalTypeAnnotation()));
    } while (this.accept(",") !== null);
    if (this.accept("=") !== null) {
      do {
        init.push(this.parseExpression());
      } while (this.accept(",") !== null);
    }
    return this.node({ type: "LocalStatement", variables, init }, start);
  }

  private parseIf(): LuauNode {
    const start = this.expect("if");
    const clauses: LuauNode[] = [];
    const condition = this.parseExpression();
    this.expect("then");
    clauses.push(
      this.node({ type: "IfClause", condition, body: this.parseBlock() }, start),
    );
    for (;;) {
      if (this.at("elseif")) {
        const clauseStart = this.next();
        const elseifCondition = this.parseExpression();
        this.expect("then");
        clauses.push(
          this.node(
            {
              type: "ElseifClause",
              condition: elseifCondition,
              body: this.parseBlock(),
            },
            clauseStart,
          ),
        );
        continue;
      }
      if (this.at("else")) {
        const clauseStart = this.next();
        clauses.push(
          this.node({ type: "ElseClause", body: this.parseBlock() }, clauseStart),
        );
      }
      break;
    }
    this.expect("end");
    return this.node({ type: "IfStatement", clauses }, start);
  }

  private parseWhile(): LuauNode {
    const start = this.expect("while");
    const condition = this.parseExpression();
    this.expect("do");
    const body = this.parseBlock();
    this.expect("end");
    return this.node({ type: "WhileStatement", condition, body }, start);
  }

  private parseDo(): LuauNode {
    const start = this.expect("do");
    const body = this.parseBlock();
    this.expect("end");
    return this.node({ type: "DoStatement", body }, start);
  }

  private parseRepeat(): LuauNode {
    const start = this.expect("repeat");
    const body = this.parseBlock();
    this.expect("until");
    const condition = this.parseExpression();
    return this.node({ type: "RepeatStatement", condition, body }, start);
  }

  private parseFor(): LuauNode {
    const start = this.expect("for");
    const first = this.expectName();
    const firstAnnotation = this.parseOptionalTypeAnnotation();
    if (this.accept("=") !== null) {
      const startExpression = this.parseExpression();
      this.expect(",");
      const endExpression = this.parseExpression();
      const step = this.accept(",") !== null ? this.parseExpression() : null;
      this.expect("do");
      const body = this.parseBlock();
      this.expect("end");
      return this.node(
        {
          type: "ForNumericStatement",
          variable: this.identifier(first, firstAnnotation),
          start: startExpression,
          end: endExpression,
          step,
          body,
        },
        start,
      );
    }
    const variables = [this.identifier(first, firstAnnotation)];
    while (this.accept(",") !== null) {
      const name = this.expectName();
      variables.push(this.identifier(name, this.parseOptionalTypeAnnotation()));
    }
    this.expect("in");
    const iterators: LuauNode[] = [];
    do {
      iterators.push(this.parseExpression());
    } while (this.accept(",") !== null);
    this.expect("do");
    const body = this.parseBlock();
    this.expect("end");
    return this.node(
      { type: "ForGenericStatement", variables, iterators, body },
      start,
    );
  }

  private parseFunctionStatement(): LuauNode {
    const start = this.expect("function");
    let identifier: LuauNode = this.identifier(this.expectName());
    let isMethod = false;
    for (;;) {
      if (this.accept(".") !== null) {
        const name = this.expectName();
        identifier = this.node(
          {
            type: "MemberExpression",
            indexer: ".",
            identifier: this.identifier(name),
            base: identifier,
          },
          start,
        );
        continue;
      }
      if (this.accept(":") !== null) {
        const name = this.expectName();
        identifier = this.node(
          {
            type: "MemberExpression",
            indexer: ":",
            identifier: this.identifier(name),
            base: identifier,
          },
          start,
        );
        isMethod = true;
        break;
      }
      break;
    }
    const body = this.parseFunctionBody(isMethod);
    return this.node(
      {
        type: "FunctionDeclaration",
        identifier,
        isLocal: false,
        parameters: body.parameters,
        body: body.body,
        returnTypeAnnotation: body.returnTypeAnnotation,
      },
      start,
    );
  }

  private parseFunctionBody(isMethod = false): {
    parameters: LuauNode[];
    body: LuauNode[];
    returnTypeAnnotation: TypeSpan | null;
  } {
    // Generic parameter lists on functions are Luau-only and carry no runtime
    // effect, so they are consumed as a balanced span.
    if (this.at("<")) this.skipBalanced("<", ">");
    this.expect("(");
    const parameters: LuauNode[] = [];
    if (isMethod) {
      const selfToken = this.peek();
      parameters.push(
        this.node({ type: "Identifier", name: "self", isImplicitSelf: true }, selfToken, selfToken),
      );
    }
    if (!this.at(")")) {
      do {
        if (this.peek().type === "VarargLiteral") {
          const vararg = this.next();
          this.parseOptionalTypeAnnotation();
          parameters.push(this.node({ type: "VarargLiteral", value: "..." }, vararg));
          break;
        }
        const name = this.expectName();
        parameters.push(this.identifier(name, this.parseOptionalTypeAnnotation()));
      } while (this.accept(",") !== null);
    }
    this.expect(")");
    const returnTypeAnnotation = this.parseOptionalTypeAnnotation();
    const body = this.parseBlock();
    this.expect("end");
    return { parameters, body, returnTypeAnnotation };
  }

  private parseTypeAlias(start: LuauToken, exported: boolean): LuauNode {
    if (exported) {
      // `export` was already consumed; `type` is the current token.
      this.next();
    } else {
      this.next();
    }
    const name = this.expectName();
    if (this.at("<")) this.skipBalanced("<", ">");
    this.expect("=");
    const annotation = this.readTypeSpan();
    return this.node(
      {
        type: "TypeAliasStatement",
        identifier: this.identifier(name),
        exported,
        annotation,
      },
      start,
    );
  }

  private parseExpressionStatement(): LuauNode {
    const start = this.peek();
    const first = this.parseSuffixedExpression();

    const operator = this.peek();
    if (
      operator.type === "Punctuator" &&
      COMPOUND_OPERATORS.has(operator.value)
    ) {
      this.next();
      const value = this.parseExpression();
      this.assertAssignable(first, start);
      return this.node(
        {
          type: "CompoundAssignmentStatement",
          operator: operator.value,
          variable: first,
          init: value,
        },
        start,
      );
    }

    if (this.at(",") || this.at("=")) {
      const variables = [first];
      while (this.accept(",") !== null) {
        variables.push(this.parseSuffixedExpression());
      }
      this.expect("=");
      const init: LuauNode[] = [];
      do {
        init.push(this.parseExpression());
      } while (this.accept(",") !== null);
      for (const variable of variables) this.assertAssignable(variable, start);
      return this.node({ type: "AssignmentStatement", variables, init }, start);
    }

    if (
      first.type !== "CallExpression" &&
      first.type !== "TableCallExpression" &&
      first.type !== "StringCallExpression"
    ) {
      this.fail("This expression is not a statement.", start);
    }
    return this.node({ type: "CallStatement", expression: first }, start);
  }

  private assertAssignable(node: LuauNode, token: LuauToken): void {
    if (
      node.type !== "Identifier" &&
      node.type !== "MemberExpression" &&
      node.type !== "IndexExpression"
    ) {
      this.fail("Cannot assign to this expression.", token);
    }
  }

  // ------------------------------------------------------------ expressions

  private parseExpression(limit = 0): LuauNode {
    const start = this.peek();
    let left: LuauNode;

    const unary = this.peek();
    const isUnary =
      (unary.type === "Punctuator" && ["-", "#", "~"].includes(unary.value)) ||
      (unary.type === "Keyword" && unary.value === "not");
    if (isUnary) {
      this.next();
      const argument = this.parseExpression(UNARY_PRECEDENCE);
      left = this.node(
        { type: "UnaryExpression", operator: unary.value, argument },
        unary,
      );
    } else {
      left = this.parseSimpleExpression();
    }

    for (;;) {
      const token = this.peek();
      if (token.type === "Punctuator" && token.value === "::") {
        /*
         * `::` is a Luau type assertion in an expression and a Lua 5.4 label
         * delimiter at statement start.  With no statement terminator in the
         * grammar, only the shape distinguishes them: `:: Name ::` closes, so
         * it is a label and the expression ended at the previous token.
         */
        if (
          this.peek(1).type === "Identifier" &&
          this.peek(2).type === "Punctuator" &&
          this.peek(2).value === "::"
        ) {
          break;
        }
        this.next();
        const annotation = this.readTypeSpan();
        left = this.node(
          { type: "TypeCastExpression", expression: left, annotation },
          start,
        );
        continue;
      }
      if (token.type !== "Punctuator" && token.type !== "Keyword") break;
      const precedence = BINARY_PRECEDENCE[token.value];
      if (precedence === undefined || precedence[0] <= limit) break;
      this.next();
      const right = this.parseExpression(precedence[1]);
      const nodeType =
        token.value === "and" || token.value === "or"
          ? "LogicalExpression"
          : "BinaryExpression";
      left = this.node(
        { type: nodeType, operator: token.value, left, right },
        start,
      );
    }
    return left;
  }

  private parseSimpleExpression(): LuauNode {
    const token = this.peek();
    switch (token.type) {
      case "NumericLiteral":
        this.next();
        return this.node(
          { type: "NumericLiteral", value: token.numeric ?? 0, raw: token.raw },
          token,
        );
      case "StringLiteral":
        this.next();
        return this.node(
          { type: "StringLiteral", value: token.value, raw: token.raw },
          token,
        );
      case "InterpolatedStringPart":
        return this.parseInterpolatedString();
      case "VarargLiteral":
        this.next();
        return this.node({ type: "VarargLiteral", value: "..." }, token);
      case "Keyword":
        if (token.value === "nil") {
          this.next();
          return this.node({ type: "NilLiteral", value: null, raw: "nil" }, token);
        }
        if (token.value === "true" || token.value === "false") {
          this.next();
          return this.node(
            {
              type: "BooleanLiteral",
              value: token.value === "true",
              raw: token.value,
            },
            token,
          );
        }
        if (token.value === "function") {
          this.next();
          const body = this.parseFunctionBody();
          return this.node(
            {
              type: "FunctionDeclaration",
              identifier: null,
              isLocal: false,
              parameters: body.parameters,
              body: body.body,
              returnTypeAnnotation: body.returnTypeAnnotation,
            },
            token,
          );
        }
        break;
      case "Punctuator":
        if (token.value === "{") return this.parseTable();
        break;
      default:
        break;
    }
    return this.parseSuffixedExpression();
  }

  private parseInterpolatedString(): LuauNode {
    const start = this.peek();
    const parts: LuauNode[] = [];
    const expressions: LuauNode[] = [];
    for (;;) {
      const token = this.peek();
      if (token.type !== "InterpolatedStringPart") {
        this.fail("Malformed interpolated string.", token);
      }
      this.next();
      parts.push(
        this.node({ type: "StringLiteral", value: token.value, raw: token.raw }, token),
      );
      if (token.interpolation?.closesLiteral === true) break;
      expressions.push(this.parseExpression());
      // The lexer resumes string scanning at the matching `}`.
    }
    return this.node(
      { type: "InterpolatedStringExpression", parts, expressions },
      start,
    );
  }

  private parsePrimaryExpression(): LuauNode {
    const token = this.peek();
    if (token.type === "Identifier") {
      this.next();
      return this.identifier(token);
    }
    if (token.type === "Punctuator" && token.value === "(") {
      this.next();
      const inner = this.parseExpression();
      this.expect(")");
      // Parentheses truncate multiple results, so the grouping is retained.
      return this.node(
        { type: "ParenthesisExpression", expression: inner },
        token,
      );
    }
    this.fail(`Unexpected ${this.describe(token)} in an expression.`, token);
  }

  private parseSuffixedExpression(): LuauNode {
    const start = this.peek();
    let base = this.parsePrimaryExpression();
    for (;;) {
      const token = this.peek();
      if (token.type === "Punctuator") {
        if (token.value === ".") {
          this.next();
          const name = this.expectName();
          base = this.node(
            {
              type: "MemberExpression",
              indexer: ".",
              identifier: this.identifier(name),
              base,
            },
            start,
          );
          continue;
        }
        if (token.value === "[") {
          this.next();
          const index = this.parseExpression();
          this.expect("]");
          base = this.node({ type: "IndexExpression", base, index }, start);
          continue;
        }
        if (token.value === ":") {
          this.next();
          const name = this.expectName();
          const args = this.parseCallArguments();
          base = this.node(
            {
              type: "CallExpression",
              base: this.node(
                {
                  type: "MemberExpression",
                  indexer: ":",
                  identifier: this.identifier(name),
                  base,
                },
                start,
              ),
              arguments: args,
            },
            start,
          );
          continue;
        }
        if (token.value === "(") {
          base = this.node(
            { type: "CallExpression", base, arguments: this.parseCallArguments() },
            start,
          );
          continue;
        }
        if (token.value === "{") {
          base = this.node(
            { type: "TableCallExpression", base, arguments: [this.parseTable()] },
            start,
          );
          continue;
        }
      }
      if (token.type === "StringLiteral") {
        this.next();
        base = this.node(
          {
            type: "StringCallExpression",
            base,
            argument: this.node(
              { type: "StringLiteral", value: token.value, raw: token.raw },
              token,
            ),
          },
          start,
        );
        continue;
      }
      break;
    }
    return base;
  }

  private parseCallArguments(): LuauNode[] {
    this.expect("(");
    const args: LuauNode[] = [];
    if (!this.at(")")) {
      do {
        args.push(this.parseExpression());
      } while (this.accept(",") !== null);
    }
    this.expect(")");
    return args;
  }

  private parseTable(): LuauNode {
    const start = this.expect("{");
    const fields: LuauNode[] = [];
    while (!this.at("}")) {
      const fieldStart = this.peek();
      if (this.at("[")) {
        this.next();
        const key = this.parseExpression();
        this.expect("]");
        this.expect("=");
        const value = this.parseExpression();
        fields.push(this.node({ type: "TableKey", key, value }, fieldStart));
      } else if (
        fieldStart.type === "Identifier" &&
        this.peek(1).type === "Punctuator" &&
        this.peek(1).value === "="
      ) {
        const key = this.expectName();
        this.expect("=");
        const value = this.parseExpression();
        fields.push(
          this.node(
            { type: "TableKeyString", key: this.identifier(key), value },
            fieldStart,
          ),
        );
      } else {
        fields.push(
          this.node({ type: "TableValue", value: this.parseExpression() }, fieldStart),
        );
      }
      if (this.accept(",") === null && this.accept(";") === null) break;
    }
    this.expect("}");
    return this.node({ type: "TableConstructorExpression", fields }, start);
  }

  private identifier(token: LuauToken, typeAnnotation: TypeSpan | null = null): LuauNode {
    return this.node(
      {
        type: "Identifier",
        name: token.value,
        ...(typeAnnotation === null ? {} : { typeAnnotation }),
      },
      token,
      token,
    );
  }

  // ------------------------------------------------------------------ types

  private parseOptionalTypeAnnotation(): TypeSpan | null {
    if (!this.at(":")) return null;
    // `::` is lexed as one token, so a lone `:` here is always an annotation.
    this.next();
    return this.readTypeSpan();
  }

  /**
   * Consume one complete type expression, recorded as a source span.
   *
   * Type syntax cannot change what a program does, so it is retained by range
   * rather than modelled.  Consuming it precisely still matters: a span that
   * runs long would swallow the statement that follows the annotation.
   *
   * The grammar walked here is `atom ('?')* ( ('|' | '&' | '->') atom ... )`.
   */
  private readTypeSpan(): TypeSpan {
    const startToken = this.peek();
    let lastToken = this.readTypeAtom();
    for (;;) {
      const token = this.peek();
      if (
        token.type === "Punctuator" &&
        (token.value === "|" || token.value === "&" || token.value === "->")
      ) {
        this.next();
        lastToken = this.readTypeAtom();
        continue;
      }
      break;
    }
    return {
      range: [startToken.range[0], lastToken.range[1]],
      loc: { start: startToken.loc.start, end: lastToken.loc.end },
    };
  }

  /** One type term: a name path, a group, a literal, or a variadic marker. */
  private readTypeAtom(): LuauToken {
    const token = this.peek();
    let last: LuauToken;

    if (token.type === "Punctuator" && (token.value === "(" || token.value === "{")) {
      last = this.consumeBalanced(token.value, token.value === "(" ? ")" : "}");
    } else if (token.type === "StringLiteral" || token.type === "VarargLiteral") {
      last = this.next();
    } else if (token.type === "Keyword" && (token.value === "nil" || token.value === "function")) {
      // `nil` and `function` are valid type names despite being keywords.
      last = this.next();
    } else if (token.type === "Identifier") {
      last = this.next();
      // Qualified names such as `Roblox.Instance`.
      while (this.at(".") && this.peek(1).type === "Identifier") {
        this.next();
        last = this.next();
      }
      if (this.at("<")) last = this.consumeBalanced("<", ">");
    } else {
      this.fail(`Expected a type but found ${this.describe(token)}.`, token);
    }

    // Optional-type suffixes.
    while (this.at("?")) last = this.next();
    return last;
  }

  /** Consume a balanced bracket group and return its closing token. */
  private consumeBalanced(open: string, close: string): LuauToken {
    this.expect(open);
    let depth = 1;
    for (;;) {
      const token = this.next();
      if (token.type === "EOF") this.fail(`Unbalanced '${open}' in a type.`);
      if (token.type === "Punctuator") {
        if (token.value === open) depth += 1;
        else if (token.value === close) {
          depth -= 1;
          if (depth === 0) return token;
        } else if (open === "<" && token.value === ">>") {
          // `Map<string, Array<number>>` closes two levels with one token.
          depth -= 2;
          if (depth <= 0) return token;
        }
      }
    }
  }

  private skipBalanced(open: string, close: string): void {
    this.expect(open);
    let depth = 1;
    while (depth > 0) {
      const token = this.next();
      if (token.type === "EOF") this.fail(`Unbalanced '${open}'.`);
      if (token.type === "Punctuator") {
        if (token.value === open) depth += 1;
        else if (token.value === close) depth -= 1;
      }
    }
  }
}

export function parseLuau(
  source: string,
  options: ParseLuauOptions = {},
): LuauChunk {
  const { tokens, comments } = lexLuau(source);
  return new Parser(tokens, comments, options).parseChunk();
}
