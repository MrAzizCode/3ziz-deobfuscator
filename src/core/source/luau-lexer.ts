/**
 * Bounded tokenizer for Lua 5.1 through Luau source.
 *
 * `luaparse` targets Lua 5.1 and rejects everything a modern Roblox script or
 * a Luau-targeting obfuscator emits: bitwise operators, floor division, hex
 * float literals, digit separators, `continue`, compound assignment, string
 * interpolation, and type annotations.  Without a front end that accepts those
 * forms the analyzer cannot reach the source at all.
 *
 * This is a pure lexical reader.  It never evaluates what it reads.
 */

export type LuauTokenType =
  | "Identifier"
  | "Keyword"
  | "NumericLiteral"
  | "StringLiteral"
  | "InterpolatedStringPart"
  | "Punctuator"
  | "VarargLiteral"
  | "EOF";

export interface LuauPosition {
  readonly line: number;
  readonly column: number;
}

export interface LuauSourceLocation {
  readonly start: LuauPosition;
  readonly end: LuauPosition;
}

export interface LuauToken {
  readonly type: LuauTokenType;
  /** Identifier text, keyword text, operator text, or decoded literal value. */
  readonly value: string;
  /** Exact source text of the token, before any escape resolution. */
  readonly raw: string;
  readonly range: readonly [number, number];
  readonly loc: LuauSourceLocation;
  /** Numeric literals only: the parsed value. */
  readonly numeric?: number;
  /**
   * Interpolated string parts only: whether an expression follows this chunk
   * and whether this chunk closes the literal.
   */
  readonly interpolation?: {
    readonly opensExpression: boolean;
    readonly closesLiteral: boolean;
  };
}

export interface LuauComment {
  readonly value: string;
  readonly raw: string;
  readonly range: readonly [number, number];
  readonly loc: LuauSourceLocation;
}

export interface LuauLexResult {
  readonly tokens: readonly LuauToken[];
  readonly comments: readonly LuauComment[];
}

export class LuauSyntaxError extends Error {
  readonly index: number;
  readonly line: number;
  readonly column: number;

  constructor(message: string, index: number, line: number, column: number) {
    super(`[${line}:${column}] ${message}`);
    this.name = "LuauSyntaxError";
    this.index = index;
    this.line = line;
    this.column = column;
  }
}

export const LUAU_KEYWORDS: ReadonlySet<string> = new Set([
  "and",
  "break",
  "do",
  "else",
  "elseif",
  "end",
  "false",
  "for",
  "function",
  "if",
  "in",
  "local",
  "nil",
  "not",
  "or",
  "repeat",
  "return",
  "then",
  "true",
  "until",
  "while",
]);

/**
 * Longest-first so the scanner never splits a multi-character operator.
 * Compound assignment and `::` are Luau additions; the rest are Lua 5.3+.
 */
const PUNCTUATORS: readonly string[] = [
  "...",
  "//=",
  "..=",
  "<<=",
  ">>=",
  "==",
  "~=",
  "<=",
  ">=",
  // Luau function-type arrow.
  "->",
  "//",
  "..",
  "::",
  "<<",
  ">>",
  "+=",
  "-=",
  "*=",
  "/=",
  "%=",
  "^=",
  "+",
  "-",
  "*",
  "/",
  "%",
  "^",
  "#",
  "&",
  "~",
  "|",
  "<",
  ">",
  "=",
  "(",
  ")",
  "{",
  "}",
  "[",
  "]",
  ";",
  ":",
  ",",
  ".",
  "?",
];

const SIMPLE_ESCAPES: Readonly<Record<string, string>> = {
  a: "",
  b: "\b",
  f: "\f",
  n: "\n",
  r: "\r",
  t: "\t",
  v: "\v",
  "\\": "\\",
  '"': '"',
  "'": "'",
  "`": "`",
  "{": "{",
};

function isDigit(character: string | undefined): boolean {
  return character !== undefined && character >= "0" && character <= "9";
}

function isHexDigit(character: string | undefined): boolean {
  if (character === undefined) return false;
  return (
    (character >= "0" && character <= "9") ||
    (character >= "a" && character <= "f") ||
    (character >= "A" && character <= "F")
  );
}

function isIdentifierStart(character: string | undefined): boolean {
  if (character === undefined) return false;
  return (
    (character >= "a" && character <= "z") ||
    (character >= "A" && character <= "Z") ||
    character === "_"
  );
}

function isIdentifierPart(character: string | undefined): boolean {
  return isIdentifierStart(character) || isDigit(character);
}

class Lexer {
  private index = 0;
  private line = 1;
  private lineStart = 0;
  private readonly tokens: LuauToken[] = [];
  private readonly comments: LuauComment[] = [];
  /**
   * Interpolated strings nest: `` `a{ f(`b`) }c` ``.  Each entry marks that a
   * closing `}` should resume string scanning rather than close a table.
   */
  private readonly interpolationDepth: number[] = [];
  private braceDepth = 0;

  constructor(private readonly source: string) {}

  lex(): LuauLexResult {
    for (;;) {
      this.skipTrivia();
      if (this.index >= this.source.length) break;
      this.readToken();
    }
    this.push("EOF", "", "", this.index, this.index);
    return { tokens: this.tokens, comments: this.comments };
  }

  private position(index: number): LuauPosition {
    return { line: this.line, column: index - this.lineStart };
  }

  private fail(message: string, index = this.index): never {
    throw new LuauSyntaxError(
      message,
      index,
      this.line,
      index - this.lineStart,
    );
  }

  private advanceLine(): void {
    this.line += 1;
    this.lineStart = this.index;
  }

  private push(
    type: LuauTokenType,
    value: string,
    raw: string,
    start: number,
    end: number,
    startLoc?: LuauPosition,
    extra?: Partial<LuauToken>,
  ): void {
    this.tokens.push({
      type,
      value,
      raw,
      range: [start, end],
      loc: {
        start: startLoc ?? this.position(start),
        end: this.position(end),
      },
      ...extra,
    });
  }

  private skipTrivia(): void {
    for (;;) {
      const character = this.source[this.index];
      if (character === undefined) return;
      if (character === "\n") {
        this.index += 1;
        this.advanceLine();
        continue;
      }
      if (character === " " || character === "\t" || character === "\r" || character === "\f" || character === "\v") {
        this.index += 1;
        continue;
      }
      if (character === "-" && this.source[this.index + 1] === "-") {
        this.readComment();
        continue;
      }
      // A shebang-style first line is tolerated so tooling output can be read.
      if (character === "#" && this.index === 0 && this.source[1] === "!") {
        while (this.index < this.source.length && this.source[this.index] !== "\n") {
          this.index += 1;
        }
        continue;
      }
      return;
    }
  }

  private readComment(): void {
    const start = this.index;
    const startLoc = this.position(start);
    this.index += 2;
    const long = this.tryReadLongBracket();
    if (long !== null) {
      this.comments.push({
        value: long.value,
        raw: this.source.slice(start, this.index),
        range: [start, this.index],
        loc: { start: startLoc, end: this.position(this.index) },
      });
      return;
    }
    while (this.index < this.source.length && this.source[this.index] !== "\n") {
      this.index += 1;
    }
    this.comments.push({
      value: this.source.slice(start + 2, this.index),
      raw: this.source.slice(start, this.index),
      range: [start, this.index],
      loc: { start: startLoc, end: this.position(this.index) },
    });
  }

  /** Read `[[...]]` / `[==[...]==]` when one starts here, else return null. */
  private tryReadLongBracket(): { value: string } | null {
    if (this.source[this.index] !== "[") return null;
    let cursor = this.index + 1;
    let level = 0;
    while (this.source[cursor] === "=") {
      level += 1;
      cursor += 1;
    }
    if (this.source[cursor] !== "[") return null;
    cursor += 1;
    // A newline immediately after the opener is not part of the contents.
    if (this.source[cursor] === "\r") cursor += 1;
    if (this.source[cursor] === "\n") {
      cursor += 1;
      this.index = cursor;
      this.advanceLine();
    }
    const contentStart = cursor;
    const close = `]${"=".repeat(level)}]`;
    const contentEnd = this.source.indexOf(close, contentStart);
    if (contentEnd < 0) this.fail("Unterminated long bracket.");
    const value = this.source.slice(contentStart, contentEnd);
    for (let scan = contentStart; scan < contentEnd; scan += 1) {
      if (this.source[scan] === "\n") {
        this.index = scan + 1;
        this.advanceLine();
      }
    }
    this.index = contentEnd + close.length;
    return { value };
  }

  private readToken(): void {
    const character = this.source[this.index]!;
    if (isIdentifierStart(character)) return this.readName();
    if (isDigit(character)) return this.readNumber();
    if (character === "." && isDigit(this.source[this.index + 1])) {
      return this.readNumber();
    }
    if (character === '"' || character === "'") return this.readQuoted(character);
    if (character === "`") return this.readInterpolatedStart();
    if (character === "[") {
      const start = this.index;
      const startLoc = this.position(start);
      const long = this.tryReadLongBracket();
      if (long !== null) {
        this.push(
          "StringLiteral",
          long.value,
          this.source.slice(start, this.index),
          start,
          this.index,
          startLoc,
        );
        return;
      }
    }
    if (character === "}" && this.closesInterpolation()) {
      return this.readInterpolatedContinuation();
    }
    return this.readPunctuator();
  }

  private closesInterpolation(): boolean {
    const top = this.interpolationDepth[this.interpolationDepth.length - 1];
    return top !== undefined && top === this.braceDepth;
  }

  private readName(): void {
    const start = this.index;
    while (isIdentifierPart(this.source[this.index])) this.index += 1;
    const text = this.source.slice(start, this.index);
    if (text === "...") {
      this.push("VarargLiteral", text, text, start, this.index);
      return;
    }
    this.push(
      LUAU_KEYWORDS.has(text) ? "Keyword" : "Identifier",
      text,
      text,
      start,
      this.index,
    );
  }

  private readNumber(): void {
    const start = this.index;
    let value: number;
    if (
      this.source[this.index] === "0" &&
      (this.source[this.index + 1] === "x" || this.source[this.index + 1] === "X")
    ) {
      this.index += 2;
      value = this.readHexNumber(start);
    } else if (
      this.source[this.index] === "0" &&
      (this.source[this.index + 1] === "b" || this.source[this.index + 1] === "B")
    ) {
      // Luau binary literal.
      this.index += 2;
      const digitsStart = this.index;
      while (this.source[this.index] === "0" || this.source[this.index] === "1" || this.source[this.index] === "_") {
        this.index += 1;
      }
      const digits = this.source.slice(digitsStart, this.index).replace(/_/g, "");
      if (digits.length === 0) this.fail("Binary literal has no digits.", start);
      value = Number.parseInt(digits, 2);
    } else {
      value = this.readDecimalNumber(start);
    }
    const raw = this.source.slice(start, this.index);
    this.push("NumericLiteral", raw, raw, start, this.index, undefined, {
      numeric: value,
    });
  }

  private readHexNumber(start: number): number {
    const digitsStart = this.index;
    while (isHexDigit(this.source[this.index]) || this.source[this.index] === "_") {
      this.index += 1;
    }
    let mantissa = this.source.slice(digitsStart, this.index).replace(/_/g, "");
    let fraction = "";
    if (this.source[this.index] === ".") {
      this.index += 1;
      const fractionStart = this.index;
      while (isHexDigit(this.source[this.index]) || this.source[this.index] === "_") {
        this.index += 1;
      }
      fraction = this.source.slice(fractionStart, this.index).replace(/_/g, "");
    }
    if (mantissa.length === 0 && fraction.length === 0) {
      this.fail("Hexadecimal literal has no digits.", start);
    }
    let exponent = 0;
    let hasExponent = false;
    if (this.source[this.index] === "p" || this.source[this.index] === "P") {
      hasExponent = true;
      this.index += 1;
      let sign = 1;
      if (this.source[this.index] === "+" || this.source[this.index] === "-") {
        if (this.source[this.index] === "-") sign = -1;
        this.index += 1;
      }
      const exponentStart = this.index;
      while (isDigit(this.source[this.index]) || this.source[this.index] === "_") {
        this.index += 1;
      }
      const digits = this.source.slice(exponentStart, this.index).replace(/_/g, "");
      if (digits.length === 0) this.fail("Hexadecimal exponent has no digits.", start);
      exponent = sign * Number.parseInt(digits, 10);
    }
    if (fraction.length === 0 && !hasExponent) {
      // Plain hexadecimal integers keep exact values past 2^53 where possible.
      mantissa = mantissa.length === 0 ? "0" : mantissa;
      return Number(BigInt(`0x${mantissa}`));
    }
    let magnitude = mantissa.length === 0 ? 0 : Number(BigInt(`0x${mantissa}`));
    for (let position = 0; position < fraction.length; position += 1) {
      magnitude += Number.parseInt(fraction[position]!, 16) / 16 ** (position + 1);
    }
    return magnitude * 2 ** exponent;
  }

  private readDecimalNumber(start: number): number {
    while (isDigit(this.source[this.index]) || this.source[this.index] === "_") {
      this.index += 1;
    }
    if (this.source[this.index] === ".") {
      this.index += 1;
      while (isDigit(this.source[this.index]) || this.source[this.index] === "_") {
        this.index += 1;
      }
    }
    if (this.source[this.index] === "e" || this.source[this.index] === "E") {
      this.index += 1;
      if (this.source[this.index] === "+" || this.source[this.index] === "-") {
        this.index += 1;
      }
      const exponentStart = this.index;
      while (isDigit(this.source[this.index]) || this.source[this.index] === "_") {
        this.index += 1;
      }
      if (this.index === exponentStart) this.fail("Exponent has no digits.", start);
    }
    const text = this.source.slice(start, this.index).replace(/_/g, "");
    const value = Number(text);
    if (Number.isNaN(value)) this.fail(`Malformed number '${text}'.`, start);
    return value;
  }

  /** Shared escape reader for quoted and interpolated strings. */
  private readEscape(out: string[]): void {
    const start = this.index;
    this.index += 1;
    const next = this.source[this.index];
    if (next === undefined) this.fail("String ends with a dangling backslash.", start);
    if (next === "\n") {
      out.push("\n");
      this.index += 1;
      this.advanceLine();
      return;
    }
    if (next === "\r") {
      out.push("\n");
      this.index += 1;
      if (this.source[this.index] === "\n") this.index += 1;
      this.advanceLine();
      return;
    }
    if (isDigit(next)) {
      let digits = "";
      while (digits.length < 3 && isDigit(this.source[this.index])) {
        digits += this.source[this.index];
        this.index += 1;
      }
      const value = Number.parseInt(digits, 10);
      if (value > 255) this.fail(`Decimal escape \\${digits} exceeds 255.`, start);
      out.push(String.fromCharCode(value));
      return;
    }
    if (next === "x") {
      this.index += 1;
      const digits = this.source.slice(this.index, this.index + 2);
      if (!isHexDigit(digits[0]) || !isHexDigit(digits[1])) {
        this.fail("\\x escape needs two hexadecimal digits.", start);
      }
      out.push(String.fromCharCode(Number.parseInt(digits, 16)));
      this.index += 2;
      return;
    }
    if (next === "z") {
      this.index += 1;
      while (this.index < this.source.length && /\s/.test(this.source[this.index]!)) {
        if (this.source[this.index] === "\n") {
          this.index += 1;
          this.advanceLine();
        } else {
          this.index += 1;
        }
      }
      return;
    }
    if (next === "u" && this.source[this.index + 1] === "{") {
      const close = this.source.indexOf("}", this.index + 2);
      if (close < 0) this.fail("Unterminated \\u{...} escape.", start);
      const codePoint = Number.parseInt(this.source.slice(this.index + 2, close), 16);
      if (!Number.isInteger(codePoint) || codePoint < 0 || codePoint > 0x10ffff) {
        this.fail("Invalid \\u{...} escape.", start);
      }
      out.push(String.fromCodePoint(codePoint));
      this.index = close + 1;
      return;
    }
    const simple = SIMPLE_ESCAPES[next];
    if (simple !== undefined) {
      out.push(simple);
      this.index += 1;
      return;
    }
    /*
     * Lua 5.1 emits an unrecognized escape as the escaped character itself;
     * 5.2 made it an error.  Obfuscators exploit the older behavior - one
     * authorized sample hides "readstring" as 'r\101\u{0061}d\s\116\z r\z in\g'
     * - so the lenient reading is required to see the string at all.
     */
    out.push(next);
    this.index += 1;
  }

  private readQuoted(quote: string): void {
    const start = this.index;
    const startLoc = this.position(start);
    this.index += 1;
    const out: string[] = [];
    for (;;) {
      const character = this.source[this.index];
      if (character === undefined || character === "\n") {
        this.fail("Unterminated string literal.", start);
      }
      if (character === "\\") {
        this.readEscape(out);
        continue;
      }
      if (character === quote) {
        this.index += 1;
        break;
      }
      out.push(character);
      this.index += 1;
    }
    this.push(
      "StringLiteral",
      out.join(""),
      this.source.slice(start, this.index),
      start,
      this.index,
      startLoc,
    );
  }

  /** Read from the opening backtick to the first `{` or the closing backtick. */
  private readInterpolatedStart(): void {
    this.index += 1;
    this.readInterpolatedChunk(this.index - 1);
  }

  /** Read from a closing `}` to the next `{` or the closing backtick. */
  private readInterpolatedContinuation(): void {
    this.interpolationDepth.pop();
    this.index += 1;
    this.readInterpolatedChunk(this.index - 1);
  }

  private readInterpolatedChunk(start: number): void {
    const startLoc = this.position(start);
    const out: string[] = [];
    for (;;) {
      const character = this.source[this.index];
      if (character === undefined) this.fail("Unterminated interpolated string.", start);
      if (character === "\\") {
        this.readEscape(out);
        continue;
      }
      if (character === "{") {
        this.index += 1;
        this.interpolationDepth.push(this.braceDepth);
        this.push(
          "InterpolatedStringPart",
          out.join(""),
          this.source.slice(start, this.index),
          start,
          this.index,
          startLoc,
          { interpolation: { opensExpression: true, closesLiteral: false } },
        );
        return;
      }
      if (character === "`") {
        this.index += 1;
        this.push(
          "InterpolatedStringPart",
          out.join(""),
          this.source.slice(start, this.index),
          start,
          this.index,
          startLoc,
          { interpolation: { opensExpression: false, closesLiteral: true } },
        );
        return;
      }
      if (character === "\n") this.fail("Unterminated interpolated string.", start);
      out.push(character);
      this.index += 1;
    }
  }

  private readPunctuator(): void {
    for (const punctuator of PUNCTUATORS) {
      if (this.source.startsWith(punctuator, this.index)) {
        const start = this.index;
        this.index += punctuator.length;
        if (punctuator === "{") this.braceDepth += 1;
        if (punctuator === "}") this.braceDepth = Math.max(0, this.braceDepth - 1);
        if (punctuator === "...") {
          this.push("VarargLiteral", "...", "...", start, this.index);
          return;
        }
        this.push("Punctuator", punctuator, punctuator, start, this.index);
        return;
      }
    }
    this.fail(`Unexpected character '${this.source[this.index]}'.`);
  }
}

export function lexLuau(source: string): LuauLexResult {
  return new Lexer(source).lex();
}
