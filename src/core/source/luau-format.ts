export type LuauTokenKind =
  | "word"
  | "number"
  | "string"
  | "comment"
  | "symbol";

export interface LuauToken {
  readonly kind: LuauTokenKind;
  readonly raw: string;
  readonly start: number;
  readonly end: number;
}

export interface StaticFormatResult {
  readonly source: string;
  readonly lineCount: number;
  readonly tokenCount: number;
  readonly functionCount: number;
  readonly verifiedTokenPreservation: boolean;
}

const MULTI_SYMBOLS = [
  "...",
  "::",
  "==",
  "~=",
  "<=",
  ">=",
  "//",
  "..",
  "+=",
  "-=",
  "*=",
  "/=",
  "%=",
  "^=",
  "->",
] as const;

const BINARY_OPERATORS = new Set([
  "=",
  "==",
  "~=",
  "<",
  ">",
  "<=",
  ">=",
  "+",
  "-",
  "*",
  "/",
  "//",
  "%",
  "^",
  "..",
  "+=",
  "-=",
  "*=",
  "/=",
  "%=",
  "^=",
]);

const SPACE_AFTER_WORD = new Set([
  "and",
  "else",
  "elseif",
  "for",
  "if",
  "in",
  "local",
  "not",
  "or",
  "return",
  "then",
  "until",
  "while",
]);

const SPACE_BEFORE_WORD = new Set([
  "and",
  "do",
  "in",
  "or",
  "then",
]);

function longBracketEnd(source: string, start: number): number | null {
  if (source[start] !== "[") return null;
  let cursor = start + 1;
  while (source[cursor] === "=") cursor += 1;
  if (source[cursor] !== "[") return null;
  const closing = `]${"=".repeat(cursor - start - 1)}]`;
  const end = source.indexOf(closing, cursor + 1);
  return end < 0 ? source.length : end + closing.length;
}

function shortStringEnd(source: string, start: number): number {
  const quote = source[start];
  let cursor = start + 1;
  while (cursor < source.length) {
    if (source[cursor] === "\\") {
      cursor = Math.min(source.length, cursor + 2);
    } else if (source[cursor] === quote) {
      return cursor + 1;
    } else {
      cursor += 1;
    }
  }
  return source.length;
}

function numberEnd(source: string, start: number): number {
  const slice = source.slice(start);
  const match = /^(?:0[xX][0-9A-Fa-f]+(?:\.[0-9A-Fa-f]*)?(?:[pP][+-]?\d+)?|\d+(?:\.(?!\.)\d*)?(?:[eE][+-]?\d+)?|\.\d+(?:[eE][+-]?\d+)?)/.exec(
    slice,
  );
  return start + Math.max(1, match?.[0].length ?? 0);
}

/**
 * A bounded, non-executing Lua/Luau lexer used only for presentation. It keeps
 * every non-whitespace token byte-for-byte so formatting cannot alter strings,
 * numbers, identifiers, operators, or comments.
 */
export function lexLuauStatically(source: string): readonly LuauToken[] {
  const tokens: LuauToken[] = [];
  let cursor = 0;
  const push = (kind: LuauTokenKind, start: number, end: number): void => {
    tokens.push({ kind, raw: source.slice(start, end), start, end });
    cursor = end;
  };

  while (cursor < source.length) {
    const character = source[cursor] ?? "";
    if (/\s/u.test(character)) {
      cursor += 1;
      continue;
    }

    if (source.startsWith("--", cursor)) {
      const longEnd = longBracketEnd(source, cursor + 2);
      if (longEnd !== null) {
        push("comment", cursor, longEnd);
      } else {
        const newline = source.indexOf("\n", cursor + 2);
        push("comment", cursor, newline < 0 ? source.length : newline);
      }
      continue;
    }

    if (character === '"' || character === "'") {
      push("string", cursor, shortStringEnd(source, cursor));
      continue;
    }

    if (character === "[") {
      const end = longBracketEnd(source, cursor);
      if (end !== null) {
        push("string", cursor, end);
        continue;
      }
    }

    if (/[A-Za-z_]/u.test(character)) {
      let end = cursor + 1;
      while (/[A-Za-z0-9_]/u.test(source[end] ?? "")) end += 1;
      push("word", cursor, end);
      continue;
    }

    if (/\d/u.test(character) || (character === "." && /\d/u.test(source[cursor + 1] ?? ""))) {
      push("number", cursor, numberEnd(source, cursor));
      continue;
    }

    const symbol = MULTI_SYMBOLS.find((candidate) => source.startsWith(candidate, cursor));
    push("symbol", cursor, cursor + (symbol?.length ?? 1));
  }
  return tokens;
}

function tokenKey(token: LuauToken): string {
  return `${token.kind}:${token.raw}`;
}

function equivalentTokens(left: readonly LuauToken[], right: readonly LuauToken[]): boolean {
  return left.length === right.length && left.every((token, index) => tokenKey(token) === tokenKey(right[index]!));
}

function isWordLike(token: LuauToken | undefined): boolean {
  return token?.kind === "word" || token?.kind === "number";
}

function wantsSpace(previous: LuauToken | undefined, current: LuauToken): boolean {
  if (!previous) return false;
  if (isWordLike(previous) && isWordLike(current)) return true;
  if (SPACE_BEFORE_WORD.has(current.raw)) return true;
  if (SPACE_AFTER_WORD.has(previous.raw) && !new Set([";", ",", ")", "]", "}"]).has(current.raw)) {
    return true;
  }
  if (BINARY_OPERATORS.has(previous.raw) || BINARY_OPERATORS.has(current.raw)) return true;
  if (previous.raw === ",") return true;
  return false;
}

/**
 * Formats minified Luau without parsing or executing it. The result is accepted
 * only when a second lexical pass proves that the complete token stream is
 * identical to the input.
 */
export function formatLuauStatically(source: string): StaticFormatResult {
  const tokens = lexLuauStatically(source);
  const lines: string[] = [];
  let current = "";
  let indent = 0;
  let previous: LuauToken | undefined;
  let parenthesisDepth = 0;
  let pendingFunction = false;
  let functionParameterDepth: number | null = null;

  const flush = (): void => {
    const trimmed = current.trimEnd();
    if (trimmed.length > 0) lines.push(`${"    ".repeat(indent)}${trimmed.trimStart()}`);
    current = "";
    previous = undefined;
  };
  const write = (token: LuauToken): void => {
    if (wantsSpace(previous, token) && current.length > 0 && !current.endsWith(" ")) current += " ";
    current += token.raw;
    previous = token;
  };

  for (let index = 0; index < tokens.length; index += 1) {
    const token = tokens[index]!;
    const next = tokens[index + 1];

    if (token.kind === "comment") {
      if (current.length > 0 && !current.endsWith(" ")) current += " ";
      current += token.raw;
      flush();
      continue;
    }

    if (token.raw === "end" || token.raw === "until" || token.raw === "else" || token.raw === "elseif") {
      flush();
      indent = Math.max(0, indent - 1);
      write(token);
      if (token.raw === "else") {
        flush();
        indent += 1;
      } else if (token.raw === "end" && !next) {
        flush();
      } else if (token.raw === "end" && next && !new Set([";", ",", ")", "]", "}", ".", ":"]).has(next.raw)) {
        flush();
      }
      continue;
    }

    if (token.raw === "function") {
      write(token);
      pendingFunction = true;
      continue;
    }

    if (token.raw === "(") {
      if (pendingFunction) {
        functionParameterDepth = parenthesisDepth + 1;
        pendingFunction = false;
      }
      parenthesisDepth += 1;
      write(token);
      continue;
    }

    if (token.raw === ")") {
      write(token);
      if (functionParameterDepth === parenthesisDepth) {
        functionParameterDepth = null;
        flush();
        indent += 1;
      }
      parenthesisDepth = Math.max(0, parenthesisDepth - 1);
      continue;
    }

    write(token);

    if (token.raw === ";") {
      flush();
    } else if (token.raw === "then" || token.raw === "do") {
      flush();
      indent += 1;
    } else if (token.raw === "repeat") {
      flush();
      indent += 1;
    }
  }
  flush();

  const formatted = `${lines.join("\n")}\n`;
  const verified = equivalentTokens(tokens, lexLuauStatically(formatted));
  if (!verified) {
    throw new Error("Static Luau formatting failed token-preservation validation.");
  }
  return {
    source: formatted,
    lineCount: lines.length,
    tokenCount: tokens.length,
    functionCount: tokens.filter((token) => token.raw === "function").length,
    verifiedTokenPreservation: verified,
  };
}
