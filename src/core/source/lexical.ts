export interface LuaTriviaRegion {
  readonly kind: "comment" | "string";
  readonly start: number;
  readonly end: number;
  readonly raw: string;
}

export interface LuaLexicalView {
  /**
   * Text with comments and literals replaced by spaces. Newline characters and
   * all offsets are preserved, so evidence can be mapped back to the input.
   */
  readonly code: string;
  readonly comments: readonly LuaTriviaRegion[];
  readonly strings: readonly LuaTriviaRegion[];
}

interface LongBracket {
  readonly equalsCount: number;
  readonly contentStart: number;
}

function readLongBracket(source: string, start: number): LongBracket | null {
  if (source[start] !== "[") return null;

  let cursor = start + 1;
  while (source[cursor] === "=") cursor += 1;
  if (source[cursor] !== "[") return null;

  return {
    equalsCount: cursor - start - 1,
    contentStart: cursor + 1,
  };
}

function findLongBracketEnd(
  source: string,
  contentStart: number,
  equalsCount: number,
): number {
  const closing = `]${"=".repeat(equalsCount)}]`;
  const closingStart = source.indexOf(closing, contentStart);
  return closingStart === -1 ? source.length : closingStart + closing.length;
}

function maskRegion(mask: string[], source: string, start: number, end: number): void {
  for (let index = start; index < end; index += 1) {
    const character = source[index];
    if (character !== "\n" && character !== "\r") mask[index] = " ";
  }
}

export function scanLuaLexically(source: string): LuaLexicalView {
  const mask = source.split("");
  const comments: LuaTriviaRegion[] = [];
  const strings: LuaTriviaRegion[] = [];

  let cursor = 0;
  while (cursor < source.length) {
    if (source.startsWith("--", cursor)) {
      const longComment = readLongBracket(source, cursor + 2);
      let end: number;
      if (longComment) {
        end = findLongBracketEnd(
          source,
          longComment.contentStart,
          longComment.equalsCount,
        );
      } else {
        const newline = source.indexOf("\n", cursor + 2);
        end = newline === -1 ? source.length : newline;
      }

      comments.push({
        kind: "comment",
        start: cursor,
        end,
        raw: source.slice(cursor, end),
      });
      maskRegion(mask, source, cursor, end);
      cursor = end;
      continue;
    }

    const quote = source[cursor];
    if (quote === '"' || quote === "'") {
      const start = cursor;
      cursor += 1;
      while (cursor < source.length) {
        if (source[cursor] === "\\") {
          cursor = Math.min(source.length, cursor + 2);
          continue;
        }
        if (source[cursor] === quote) {
          cursor += 1;
          break;
        }
        cursor += 1;
      }

      strings.push({
        kind: "string",
        start,
        end: cursor,
        raw: source.slice(start, cursor),
      });
      maskRegion(mask, source, start, cursor);
      continue;
    }

    if (quote === "[") {
      const longString = readLongBracket(source, cursor);
      if (longString) {
        const start = cursor;
        cursor = findLongBracketEnd(
          source,
          longString.contentStart,
          longString.equalsCount,
        );
        strings.push({
          kind: "string",
          start,
          end: cursor,
          raw: source.slice(start, cursor),
        });
        maskRegion(mask, source, start, cursor);
        continue;
      }
    }

    cursor += 1;
  }

  return {
    code: mask.join(""),
    comments,
    strings,
  };
}

export function physicalLineCount(source: string): number {
  if (source.length === 0) return 0;
  return (source.match(/\n/g)?.length ?? 0) + 1;
}

export function lineNumberAt(source: string, offset: number): number {
  let line = 1;
  const end = Math.min(Math.max(offset, 0), source.length);
  for (let index = 0; index < end; index += 1) {
    if (source.charCodeAt(index) === 10) line += 1;
  }
  return line;
}

export function countMatches(text: string, expression: RegExp): number {
  const flags = expression.flags.includes("g")
    ? expression.flags
    : `${expression.flags}g`;
  return [...text.matchAll(new RegExp(expression.source, flags))].length;
}
