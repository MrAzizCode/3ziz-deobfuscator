/**
 * Variant-tolerant discovery and decoding of Luraph `LPH`-marked payload
 * streams.
 *
 * Different Luraph builds embed the same Ascii85 transform behind different
 * surface syntax.  Two authorized samples exercise both ends of the range:
 *
 * - a 14.7 build stores a `LPH@V` / `LPH!` pair inside Lua long-bracket
 *   strings, packs each 32-bit group little-endian, and compresses the result
 *   with raw LZMA;
 * - another build stores a single `LPH/` stream inside a quoted string with
 *   decimal escapes, packs big-endian, and stores records uncompressed.
 *
 * Nothing here executes submitted code.  The scanner is a lexical reader and
 * the decoders are pure byte transforms.
 */

/** Byte order used when a decoded 32-bit Ascii85 group is written out. */
export type LuraphWordOrder = "little" | "big";

/** How the encoded stream was written in the submitted source. */
export type LuraphLiteralKind = "long-bracket" | "quoted";

export interface LuraphEncodedStream {
  /** Zero-based index of the literal's opening delimiter. */
  readonly literalStart: number;
  /** Zero-based index just past the literal's closing delimiter. */
  readonly literalEnd: number;
  readonly literalKind: LuraphLiteralKind;
  /** Leading marker bytes, retained as detection evidence. */
  readonly marker: string;
  /** Literal contents with Lua escape sequences resolved. */
  readonly text: string;
  /**
   * Lua `string.sub` start index passed at the call site when the wrapper
   * spells it out (`u("LPH/...", 5)`), else null.  One-based, like Lua.
   */
  readonly declaredSubIndex: number | null;
}

export interface LuraphAscii85Options {
  /** Characters dropped from the front before grouping. */
  readonly headerSkip: number;
  readonly wordOrder: LuraphWordOrder;
}

export interface LuraphAscii85Candidate extends LuraphAscii85Options {
  readonly bytes: Uint8Array;
}

const MARKER = "LPH";
const MARKER_EVIDENCE_LENGTH = 6;

/**
 * Every candidate is congruent to 4 modulo 5, so group alignment alone cannot
 * separate them.  Callers disambiguate by validating the decoded bytes.
 */
const HEADER_SKIP_CANDIDATES = [4, 14, 9, 19] as const;
const WORD_ORDER_CANDIDATES: readonly LuraphWordOrder[] = ["little", "big"];

const SIMPLE_ESCAPES: Readonly<Record<string, number>> = {
  a: 7,
  b: 8,
  f: 12,
  n: 10,
  r: 13,
  t: 9,
  v: 11,
  "\\": 92,
  '"': 34,
  "'": 39,
  "\n": 10,
};

function isDecimalDigit(character: string | undefined): boolean {
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

/**
 * Resolve Lua 5.1 and Luau escape sequences into their byte values.  The
 * result is a latin-1 string: one code unit per byte, matching how the
 * surrounding pipeline carries raw payload bytes.
 */
export function unescapeLuaString(raw: string): string {
  if (!raw.includes("\\")) return raw;
  const out: string[] = [];
  let cursor = 0;
  while (cursor < raw.length) {
    const character = raw[cursor]!;
    if (character !== "\\") {
      out.push(character);
      cursor += 1;
      continue;
    }
    const next = raw[cursor + 1];
    if (next === undefined) {
      throw new Error("Lua string literal ends with a dangling backslash.");
    }
    if (isDecimalDigit(next)) {
      let digits = "";
      let scan = cursor + 1;
      while (digits.length < 3 && isDecimalDigit(raw[scan])) {
        digits += raw[scan];
        scan += 1;
      }
      const value = Number.parseInt(digits, 10);
      if (value > 255) {
        throw new Error(`Decimal escape \\${digits} is outside the byte range.`);
      }
      out.push(String.fromCharCode(value));
      cursor = scan;
      continue;
    }
    if (next === "x" && isHexDigit(raw[cursor + 2]) && isHexDigit(raw[cursor + 3])) {
      out.push(String.fromCharCode(Number.parseInt(raw.slice(cursor + 2, cursor + 4), 16)));
      cursor += 4;
      continue;
    }
    if (next === "z") {
      cursor += 2;
      while (cursor < raw.length && /\s/.test(raw[cursor]!)) cursor += 1;
      continue;
    }
    if (next === "u" && raw[cursor + 2] === "{") {
      const close = raw.indexOf("}", cursor + 3);
      if (close < 0) throw new Error("Unterminated \\u{...} escape.");
      const codePoint = Number.parseInt(raw.slice(cursor + 3, close), 16);
      if (!Number.isInteger(codePoint) || codePoint < 0 || codePoint > 0x10ffff) {
        throw new Error("Invalid \\u{...} escape.");
      }
      for (const byte of Buffer.from(String.fromCodePoint(codePoint), "utf8")) {
        out.push(String.fromCharCode(byte));
      }
      cursor = close + 1;
      continue;
    }
    const simple = SIMPLE_ESCAPES[next];
    if (simple !== undefined) {
      out.push(String.fromCharCode(simple));
      cursor += 2;
      continue;
    }
    // Lua 5.1 emits an unrecognized escape as the escaped character itself.
    // Wrappers rely on that, so follow it rather than rejecting the literal.
    out.push(next);
    cursor += 2;
  }
  return out.join("");
}

/** Read `[[...]]` / `[==[...]==]` starting at the opening bracket. */
function readLongBracket(
  source: string,
  start: number,
): { text: string; end: number } | null {
  if (source[start] !== "[") return null;
  let cursor = start + 1;
  while (source[cursor] === "=") cursor += 1;
  if (source[cursor] !== "[") return null;
  const level = source.slice(start + 1, cursor);
  const contentStart = cursor + 1;
  const close = `]${level}]`;
  const contentEnd = source.indexOf(close, contentStart);
  if (contentEnd < 0) return null;
  return {
    text: source.slice(contentStart, contentEnd),
    end: contentEnd + close.length,
  };
}

/** Read `"..."` / `'...'` starting at the opening quote, honoring escapes. */
function readQuoted(
  source: string,
  start: number,
): { text: string; end: number } | null {
  const quote = source[start];
  if (quote !== '"' && quote !== "'") return null;
  let cursor = start + 1;
  while (cursor < source.length) {
    const character = source[cursor]!;
    if (character === "\\") {
      cursor += 2;
      continue;
    }
    if (character === quote) {
      return { text: source.slice(start + 1, cursor), end: cursor + 1 };
    }
    if (character === "\n") return null;
    cursor += 1;
  }
  return null;
}

/**
 * Read a trailing `, <integer>)` argument after a literal, which some wrappers
 * use to spell out the `string.sub` start index instead of computing it.
 */
function readDeclaredSubIndex(source: string, from: number): number | null {
  let cursor = from;
  while (/\s/.test(source[cursor] ?? "")) cursor += 1;
  if (source[cursor] !== ",") return null;
  cursor += 1;
  while (/\s/.test(source[cursor] ?? "")) cursor += 1;
  let digits = "";
  while (isDecimalDigit(source[cursor])) {
    digits += source[cursor];
    cursor += 1;
  }
  if (digits.length === 0 || digits.length > 4) return null;
  while (/\s/.test(source[cursor] ?? "")) cursor += 1;
  if (source[cursor] !== ")") return null;
  return Number.parseInt(digits, 10);
}

/**
 * Find every `LPH`-marked encoded stream in submitted source, regardless of
 * which Lua literal form the wrapper used.  Streams are returned in source
 * order.
 */
export function scanLuraphEncodedStreams(
  source: string,
): readonly LuraphEncodedStream[] {
  const streams: LuraphEncodedStream[] = [];
  let searchFrom = 0;
  for (;;) {
    const marker = source.indexOf(MARKER, searchFrom);
    if (marker < 0) break;
    searchFrom = marker + MARKER.length;

    const previous = source[marker - 1];
    let literalStart = -1;
    let kind: LuraphLiteralKind | null = null;
    if (previous === '"' || previous === "'") {
      literalStart = marker - 1;
      kind = "quoted";
    } else if (previous === "[") {
      // Walk back over the optional `=` level markers to the opening bracket.
      let scan = marker - 2;
      while (source[scan] === "=") scan -= 1;
      if (source[scan] === "[") {
        literalStart = scan;
        kind = "long-bracket";
      }
    }
    if (kind === null || literalStart < 0) continue;

    const read =
      kind === "long-bracket"
        ? readLongBracket(source, literalStart)
        : readQuoted(source, literalStart);
    if (read === null) continue;

    let text: string;
    try {
      text = kind === "quoted" ? unescapeLuaString(read.text) : read.text;
    } catch {
      // A literal we cannot decode lexically is not usable evidence.
      continue;
    }
    if (!text.startsWith(MARKER)) continue;

    streams.push({
      literalStart,
      literalEnd: read.end,
      literalKind: kind,
      marker: text.slice(0, MARKER_EVIDENCE_LENGTH),
      text,
      declaredSubIndex: readDeclaredSubIndex(source, read.end),
    });
    searchFrom = read.end;
  }
  return streams;
}

/**
 * Decode one Luraph Ascii85 stream.  `z` expands to a zero group exactly as
 * the wrapper's `gsub(s, "z", "!!!!!")` does.
 */
export function decodeLuraphAscii85(
  encoded: string,
  options: LuraphAscii85Options = { headerSkip: 0, wordOrder: "little" },
): Uint8Array {
  const { headerSkip, wordOrder } = options;
  if (!Number.isInteger(headerSkip) || headerSkip < 0) {
    throw new Error("The Ascii85 header skip must be a non-negative integer.");
  }
  if (headerSkip > encoded.length) {
    throw new Error("The Ascii85 header skip exceeds the stream length.");
  }
  const body = encoded.slice(headerSkip);
  // Each `z` shorthand contributes a whole group on its own, so the group
  // count is not simply the character count divided by five.
  let zeroShorthandCount = 0;
  for (let index = 0; index < body.length; index += 1) {
    if (body.charCodeAt(index) === 122) zeroShorthandCount += 1;
  }
  const maxGroups =
    Math.ceil((body.length - zeroShorthandCount) / 5) + zeroShorthandCount;
  const output = new Uint8Array(maxGroups * 4);
  let outputOffset = 0;
  let group = "";

  const writeGroup = (value: string): void => {
    if (value.length !== 5) throw new Error("Invalid Ascii85 group length.");
    let packed = 0;
    for (let index = 0; index < 5; index += 1) {
      const code = value.charCodeAt(index);
      if (code < 33 || code > 117) {
        throw new Error(`Invalid Ascii85 character at group offset ${index}.`);
      }
      packed = packed * 85 + (code - 33);
    }
    if (packed > 0xffff_ffff) {
      throw new Error("Ascii85 group exceeds the 32-bit range.");
    }
    const b0 = packed & 0xff;
    const b1 = Math.floor(packed / 0x100) & 0xff;
    const b2 = Math.floor(packed / 0x1_0000) & 0xff;
    const b3 = Math.floor(packed / 0x100_0000) & 0xff;
    if (wordOrder === "little") {
      output[outputOffset] = b0;
      output[outputOffset + 1] = b1;
      output[outputOffset + 2] = b2;
      output[outputOffset + 3] = b3;
    } else {
      output[outputOffset] = b3;
      output[outputOffset + 1] = b2;
      output[outputOffset + 2] = b1;
      output[outputOffset + 3] = b0;
    }
    outputOffset += 4;
  };

  for (const character of body) {
    if (character === "z") {
      if (group.length !== 0) {
        throw new Error("Ascii85 zero shorthand appeared inside a group.");
      }
      writeGroup("!!!!!");
      continue;
    }
    group += character;
    if (group.length === 5) {
      writeGroup(group);
      group = "";
    }
  }
  if (group.length !== 0) {
    throw new Error("Ascii85 stream ended with an incomplete group.");
  }
  return output.slice(0, outputOffset);
}

/**
 * Produce every structurally valid decoding of one stream, most likely first.
 *
 * Header skips are all congruent modulo the 5-character group, and both word
 * orders accept the same groups, so this function cannot pick a winner on its
 * own.  Callers validate candidates against the decompressor or the record
 * reader and keep the first that survives.
 */
export function* luraphAscii85Candidates(
  stream: LuraphEncodedStream,
): Generator<LuraphAscii85Candidate, void, undefined> {
  const declared =
    stream.declaredSubIndex === null ? null : stream.declaredSubIndex - 1;
  const skips =
    declared !== null && declared >= 0
      ? [declared, ...HEADER_SKIP_CANDIDATES.filter((value) => value !== declared)]
      : [...HEADER_SKIP_CANDIDATES];
  for (const headerSkip of skips) {
    for (const wordOrder of WORD_ORDER_CANDIDATES) {
      let bytes: Uint8Array;
      try {
        bytes = decodeLuraphAscii85(stream.text, { headerSkip, wordOrder });
      } catch {
        continue;
      }
      yield { headerSkip, wordOrder, bytes };
    }
  }
}

/**
 * Distinguish a raw-LZMA stream from an uncompressed record stream.
 *
 * The LZMA range coder specifies that the first byte of the compressed stream
 * is ignored and written as zero, so a non-zero first byte rules compression
 * out without attempting a decode.
 */
export function looksLikeRawLzma(bytes: Uint8Array): boolean {
  return bytes.byteLength > 0 && bytes[0] === 0;
}
