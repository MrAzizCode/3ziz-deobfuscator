import * as luaparse from "luaparse";

import type {
  Diagnostic,
  LuaParseFacts,
  SourceClassification,
  SourceEdit,
  SourcePassRecord,
} from "../../shared/contracts";
import { parseLuaFacts } from "../source/parse-facts";
import { scanLuaLexically } from "../source/lexical";
import { runProofGatedCleanup, type CleanupResult } from "./proof-gated-cleanup";

interface AstNode {
  readonly type?: unknown;
  readonly operator?: unknown;
  readonly left?: unknown;
  readonly right?: unknown;
  readonly raw?: unknown;
  readonly range?: unknown;
  readonly [key: string]: unknown;
}

interface FoldCandidate {
  readonly start: number;
  readonly end: number;
  readonly bytes: Uint8Array;
}

const AST_METADATA_KEYS = new Set([
  "loc",
  "range",
  "raw",
  "comments",
  "globals",
  "isLocal",
]);
const MAX_FOLDED_LITERAL_BYTES = 64 * 1_024;
const MAX_TOTAL_REPLACEMENT_BYTES = 1 * 1_024 * 1_024;
const MAX_LITERAL_FOLD_EDITS = 10_000;

function isNode(value: unknown): value is AstNode {
  return value !== null && typeof value === "object";
}

function rangeOf(node: AstNode): readonly [number, number] | null {
  if (
    Array.isArray(node.range) &&
    node.range.length === 2 &&
    typeof node.range[0] === "number" &&
    typeof node.range[1] === "number"
  ) {
    return [node.range[0], node.range[1]];
  }
  return null;
}

function appendUtf8(bytes: number[], text: string): void {
  bytes.push(...Buffer.from(text, "utf8"));
}

/**
 * Decodes only Lua 5.1 short-string forms whose byte value is unambiguous.
 * Long strings and line-continuation escapes are intentionally skipped.
 */
function decodeShortString(raw: string): Uint8Array | null {
  const quote = raw[0];
  if ((quote !== '"' && quote !== "'") || raw.at(-1) !== quote) return null;

  const bytes: number[] = [];
  for (let index = 1; index < raw.length - 1; index += 1) {
    const character = raw[index];
    if (character !== "\\") {
      const codePoint = raw.codePointAt(index);
      if (codePoint === undefined) return null;
      const text = String.fromCodePoint(codePoint);
      appendUtf8(bytes, text);
      index += text.length - 1;
      continue;
    }

    const escaped = raw[index + 1];
    if (escaped === undefined || escaped === "\n" || escaped === "\r") return null;
    const named: Readonly<Record<string, number>> = {
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
    };
    if (named[escaped] !== undefined) {
      bytes.push(named[escaped]);
      index += 1;
      continue;
    }

    if (/[0-9]/.test(escaped)) {
      let digits = escaped;
      while (
        digits.length < 3 &&
        /[0-9]/.test(raw[index + 1 + digits.length] ?? "")
      ) {
        digits += raw[index + 1 + digits.length];
      }
      const value = Number(digits);
      if (!Number.isInteger(value) || value > 255) return null;
      bytes.push(value);
      index += digits.length;
      continue;
    }

    return null;
  }
  return Uint8Array.from(bytes);
}

function literalBytes(node: AstNode, source: string): Uint8Array | null {
  if (node.type !== "StringLiteral") return null;
  const range = rangeOf(node);
  if (!range) return null;
  const raw =
    typeof node.raw === "string" ? node.raw : source.slice(range[0], range[1]);
  return decodeShortString(raw);
}

function concatenatedBytes(node: AstNode, source: string): Uint8Array | null {
  const literal = literalBytes(node, source);
  if (literal) return literal;
  if (node.type !== "BinaryExpression" || node.operator !== "..") return null;
  if (!isNode(node.left) || !isNode(node.right)) return null;

  const left = concatenatedBytes(node.left, source);
  const right = concatenatedBytes(node.right, source);
  if (!left || !right || left.length + right.length > MAX_FOLDED_LITERAL_BYTES) {
    return null;
  }
  const joined = new Uint8Array(left.length + right.length);
  joined.set(left, 0);
  joined.set(right, left.length);
  return joined;
}

function collectCandidates(
  node: unknown,
  source: string,
  candidates: FoldCandidate[],
  parentFoldable: boolean,
  seen: Set<object>,
): void {
  if (!isNode(node) || seen.has(node)) return;
  seen.add(node);

  const bytes = concatenatedBytes(node, source);
  const range = rangeOf(node);
  const foldable =
    bytes !== null &&
    range !== null &&
    node.type === "BinaryExpression" &&
    node.operator === "..";
  if (foldable && !parentFoldable && bytes && range) {
    const region = source.slice(range[0], range[1]);
    if (scanLuaLexically(region).comments.length === 0) {
      candidates.push({ start: range[0], end: range[1], bytes });
      return;
    }
  }

  for (const [key, child] of Object.entries(node)) {
    if (AST_METADATA_KEYS.has(key) || key === "type" || key === "operator") continue;
    if (Array.isArray(child)) {
      for (const item of child) {
        collectCandidates(item, source, candidates, foldable, seen);
      }
    } else {
      collectCandidates(child, source, candidates, foldable, seen);
    }
  }
}

function escapedByteLiteral(bytes: Uint8Array): string {
  if (bytes.length === 0) return '""';
  let literal = '"';
  for (const byte of bytes) {
    if (byte === 34) {
      literal += '\\"';
    } else if (byte === 92) {
      literal += "\\\\";
    } else if (byte >= 32 && byte <= 126) {
      literal += String.fromCharCode(byte);
    } else {
      // Three digits make the boundary unambiguous when the next byte is a
      // printable decimal digit.
      literal += `\\${byte.toString(10).padStart(3, "0")}`;
    }
  }
  return `${literal}"`;
}

function invariantMismatch(
  before: LuaParseFacts,
  after: LuaParseFacts,
): readonly string[] {
  const mismatches: string[] = [];
  if (!after.parsed) mismatches.push("rewritten output did not parse as Lua 5.1");
  for (const key of [
    "functionCount",
    "callCount",
    "varargCount",
    "registerIdentifierOccurrences",
    "uniqueRegisterIdentifiers",
  ] as const) {
    if (before[key] !== after[key]) {
      mismatches.push(`${key}: ${before[key]} -> ${after[key]}`);
    }
  }
  return mismatches;
}

function foldLiteralConcatenations(
  source: string,
  classification: SourceClassification,
  facts: LuaParseFacts,
): {
  readonly source: string;
  readonly facts: LuaParseFacts;
  readonly pass: SourcePassRecord;
  readonly diagnostics: readonly Diagnostic[];
} {
  if (!facts.parsed || facts.mode !== "lua-5.1-ast") {
    const diagnostic: Diagnostic = {
      code: "LITERAL_FOLD_SKIPPED_UNPARSED",
      severity: "info",
      stage: "source-cleanup",
      message:
        "Literal concatenation folding requires a successful Lua 5.1 parse and was skipped.",
    };
    return {
      source,
      facts,
      diagnostics: [diagnostic],
      pass: {
        id: "literal-string-concatenation",
        version: "1.0.0",
        applied: false,
        confidence: 1,
        edits: [],
        factsBefore: facts,
        factsAfter: facts,
        diagnostics: [diagnostic],
      },
    };
  }

  let ast: unknown;
  try {
    ast = luaparse.parse(source, {
      comments: true,
      locations: true,
      ranges: true,
      scope: true,
      luaVersion: "5.1",
      encodingMode: "x-user-defined",
    });
  } catch {
    const diagnostic: Diagnostic = {
      code: "LITERAL_FOLD_SKIPPED_REPARSE",
      severity: "warning",
      stage: "source-cleanup",
      message: "The source could not be reparsed for exact-range literal folding.",
    };
    return {
      source,
      facts,
      diagnostics: [diagnostic],
      pass: {
        id: "literal-string-concatenation",
        version: "1.0.0",
        applied: false,
        confidence: 1,
        edits: [],
        factsBefore: facts,
        factsAfter: facts,
        diagnostics: [diagnostic],
      },
    };
  }

  const candidates: FoldCandidate[] = [];
  collectCandidates(ast, source, candidates, false, new Set());
  if (candidates.length > MAX_LITERAL_FOLD_EDITS) {
    const diagnostic: Diagnostic = {
      code: "LITERAL_FOLD_SKIPPED_EDIT_LIMIT",
      severity: "warning",
      stage: "source-cleanup",
      message:
        `Literal folding found ${candidates.length} edits, exceeding the ` +
        `${MAX_LITERAL_FOLD_EDITS}-edit report limit; the pass was skipped.`,
    };
    return {
      source,
      facts,
      diagnostics: [diagnostic],
      pass: {
        id: "literal-string-concatenation",
        version: "1.0.0",
        applied: false,
        confidence: 1,
        edits: [],
        factsBefore: facts,
        factsAfter: facts,
        diagnostics: [diagnostic],
      },
    };
  }
  const edits: SourceEdit[] = candidates.map((candidate) => ({
    start: candidate.start,
    end: candidate.end,
    replacement: escapedByteLiteral(candidate.bytes),
    reason: "Both operands are statically proven Lua short-string literals.",
  }));
  const replacementSize = edits.reduce(
    (sum, edit) => sum + Buffer.byteLength(edit.replacement, "utf8"),
    0,
  );
  if (replacementSize > MAX_TOTAL_REPLACEMENT_BYTES) {
    const diagnostic: Diagnostic = {
      code: "LITERAL_FOLD_SKIPPED_OUTPUT_LIMIT",
      severity: "warning",
      stage: "source-cleanup",
      message: "Literal folding was skipped because escaped output would exceed its cap.",
    };
    return {
      source,
      facts,
      diagnostics: [diagnostic],
      pass: {
        id: "literal-string-concatenation",
        version: "1.0.0",
        applied: false,
        confidence: 1,
        edits: [],
        factsBefore: facts,
        factsAfter: facts,
        diagnostics: [diagnostic],
      },
    };
  }

  if (edits.length === 0) {
    const diagnostic: Diagnostic = {
      code: "LITERAL_FOLD_NO_CANDIDATES",
      severity: "info",
      stage: "source-cleanup",
      message: "No provable short-string concatenations were found.",
    };
    return {
      source,
      facts,
      diagnostics: [diagnostic],
      pass: {
        id: "literal-string-concatenation",
        version: "1.0.0",
        applied: false,
        confidence: 1,
        edits: [],
        factsBefore: facts,
        factsAfter: facts,
        diagnostics: [diagnostic],
      },
    };
  }

  let rewritten = source;
  for (const edit of [...edits].sort((left, right) => right.start - left.start)) {
    rewritten =
      rewritten.slice(0, edit.start) +
      edit.replacement +
      rewritten.slice(edit.end);
  }
  const after = parseLuaFacts(rewritten, classification);
  const mismatches = invariantMismatch(facts, after);
  if (mismatches.length > 0) {
    const diagnostic: Diagnostic = {
      code: "LITERAL_FOLD_VALIDATION_ROLLBACK",
      severity: "error",
      stage: "source-cleanup",
      message:
        "Literal-fold edits were rolled back because structural validation failed.",
      evidence: mismatches,
    };
    return {
      source,
      facts,
      diagnostics: [diagnostic],
      pass: {
        id: "literal-string-concatenation",
        version: "1.0.0",
        applied: false,
        confidence: 1,
        edits: [],
        factsBefore: facts,
        factsAfter: facts,
        diagnostics: [diagnostic],
      },
    };
  }

  const diagnostic: Diagnostic = {
    code: "LITERAL_FOLD_APPLIED",
    severity: "info",
    stage: "source-cleanup",
    message: `${edits.length} literal-only concatenation edit(s) were applied and reparsed.`,
  };
  return {
    source: rewritten,
    facts: after,
    diagnostics: [diagnostic],
    pass: {
      id: "literal-string-concatenation",
      version: "1.0.0",
      applied: true,
      confidence: 1,
      edits,
      factsBefore: facts,
      factsAfter: after,
      diagnostics: [diagnostic],
    },
  };
}

export function runSourceCleanup(
  source: string,
  classification: SourceClassification,
  facts: LuaParseFacts,
): CleanupResult {
  const literalFold = foldLiteralConcatenations(source, classification, facts);
  const conservative = runProofGatedCleanup(literalFold.source, literalFold.facts);
  return {
    source: conservative.source,
    passes: [literalFold.pass, ...conservative.passes],
    diagnostics: [...literalFold.diagnostics, ...conservative.diagnostics],
  };
}
