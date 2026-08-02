import * as luaparse from "luaparse";

import type {
  LuaParseFacts,
  ParseMode,
  SourceClassification,
  StructuralFacts,
} from "../../shared/contracts";
import { sha256Text, utf8ByteLength } from "../hash";
import { auditSignals, luauSignals } from "../classification";
import { countMatches, physicalLineCount, scanLuaLexically } from "./lexical";
import { parseLuau } from "./luau-parser";

interface AstNodeLike {
  readonly type?: unknown;
  readonly name?: unknown;
  readonly [key: string]: unknown;
}

interface MutableAstCounts {
  nodes: number;
  functions: number;
  calls: number;
  varargs: number;
  registerOccurrences: number;
  readonly registerNames: Set<string>;
}

const REGISTER_IDENTIFIER = /^(?:L\d+_\d+|A\d+_\d+)$/;
const NON_CHILD_KEYS = new Set([
  "loc",
  "range",
  "raw",
  "comments",
  "globals",
  "isLocal",
]);

function isObject(value: unknown): value is AstNodeLike {
  return value !== null && typeof value === "object";
}

function visitAst(
  value: unknown,
  counts: MutableAstCounts,
  maxAstNodes: number,
  seen: Set<object>,
): void {
  if (!isObject(value) || seen.has(value)) return;
  seen.add(value);

  if (typeof value.type === "string") {
    counts.nodes += 1;
    if (counts.nodes > maxAstNodes) {
      throw new Error(`AST node limit exceeded (${maxAstNodes})`);
    }

    if (value.type === "FunctionDeclaration") counts.functions += 1;
    if (
      value.type === "CallExpression" ||
      value.type === "TableCallExpression" ||
      value.type === "StringCallExpression"
    ) {
      counts.calls += 1;
    }
    if (value.type === "VarargLiteral") counts.varargs += 1;
    if (
      value.type === "Identifier" &&
      typeof value.name === "string" &&
      REGISTER_IDENTIFIER.test(value.name)
    ) {
      counts.registerOccurrences += 1;
      counts.registerNames.add(value.name);
    }
  }

  for (const [key, child] of Object.entries(value)) {
    if (NON_CHILD_KEYS.has(key) || key === "type" || key === "name") continue;
    if (Array.isArray(child)) {
      for (const item of child) visitAst(item, counts, maxAstNodes, seen);
    } else {
      visitAst(child, counts, maxAstNodes, seen);
    }
  }
}

function staticFacts(source: string): Omit<StructuralFacts, "sha256" | "byteLength" | "lineCount"> {
  const code = scanLuaLexically(source).code;
  const registerMatches =
    code.match(/\b(?:L\d+_\d+|A\d+_\d+)\b/g) ?? [];
  const registerNames = new Set(registerMatches);

  return {
    astNodeCount: 0,
    functionCount: countMatches(code, /\bfunction\b/g),
    callCount: countMatches(
      code,
      /\b[A-Za-z_]\w*(?:\s*[.:]\s*[A-Za-z_]\w*)*\s*\(/g,
    ),
    varargCount: countMatches(code, /\.\.\./g),
    registerIdentifierOccurrences: registerMatches.length,
    uniqueRegisterIdentifiers: registerNames.size,
  };
}

function syntaxErrorMessage(error: unknown): string {
  if (error instanceof Error) {
    return error.message.replace(/\s+/g, " ").slice(0, 500);
  }
  return "Lua parser rejected the input";
}

export function parseLuaFacts(
  source: string,
  classification: SourceClassification,
  maxAstNodes = 500_000,
): LuaParseFacts {
  const common = {
    sha256: sha256Text(source),
    byteLength: utf8ByteLength(source),
    lineCount: physicalLineCount(source),
  } as const;

  const vmMarkers = auditSignals(source);
  const lexical = scanLuaLexically(source);
  const detectedLuauMarkers = luauSignals(lexical.code);

  if (classification.kind === "vm-audit-ir" || vmMarkers.length >= 3) {
    return {
      ...common,
      ...staticFacts(source),
      mode: "vm-ir",
      parsed: false,
      luauMarkers: detectedLuauMarkers,
      vmIrMarkers: vmMarkers,
    };
  }

  try {
    const ast = luaparse.parse(source, {
      comments: true,
      locations: true,
      ranges: true,
      scope: true,
      luaVersion: "5.1",
      encodingMode: "x-user-defined",
    });
    const counts: MutableAstCounts = {
      nodes: 0,
      functions: 0,
      calls: 0,
      varargs: 0,
      registerOccurrences: 0,
      registerNames: new Set(),
    };
    visitAst(ast, counts, maxAstNodes, new Set());

    return {
      ...common,
      mode: "lua-5.1-ast",
      parsed: true,
      astNodeCount: counts.nodes,
      functionCount: counts.functions,
      callCount: counts.calls,
      varargCount: counts.varargs,
      registerIdentifierOccurrences: counts.registerOccurrences,
      uniqueRegisterIdentifiers: counts.registerNames.size,
      luauMarkers: detectedLuauMarkers,
      vmIrMarkers: vmMarkers,
    };
  } catch (error) {
    const luaSyntaxError = syntaxErrorMessage(error);

    /*
     * Lua 5.1 rejects every modern Luau construct, so a failure here is not
     * evidence that the source is unreadable.  The in-tree Luau front end is
     * tried next; only when both reject the input do we fall back to lexical
     * facts alone.
     */
    try {
      const ast = parseLuau(source, { maxNodes: maxAstNodes });
      const counts: MutableAstCounts = {
        nodes: 0,
        functions: 0,
        calls: 0,
        varargs: 0,
        registerOccurrences: 0,
        registerNames: new Set(),
      };
      visitAst(ast, counts, maxAstNodes, new Set());

      return {
        ...common,
        mode: "luau-ast",
        parsed: true,
        astNodeCount: counts.nodes,
        functionCount: counts.functions,
        callCount: counts.calls,
        varargCount: counts.varargs,
        registerIdentifierOccurrences: counts.registerOccurrences,
        uniqueRegisterIdentifiers: counts.registerNames.size,
        luauMarkers: detectedLuauMarkers,
        vmIrMarkers: vmMarkers,
      };
    } catch (luauError) {
      const mode: ParseMode =
        classification.kind === "luau-source" || detectedLuauMarkers.length > 0
          ? "luau-static-fallback"
          : "unparsed";
      return {
        ...common,
        ...staticFacts(source),
        mode,
        parsed: false,
        // Report the Luau failure: it is the more capable of the two readers.
        syntaxError: `${syntaxErrorMessage(luauError)} (Lua 5.1: ${luaSyntaxError})`.slice(
          0,
          500,
        ),
        luauMarkers: detectedLuauMarkers,
        vmIrMarkers: vmMarkers,
      };
    }
  }
}
