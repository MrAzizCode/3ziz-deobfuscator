import { extname } from "node:path";

import type { SourceClassification } from "../shared/contracts";
import { countMatches, scanLuaLexically } from "./source/lexical";

const LUA_SIGNATURE = [0x1b, 0x4c, 0x75, 0x61] as const;

function hasLuaSignature(bytes: Uint8Array): boolean {
  return LUA_SIGNATURE.every((value, index) => bytes[index] === value);
}

function decodeUtf8(bytes: Uint8Array): string | null {
  try {
    return new TextDecoder("utf-8", { fatal: true }).decode(bytes);
  } catch {
    return null;
  }
}

function isProbablyBinary(text: string): boolean {
  if (text.includes("\0")) return true;
  if (text.length === 0) return false;

  let controls = 0;
  for (const character of text) {
    const code = character.codePointAt(0) ?? 0;
    if (code < 32 && character !== "\n" && character !== "\r" && character !== "\t") {
      controls += 1;
    }
  }
  return controls / text.length > 0.01;
}

function auditSignals(text: string): readonly string[] {
  const signals: string[] = [];
  if (/LURAPH PAYLOAD[\s\S]{0,80}DEVIRTUALIZED REGISTER-LEVEL/i.test(text)) {
    signals.push("Luraph devirtualized-register header");
  }
  if (/--\s*stack slots:\s*\d+;\s*decoded instructions:/i.test(text)) {
    signals.push("decoded-instruction metadata");
  }
  if (countMatches(text, /::L\d+::/g) >= 8) signals.push("dense VM labels");
  if (countMatches(text, /\bgoto\s+L\d+\b/g) >= 4) signals.push("VM goto graph");
  if (countMatches(text, /\bVM_FRAGMENT\b/g) >= 1) signals.push("unresolved VM fragments");
  if (/--\s*source path:\s*root(?:\.M\[\d+\])*/i.test(text)) {
    signals.push("recovered prototype paths");
  }
  return signals;
}

function luauSignals(code: string): readonly string[] {
  const signals: string[] = [];
  if (/\bcontinue\b/.test(code)) signals.push("continue statement");
  if (/(?:\+=|-=|\*=|\/=|\/\/=|\.\.=)/.test(code)) {
    signals.push("compound assignment");
  }
  if (/\bexport\s+type\b|\btype\s+[A-Za-z_]\w*\s*=/.test(code)) {
    signals.push("type declaration");
  }
  if (/(?:local\s+[A-Za-z_]\w*|function\s*\([^)]*)\s*:\s*[A-Za-z_{(]/.test(code)) {
    signals.push("type annotation");
  }
  if (/`(?:\\.|[^`])*`/.test(code)) signals.push("interpolated string");
  if (/=\s*if\b[^\n;]+\bthen\b[^\n;]+\belse\b/.test(code)) {
    signals.push("if-expression");
  }
  return signals;
}

export interface ClassifiedInput {
  readonly classification: SourceClassification;
  readonly text?: string;
}

export function classifyInput(bytes: Uint8Array, fileName: string): ClassifiedInput {
  if (hasLuaSignature(bytes)) {
    return {
      classification: {
        kind: "lua-bytecode",
        dialect: "lua-5.1",
        confidence: 1,
        isText: false,
        reasons: ["Lua binary chunk signature"],
      },
    };
  }

  const text = decodeUtf8(bytes);
  if (text === null) {
    return {
      classification: {
        kind: "binary",
        dialect: "unknown",
        confidence: 0.98,
        isText: false,
        reasons: ["input is not valid UTF-8 and has no Lua chunk signature"],
      },
    };
  }

  if (isProbablyBinary(text)) {
    return {
      text,
      classification: {
        kind: "binary",
        dialect: "unknown",
        confidence: 0.9,
        isText: false,
        reasons: ["text contains a high density of binary control bytes"],
      },
    };
  }

  const vmSignals = auditSignals(text);
  if (vmSignals.length >= 3) {
    return {
      text,
      classification: {
        kind: "vm-audit-ir",
        dialect: "vm-ir",
        confidence: Math.min(1, 0.65 + vmSignals.length * 0.06),
        isText: true,
        reasons: vmSignals,
      },
    };
  }

  const lexical = scanLuaLexically(text);
  const extension = extname(fileName).toLowerCase();
  const extensions = luauSignals(lexical.code);
  const luaTokenCount = countMatches(
    lexical.code,
    /\b(?:local|function|return|if|then|end|for|while|repeat)\b/g,
  );

  if (extensions.length > 0 || extension === ".luau") {
    return {
      text,
      classification: {
        kind: "luau-source",
        dialect: "luau",
        confidence: extensions.length > 0 ? 0.88 : 0.62,
        isText: true,
        reasons:
          extensions.length > 0
            ? extensions
            : ["Luau filename extension without a detected extension token"],
      },
    };
  }

  if (extension === ".lua" || luaTokenCount >= 2) {
    return {
      text,
      classification: {
        kind: "lua-source",
        dialect: "lua-5.1",
        confidence: extension === ".lua" && luaTokenCount >= 2 ? 0.92 : 0.7,
        isText: true,
        reasons: [
          ...(extension === ".lua" ? ["Lua filename extension"] : []),
          ...(luaTokenCount >= 2 ? ["Lua statement tokens"] : []),
        ],
      },
    };
  }

  return {
    text,
    classification: {
      kind: "text",
      dialect: "unknown",
      confidence: 0.7,
      isText: true,
      reasons: ["valid UTF-8 without sufficient Lua syntax evidence"],
    },
  };
}

export { auditSignals, luauSignals };
