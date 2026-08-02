import type {
  BehaviorInventory,
  CapabilityCategory,
  CapabilityFinding,
  UrlFinding,
} from "../../shared/contracts";
import { scanLuaLexically } from "../source/lexical";

interface CapabilitySpec {
  readonly category: CapabilityCategory;
  readonly api: string;
  readonly expression: RegExp;
}

const CAPABILITIES: readonly CapabilitySpec[] = [
  { category: "dynamic-code", api: "loadstring", expression: /\bloadstring\b/g },
  { category: "dynamic-code", api: "load", expression: /\bload\b/g },
  { category: "dynamic-code", api: "dofile", expression: /\bdofile\b/g },
  { category: "dynamic-code", api: "require", expression: /\brequire\b/g },
  {
    category: "executor-hook",
    api: "hookmetamethod",
    expression: /\bhookmetamethod\b/g,
  },
  { category: "executor-hook", api: "hookfunction", expression: /\bhookfunction\b/g },
  { category: "executor-hook", api: "newcclosure", expression: /\bnewcclosure\b/g },
  {
    category: "executor-hook",
    api: "getnamecallmethod",
    expression: /\bgetnamecallmethod\b/g,
  },
  {
    category: "executor-hook",
    api: "getcallbackmember",
    expression: /\bgetcallbackmember\b/g,
  },
  { category: "filesystem", api: "readfile", expression: /\breadfile\b/g },
  { category: "filesystem", api: "writefile", expression: /\bwritefile\b/g },
  { category: "filesystem", api: "appendfile", expression: /\bappendfile\b/g },
  { category: "filesystem", api: "makefolder", expression: /\bmakefolder\b/g },
  { category: "filesystem", api: "delfile", expression: /\bdelfile\b/g },
  {
    category: "network",
    api: "request",
    expression: /\b(?:request|http_request)\b|\bsyn\s*\.\s*request\b/g,
  },
  {
    category: "network",
    api: "HttpGet",
    expression: /(?:[:.]\s*HttpGet\b|\bHttpGet\b)/g,
  },
  {
    category: "network",
    api: "GetAsync",
    expression: /(?:[:.]\s*GetAsync\b|\bGetAsync\b)/g,
  },
  {
    category: "network",
    api: "PostAsync",
    expression: /(?:[:.]\s*PostAsync\b|\bPostAsync\b)/g,
  },
  {
    category: "network",
    api: "RequestAsync",
    expression: /(?:[:.]\s*RequestAsync\b|\bRequestAsync\b)/g,
  },
  {
    category: "clipboard",
    api: "setclipboard",
    expression: /\bsetclipboard\b/g,
  },
  { category: "environment", api: "getgenv", expression: /\bgetgenv\b/g },
  { category: "environment", api: "getfenv", expression: /\bgetfenv\b/g },
  { category: "environment", api: "setfenv", expression: /\bsetfenv\b/g },
  { category: "environment", api: "identifyexecutor", expression: /\bidentifyexecutor\b/g },
  { category: "environment", api: "shared", expression: /\bshared\b/g },
  {
    category: "debug-introspection",
    api: "debug/getinfo",
    expression: /\bdebug\s*\.\s*getinfo\b|\bgetinfo\b/g,
  },
  {
    category: "debug-introspection",
    api: "decompile/disassemble",
    expression: /\b(?:decompile|disassemble)\b/g,
  },
  {
    category: "roblox-remote",
    api: "FireServer",
    expression: /[:.]\s*FireServer\b/g,
  },
  {
    category: "roblox-remote",
    api: "InvokeServer",
    expression: /[:.]\s*InvokeServer\b/g,
  },
  {
    category: "roblox-remote",
    api: "OnClientEvent/OnClientInvoke",
    expression: /\b(?:OnClientEvent|OnClientInvoke)\b/g,
  },
] as const;

function buildLineStarts(source: string): readonly number[] {
  const starts = [0];
  for (let index = 0; index < source.length; index += 1) {
    if (source.charCodeAt(index) === 10) starts.push(index + 1);
  }
  return starts;
}

function lineForOffset(starts: readonly number[], offset: number): number {
  let low = 0;
  let high = starts.length;
  while (low + 1 < high) {
    const middle = Math.floor((low + high) / 2);
    const value = starts[middle] ?? 0;
    if (value <= offset) low = middle;
    else high = middle;
  }
  return low + 1;
}

function findCapability(
  code: string,
  lineStarts: readonly number[],
  spec: CapabilitySpec,
): CapabilityFinding | null {
  const matches = [...code.matchAll(spec.expression)];
  if (matches.length === 0) return null;
  const lines = [
    ...new Set(
      matches.map((match) => lineForOffset(lineStarts, match.index ?? 0)),
    ),
  ]
    .sort((left, right) => left - right)
    .slice(0, 25);
  return {
    category: spec.category,
    api: spec.api,
    occurrences: matches.length,
    lines,
  };
}

function findUrls(source: string, lineStarts: readonly number[]): readonly UrlFinding[] {
  const findings: UrlFinding[] = [];
  const seen = new Set<string>();
  const urlExpression = /\bhttps?:\/\/[^\s"'`<>{}\[\]]+/giu;
  for (const match of source.matchAll(urlExpression)) {
    const raw = match[0].replace(/[),.;]+$/u, "");
    if (raw.length > 2_048) continue;
    const line = lineForOffset(lineStarts, match.index ?? 0);
    const key = `${line}:${raw}`;
    if (seen.has(key)) continue;
    seen.add(key);
    findings.push({
      url: raw,
      scheme: raw.toLowerCase().startsWith("https:") ? "https" : "http",
      line,
    });
  }
  return findings;
}

export function inventoryBehavior(source: string): BehaviorInventory {
  const lexical = scanLuaLexically(source);
  const lineStarts = buildLineStarts(source);
  const capabilities = CAPABILITIES.map((spec) =>
    findCapability(lexical.code, lineStarts, spec),
  ).filter((finding): finding is CapabilityFinding => finding !== null);

  return {
    reachability: "not-evaluated",
    evidenceSource: "source-code",
    capabilities,
    urls: findUrls(source, lineStarts),
  };
}

/**
 * Inventories decoded string/constant evidence. Unlike inventoryBehavior,
 * this intentionally includes literal rows; reachability is still unknown.
 */
export function inventorySerializedBehaviorEvidence(
  source: string,
): BehaviorInventory {
  const lineStarts = buildLineStarts(source);
  const capabilities = CAPABILITIES.map((spec) =>
    findCapability(source, lineStarts, spec),
  ).filter((finding): finding is CapabilityFinding => finding !== null);
  return {
    reachability: "not-evaluated",
    evidenceSource: "serialized-string-inventory",
    capabilities,
    urls: findUrls(source, lineStarts),
  };
}
