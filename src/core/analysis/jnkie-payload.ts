import { scanLuaLexically } from "../source/lexical";

export interface JnkiePayloadFacts {
  readonly byteLength: number;
  readonly entropyBitsPerByte: number;
  readonly distinctByteValues: number;
  readonly printableByteRatio: number;
  readonly zeroByteCount: number;
  readonly previewHex: string;
  readonly asciiStrings: readonly string[];
}

export interface JnkieLoaderFacts {
  readonly functionCount: number;
  readonly namedHandlers: readonly string[];
  readonly entrypoint?: string;
  readonly libraryAliases: readonly string[];
  readonly mostCalledMethods: readonly {
    readonly name: string;
    readonly occurrences: number;
  }[];
}

const MAX_REPORTED_STRINGS = 160;
const MAX_STRING_LENGTH = 240;

function extractAsciiStrings(bytes: Uint8Array): readonly string[] {
  const values: string[] = [];
  const seen = new Set<string>();
  let current = "";
  const emit = (): void => {
    if (current.length >= 4) {
      const value = current.slice(0, MAX_STRING_LENGTH);
      if (!seen.has(value)) {
        seen.add(value);
        values.push(value);
      }
    }
    current = "";
  };
  for (const byte of bytes) {
    if (byte >= 32 && byte <= 126) current += String.fromCharCode(byte);
    else emit();
    if (values.length >= MAX_REPORTED_STRINGS) break;
  }
  emit();
  return values.slice(0, MAX_REPORTED_STRINGS);
}

export function inspectJnkiePayload(bytes: Uint8Array): JnkiePayloadFacts {
  const frequencies = new Uint32Array(256);
  let printable = 0;
  for (const byte of bytes) {
    frequencies[byte] = (frequencies[byte] ?? 0) + 1;
    if (byte === 9 || byte === 10 || byte === 13 || (byte >= 32 && byte <= 126)) printable += 1;
  }
  let entropy = 0;
  let distinct = 0;
  for (const count of frequencies) {
    if (count === 0) continue;
    distinct += 1;
    const probability = count / Math.max(1, bytes.length);
    entropy -= probability * Math.log2(probability);
  }
  return {
    byteLength: bytes.length,
    entropyBitsPerByte: entropy,
    distinctByteValues: distinct,
    printableByteRatio: printable / Math.max(1, bytes.length),
    zeroByteCount: frequencies[0] ?? 0,
    previewHex: [...bytes.slice(0, 64)].map((byte) => byte.toString(16).padStart(2, "0")).join(" "),
    asciiStrings: extractAsciiStrings(bytes),
  };
}

export function inspectJnkieLoader(source: string): JnkieLoaderFacts {
  const code = scanLuaLexically(source).code;
  const namedHandlers = [...code.matchAll(/\b([A-Za-z_]\w*)\s*=\s*function\s*\(/g)]
    .map((match) => match[1]!)
    .filter((name, index, values) => values.indexOf(name) === index);
  const libraryAliases = [...code.matchAll(
    /\b([A-Za-z_]\w*)\s*=\s*((?:math|string|bit32|buffer|table|coroutine)(?:\s*\.\s*[A-Za-z_]\w*)?)/g,
  )].map((match) => `${match[1]} -> ${match[2]!.replace(/\s+/g, "")}`);
  const callCounts = new Map<string, number>();
  for (const match of code.matchAll(/:\s*([A-Za-z_]\w*)\s*\(/g)) {
    const name = match[1]!;
    callCounts.set(name, (callCounts.get(name) ?? 0) + 1);
  }
  const entrypoint = /\}\)\s*:\s*([A-Za-z_]\w*)\s*\(\s*\)\s*;?\s*$/.exec(code)?.[1];
  return {
    functionCount: [...code.matchAll(/\bfunction\b/g)].length,
    namedHandlers,
    ...(entrypoint === undefined ? {} : { entrypoint }),
    libraryAliases,
    mostCalledMethods: [...callCounts.entries()]
      .map(([name, occurrences]) => ({ name, occurrences }))
      .sort((left, right) => right.occurrences - left.occurrences || left.name.localeCompare(right.name))
      .slice(0, 30),
  };
}

export function renderJnkiePayloadReport(loaderSource: string, bytes: Uint8Array): string {
  const facts = inspectJnkiePayload(bytes);
  const loader = inspectJnkieLoader(loaderSource);
  const strings = facts.asciiStrings.length === 0
    ? ["- No plain ASCII strings of four or more bytes were found."]
    : facts.asciiStrings.map((value, index) => `- ${index + 1}. \`${value.replace(/`/g, "\\`")}\``);
  return [
    "# JNKIE / Luraph payload — static structure report",
    "",
    "> This report inspects inert bytes only. The loader and payload were not executed.",
    "",
    "## Recovered VM loader",
    "",
    `- Formatted functions: ${loader.functionCount}`,
    `- Named handler fields: ${loader.namedHandlers.length}`,
    `- Final table entrypoint: ${loader.entrypoint ?? "not proven"}`,
    `- Handler names: ${loader.namedHandlers.join(", ")}`,
    "",
    "### Exact library aliases",
    "",
    ...(loader.libraryAliases.length === 0
      ? ["- No direct standard-library aliases were identified."]
      : loader.libraryAliases.map((alias) => `- ${alias}`)),
    "",
    "### Most referenced VM methods",
    "",
    ...loader.mostCalledMethods.map((method) => `- ${method.name}: ${method.occurrences} call(s)`),
    "",
    "## Binary facts",
    "",
    `- Length: ${facts.byteLength.toLocaleString("en-US")} bytes`,
    `- Shannon entropy: ${facts.entropyBitsPerByte.toFixed(4)} bits/byte`,
    `- Distinct byte values: ${facts.distinctByteValues} / 256`,
    `- Printable-byte ratio: ${(facts.printableByteRatio * 100).toFixed(2)}%`,
    `- Zero bytes: ${facts.zeroByteCount.toLocaleString("en-US")}`,
    `- First 64 bytes: \`${facts.previewHex}\``,
    "",
    "## Recoverable plain strings",
    "",
    ...strings,
    "",
    "## Interpretation",
    "",
    "The buffer is serialized input for the recovered randomized VM loader, not standard Lua 5.1 bytecode. Generic formatting and whole-buffer measurements do not reconstruct payload source. A matching dual-hash profile may attach current-stream inventory and raw-IR evidence; any compact or VM-audit text from the separate 324,503-byte sample is quarantined reference material, never current recovery evidence.",
    "",
  ].join("\n");
}
