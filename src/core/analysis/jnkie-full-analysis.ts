import { sha256Bytes } from "../hash";
import { scanLuaLexically } from "../source/lexical";

const ENTROPY_WINDOW_BYTES = 64 * 1_024;
const MAX_CAPTURED_STRING_BYTES = 1_024;
const MAX_STRING_CANDIDATES = 4_096;
const MAX_REPORTED_STRINGS = 160;

const PAYLOAD_INDICATORS = [
  "loadstring",
  "setfenv",
  "getfenv",
  "debug",
  "identifyexecutor",
  "HttpService",
  "GetAsync",
  "PostAsync",
  "RequestAsync",
  "GetService",
  "ScreenGui",
  "TextButton",
  "Path2D",
  "CFrame",
  "writeu8",
  "readu32",
  "buffer",
  "bit32",
] as const;

const BUFFER_APIS = [
  "fromstring",
  "len",
  "readi8",
  "readu8",
  "readi16",
  "readu16",
  "readi32",
  "readu32",
  "readf32",
  "readf64",
  "writei8",
  "writeu8",
  "writei16",
  "writeu16",
  "writei32",
  "writeu32",
  "writef32",
  "writef64",
] as const;

export interface JnkieByteFrequency {
  readonly value: number;
  readonly occurrences: number;
  readonly ratio: number;
}

export interface JnkieEntropyWindows {
  readonly windowBytes: number;
  readonly count: number;
  readonly minimum: number;
  readonly maximum: number;
  readonly average: number;
}

export interface JnkieParityFacts {
  readonly evenMostCommonByte: number;
  readonly evenOccurrences: number;
  readonly oddMostCommonByte: number;
  readonly oddOccurrences: number;
}

export interface JnkieDeepPayloadFacts {
  readonly inspectedBytes: number;
  readonly asciiStringRuns: number;
  readonly longestAsciiStringBytes: number;
  readonly readableStrings: readonly string[];
  readonly indicators: readonly string[];
  readonly topByteFrequencies: readonly JnkieByteFrequency[];
  readonly entropyWindows: JnkieEntropyWindows;
  readonly parity: JnkieParityFacts;
}

export interface JnkieDeepLoaderFacts {
  readonly inspectedCharacters: number;
  readonly conditionalCount: number;
  readonly loopCount: number;
  readonly continueCount: number;
  readonly returnCount: number;
  readonly methodCallCount: number;
  readonly uniqueMethodCalls: number;
  readonly uniqueLargeNumericKeys: number;
  readonly bufferApis: readonly string[];
}

export interface JnkieFullStaticAnalysis {
  readonly schemaVersion: 2;
  readonly identity: {
    readonly loaderSha256: string;
    readonly payloadSha256: string;
  };
  readonly safety: {
    readonly execution: "not-executed";
    readonly reachability: "not-evaluated";
    readonly scope: "whole-loader-and-payload-static-scan";
  };
  readonly loader: JnkieDeepLoaderFacts;
  readonly payload: JnkieDeepPayloadFacts;
}

interface StringCandidate {
  readonly value: string;
  readonly score: number;
}

function entropyOfFrequencies(frequencies: Uint32Array, length: number): number {
  if (length === 0) return 0;
  let entropy = 0;
  for (const count of frequencies) {
    if (count === 0) continue;
    const probability = count / length;
    entropy -= probability * Math.log2(probability);
  }
  return entropy;
}

function mostCommon(frequencies: Uint32Array): readonly [number, number] {
  let value = 0;
  let occurrences = 0;
  for (let index = 0; index < frequencies.length; index += 1) {
    const count = frequencies[index] ?? 0;
    if (count > occurrences) {
      value = index;
      occurrences = count;
    }
  }
  return [value, occurrences];
}

function candidateScore(value: string, indicators: readonly string[]): number {
  const letters = value.match(/[A-Za-z]/g)?.length ?? 0;
  const readable = value.match(/[A-Za-z0-9 _.:/()\[\]{}-]/g)?.length ?? 0;
  const ratio = readable / Math.max(1, value.length);
  return indicators.length * 10_000 + Math.round(ratio * 1_000) + Math.min(300, value.length) + letters;
}

export function inspectJnkiePayloadDeep(bytes: Uint8Array): JnkieDeepPayloadFacts {
  const frequencies = new Uint32Array(256);
  const evenFrequencies = new Uint32Array(256);
  const oddFrequencies = new Uint32Array(256);
  const windowEntropies: number[] = [];
  const indicators = new Set<string>();
  const candidates = new Map<string, StringCandidate>();
  let asciiStringRuns = 0;
  let longestAsciiStringBytes = 0;
  let stringLength = 0;
  let captured = "";
  let windowFrequencies = new Uint32Array(256);
  let windowLength = 0;

  const emitString = (): void => {
    if (stringLength >= 4) {
      asciiStringRuns += 1;
      longestAsciiStringBytes = Math.max(longestAsciiStringBytes, stringLength);
      const matched = PAYLOAD_INDICATORS.filter((indicator) =>
        captured.toLowerCase().includes(indicator.toLowerCase()),
      );
      for (const indicator of matched) indicators.add(indicator);
      const letters = captured.match(/[A-Za-z]/g)?.length ?? 0;
      const readable = captured.match(/[A-Za-z0-9 _.:/()\[\]{}-]/g)?.length ?? 0;
      const meaningful = matched.length > 0 || (letters >= 3 && readable / Math.max(1, captured.length) >= 0.55);
      if (meaningful) {
        const value = captured.slice(0, 240);
        const candidate = { value, score: candidateScore(value, matched) };
        const previous = candidates.get(value);
        if (previous) {
          if (candidate.score > previous.score) candidates.set(value, candidate);
        } else if (candidates.size < MAX_STRING_CANDIDATES) {
          candidates.set(value, candidate);
        } else if (matched.length > 0) {
          const generic = [...candidates.entries()].find(([, item]) => item.score < 10_000);
          if (generic) {
            candidates.delete(generic[0]);
            candidates.set(value, candidate);
          }
        }
      }
    }
    stringLength = 0;
    captured = "";
  };

  for (let index = 0; index < bytes.length; index += 1) {
    const byte = bytes[index]!;
    frequencies[byte] = (frequencies[byte] ?? 0) + 1;
    const parityFrequencies = index % 2 === 0 ? evenFrequencies : oddFrequencies;
    parityFrequencies[byte] = (parityFrequencies[byte] ?? 0) + 1;
    windowFrequencies[byte] = (windowFrequencies[byte] ?? 0) + 1;
    windowLength += 1;
    if (windowLength === ENTROPY_WINDOW_BYTES || index === bytes.length - 1) {
      windowEntropies.push(entropyOfFrequencies(windowFrequencies, windowLength));
      windowFrequencies = new Uint32Array(256);
      windowLength = 0;
    }

    if (byte >= 32 && byte <= 126) {
      stringLength += 1;
      if (captured.length < MAX_CAPTURED_STRING_BYTES) captured += String.fromCharCode(byte);
    } else {
      emitString();
    }
  }
  emitString();

  const topByteFrequencies = [...frequencies]
    .map((occurrences, value) => ({
      value,
      occurrences,
      ratio: occurrences / Math.max(1, bytes.length),
    }))
    .sort((left, right) => right.occurrences - left.occurrences || left.value - right.value)
    .slice(0, 16);
  const [evenMostCommonByte, evenOccurrences] = mostCommon(evenFrequencies);
  const [oddMostCommonByte, oddOccurrences] = mostCommon(oddFrequencies);

  return {
    inspectedBytes: bytes.length,
    asciiStringRuns,
    longestAsciiStringBytes,
    readableStrings: [...candidates.values()]
      .sort((left, right) => right.score - left.score || left.value.localeCompare(right.value))
      .slice(0, MAX_REPORTED_STRINGS)
      .map((candidate) => candidate.value),
    indicators: [...indicators].sort((left, right) => left.localeCompare(right)),
    topByteFrequencies,
    entropyWindows: {
      windowBytes: ENTROPY_WINDOW_BYTES,
      count: windowEntropies.length,
      minimum: windowEntropies.length === 0 ? 0 : Math.min(...windowEntropies),
      maximum: Math.max(...windowEntropies, 0),
      average: windowEntropies.reduce((sum, value) => sum + value, 0) / Math.max(1, windowEntropies.length),
    },
    parity: {
      evenMostCommonByte,
      evenOccurrences,
      oddMostCommonByte,
      oddOccurrences,
    },
  };
}

export function inspectJnkieLoaderDeep(source: string): JnkieDeepLoaderFacts {
  const code = scanLuaLexically(source).code;
  const methodCalls = [...code.matchAll(/:\s*([A-Za-z_]\w*)\s*\(/g)].map((match) => match[1]!);
  const numericKeys = new Set(
    [...code.matchAll(/\[\s*(\d{2,})\s*\]/g)].map((match) => match[1]!),
  );
  const bufferApis = BUFFER_APIS.filter((api) => new RegExp(`\\b${api}\\b`, "g").test(code));
  return {
    inspectedCharacters: source.length,
    conditionalCount: [...code.matchAll(/\bif\b/g)].length,
    loopCount: [...code.matchAll(/\b(?:for|while|repeat)\b/g)].length,
    continueCount: [...code.matchAll(/\bcontinue\b/g)].length,
    returnCount: [...code.matchAll(/\breturn\b/g)].length,
    methodCallCount: methodCalls.length,
    uniqueMethodCalls: new Set(methodCalls).size,
    uniqueLargeNumericKeys: numericKeys.size,
    bufferApis,
  };
}

export function buildJnkieFullStaticAnalysis(
  loaderSource: string,
  payload: Uint8Array,
): JnkieFullStaticAnalysis {
  return {
    schemaVersion: 2,
    identity: {
      loaderSha256: sha256Bytes(Buffer.from(loaderSource, "utf8")),
      payloadSha256: sha256Bytes(payload),
    },
    safety: {
      execution: "not-executed",
      reachability: "not-evaluated",
      scope: "whole-loader-and-payload-static-scan",
    },
    loader: inspectJnkieLoaderDeep(loaderSource),
    payload: inspectJnkiePayloadDeep(payload),
  };
}

function byteLabel(value: number): string {
  return `0x${value.toString(16).padStart(2, "0")}`;
}

export function renderJnkieFullAnalysisAppendix(
  analysis: JnkieFullStaticAnalysis,
): string {
  const { loader, payload } = analysis;
  return [
    "## Whole-buffer coverage",
    "",
    `- Payload bytes inspected: ${payload.inspectedBytes.toLocaleString("en-US")} / ${payload.inspectedBytes.toLocaleString("en-US")}`,
    `- Loader characters inspected: ${loader.inspectedCharacters.toLocaleString("en-US")}`,
    `- Printable ASCII runs: ${payload.asciiStringRuns.toLocaleString("en-US")}`,
    `- Longest printable ASCII run: ${payload.longestAsciiStringBytes.toLocaleString("en-US")} bytes`,
    `- 64 KiB entropy windows: ${payload.entropyWindows.count} (min ${payload.entropyWindows.minimum.toFixed(4)}, average ${payload.entropyWindows.average.toFixed(4)}, max ${payload.entropyWindows.maximum.toFixed(4)} bits/byte)`,
    "",
    "## Loader control-flow surface",
    "",
    `- Conditional branches: ${loader.conditionalCount.toLocaleString("en-US")}`,
    `- Loop constructs: ${loader.loopCount.toLocaleString("en-US")}`,
    `- Continue statements: ${loader.continueCount.toLocaleString("en-US")}`,
    `- Return statements: ${loader.returnCount.toLocaleString("en-US")}`,
    `- Method calls: ${loader.methodCallCount.toLocaleString("en-US")} across ${loader.uniqueMethodCalls.toLocaleString("en-US")} names`,
    `- Unique large numeric state keys: ${loader.uniqueLargeNumericKeys.toLocaleString("en-US")}`,
    `- Buffer APIs referenced: ${loader.bufferApis.length === 0 ? "none" : loader.bufferApis.join(", ")}`,
    "",
    "## Payload byte profile",
    "",
    ...payload.topByteFrequencies.map(
      (item) => `- ${byteLabel(item.value)}: ${item.occurrences.toLocaleString("en-US")} (${(item.ratio * 100).toFixed(2)}%)`,
    ),
    "",
    `- Most common byte at even offsets: ${byteLabel(payload.parity.evenMostCommonByte)} (${payload.parity.evenOccurrences.toLocaleString("en-US")} occurrences)`,
    `- Most common byte at odd offsets: ${byteLabel(payload.parity.oddMostCommonByte)} (${payload.parity.oddOccurrences.toLocaleString("en-US")} occurrences)`,
    "",
    "## Static capability indicators in serialized data",
    "",
    ...(payload.indicators.length === 0
      ? ["- No configured indicators were found in printable payload regions."]
      : payload.indicators.map((indicator) => `- ${indicator}`)),
    "",
    "## Highest-ranked readable payload strings",
    "",
    ...payload.readableStrings.map((value, index) => `- ${index + 1}. \`${value.replace(/`/g, "\\`")}\``),
    "",
    "## Evidence boundary",
    "",
    "Every payload byte was included in the measurements above. This proves structural coverage, not runtime reachability. Randomized opcode semantics and original source identifiers remain unknown until an exact static decoder mapping is recovered.",
    "",
  ].join("\n");
}
