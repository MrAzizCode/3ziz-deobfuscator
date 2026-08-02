import type { ExtractedArtifact } from "../../shared/contracts";
import lzmaPurejs from "lzma-purejs";

import {
  buildJnkieFullStaticAnalysis,
  renderJnkieFullAnalysisAppendix,
} from "../analysis/jnkie-full-analysis";
import { renderJnkiePayloadReport } from "../analysis/jnkie-payload";
import {
  devirtualizationSourceLabel,
  devirtualizeSection,
  renderDevirtualizationAppendix,
  type DevirtualizationResult,
} from "../devirt";
import { sha256Bytes } from "../hash";
import {
  decodeLuraphAscii85,
  looksLikeRawLzma,
  luraphAscii85Candidates,
  scanLuraphEncodedStreams,
  type LuraphEncodedStream,
} from "../luraph/stream-scan";
import {
  KNOWN_JNKIE_LOADER_SHA256,
  KNOWN_JNKIE_PAYLOAD_SHA256,
  knownProfileManifestArtifact,
  resolveKnownJnkieProfile,
} from "../recovery/jnkie-known-profile";
import { renderKnownJnkieProfileReport } from "../recovery/jnkie-profile-report";
import { buildJnkieRecordArtifacts } from "../recovery/jnkie-record-artifacts";
import {
  assertKnownJnkieRecordInvariants,
  decodeJnkieRecordStream,
} from "../recovery/jnkie-record-decoder";
import {
  emitKnownJnkieSemanticPseudocode,
  type JnkieSemanticEmission,
  type JnkieSemanticIdentity,
} from "../recovery/jnkie-semantic-emitter";
import { formatLuauStatically } from "../source/luau-format";

const MAX_STREAMS = 2;

interface LongStringMatch {
  readonly value: string;
  readonly end: number;
}

/**
 * File name of the devirtualized Lua, when the target section was lifted.
 *
 * Deliberately not `readable.lua`: the artifact store writes that name from
 * the analysis readable source, and artifacts are never overwritten.
 */
export const JNKIE_READABLE_LUA_ARTIFACT = "jnkie-devirtualized.lua";

export interface JnkieExtractionResult {
  readonly artifacts: readonly ExtractedArtifact[];
  readonly encodedLengths: readonly number[];
  readonly diagnostics: readonly string[];
  /** Present when the target script section was devirtualized. */
  readonly devirtualization?: DevirtualizationResult;
}

function readLongBracketString(source: string, start: number): LongStringMatch {
  if (source[start] !== "[") {
    throw new Error("Expected a Lua long-bracket string.");
  }
  let cursor = start + 1;
  while (source[cursor] === "=") cursor += 1;
  if (source[cursor] !== "[") {
    throw new Error("Malformed Lua long-bracket opener.");
  }
  const equals = source.slice(start + 1, cursor);
  const contentStart = cursor + 1;
  const close = `]${equals}]`;
  const contentEnd = source.indexOf(close, contentStart);
  if (contentEnd < 0) {
    throw new Error("Unterminated Lua long-bracket string.");
  }
  return {
    value: source.slice(contentStart, contentEnd),
    end: contentEnd + close.length,
  };
}

export function findJnkieEncodedStreams(source: string): readonly string[] {
  const assignment = /local\s+V\s*,\s*y\s*=\s*Y\s*\(\s*/g;
  const match = assignment.exec(source);
  if (!match) return [];

  const streams: string[] = [];
  let cursor = match.index + match[0].length;
  for (let index = 0; index < MAX_STREAMS; index += 1) {
    const longString = readLongBracketString(source, cursor);
    streams.push(longString.value);
    cursor = longString.end;
    while (/\s/.test(source[cursor] ?? "")) cursor += 1;
    if (source[cursor] !== ")") {
      throw new Error("Malformed JNKIE/Luraph decoder call.");
    }
    cursor += 1;
    while (/\s/.test(source[cursor] ?? "")) cursor += 1;
    if (index + 1 < MAX_STREAMS) {
      if (source[cursor] !== ",") {
        throw new Error("The second JNKIE/Luraph stream is missing.");
      }
      cursor += 1;
      while (/\s/.test(source[cursor] ?? "")) cursor += 1;
      if (!source.startsWith("Y(", cursor)) {
        throw new Error("Malformed second JNKIE/Luraph decoder call.");
      }
      cursor += 2;
      while (/\s/.test(source[cursor] ?? "")) cursor += 1;
    }
  }
  return streams;
}

export { decodeLuraphAscii85 } from "../luraph/stream-scan";

/**
 * Present a legacy structural match as a scanned stream so both discovery
 * paths feed the same decoder.
 */
function asScannedStream(text: string): LuraphEncodedStream {
  return {
    literalStart: -1,
    literalEnd: -1,
    literalKind: "long-bracket",
    marker: text.slice(0, 6),
    text,
    declaredSubIndex: null,
  };
}

/**
 * Discover the wrapper's encoded streams.  The marker scan handles every
 * literal form seen across builds; the structural `Y(...)` match remains as a
 * fallback for sources whose streams carry no recognizable marker.
 */
function discoverEncodedStreams(source: string): readonly LuraphEncodedStream[] {
  const scanned = scanLuraphEncodedStreams(source);
  if (scanned.length > 0) return scanned;
  return findJnkieEncodedStreams(source).map(asScannedStream);
}


function textMediaType(bytes: Uint8Array): string {
  try {
    const text = new TextDecoder("utf-8", { fatal: true }).decode(bytes);
    const printable = [...text].filter((character) => {
      const code = character.codePointAt(0) ?? 0;
      return code === 9 || code === 10 || code === 13 || code >= 32;
    }).length;
    return printable / Math.max(1, text.length) > 0.97
      ? "text/x-lua; charset=utf-8"
      : "application/octet-stream";
  } catch {
    return "application/octet-stream";
  }
}

function artifact(fileName: string, mediaType: string, bytes: Uint8Array): ExtractedArtifact {
  return { fileName, mediaType, bytes, sha256: sha256Bytes(bytes) };
}

type EmittedJnkieSemantics = Extract<
  JnkieSemanticEmission,
  { readonly status: "emitted" }
>;

/** Canonical manifest bytes shared by extraction and independent validation. */
export function buildJnkieSemanticCoverageArtifact(
  semantics: EmittedJnkieSemantics,
  identity: JnkieSemanticIdentity,
): ExtractedArtifact {
  return artifact(
    "jnkie-semantic-coverage.json",
    "application/json",
    Buffer.from(
      `${JSON.stringify(
        {
          schemaVersion: 1,
          scope: semantics.scope,
          identity,
          coverage: semantics.coverage,
          compact: {
            byteLength: semantics.compactByteLength,
            truncated: semantics.compactTruncated,
            includedInstructionRecords:
              semantics.compactIncludedInstructionRecords,
            omittedInstructionRecords:
              semantics.compactOmittedInstructionRecords,
          },
          fullArtifact: {
            fileName: semantics.fullArtifact.fileName,
            mediaType: semantics.fullArtifact.mediaType,
            compressedByteLength:
              semantics.fullArtifact.compressedByteLength,
            uncompressedByteLength:
              semantics.fullArtifact.uncompressedByteLength,
            deterministicHeader:
              semantics.fullArtifact.deterministicHeader,
          },
          safety: semantics.safety,
        },
        null,
        2,
      )}\n`,
      "utf8",
    ),
  );
}

export function extractJnkieLuraph(
  source: string,
  maxOutputBytes: number,
): JnkieExtractionResult {
  const encoded = discoverEncodedStreams(source);
  if (encoded.length !== 2) {
    throw new Error("The expected pair of JNKIE/Luraph streams was not found.");
  }
  const perStreamLimit = Math.max(1, Math.floor(maxOutputBytes / 2));
  const diagnostics: string[] = [];
  let devirtualizationResult: DevirtualizationResult | undefined;
  let compressed: readonly Uint8Array[] | undefined;
  let decompressed: readonly Uint8Array[] = [];

  /*
   * The wrapper picks its Lua substring start index after probing its host, and
   * different builds pack each 32-bit group in different byte orders.  Every
   * candidate decoding is structurally valid on its own, so the range decoder
   * is the acceptance test: only one candidate decompresses.
   */
  for (const candidate of luraphAscii85Candidates(encoded[0]!)) {
    if (!looksLikeRawLzma(candidate.bytes)) continue;
    const label = `offset ${candidate.headerSkip + 1} / ${candidate.wordOrder}-endian`;
    try {
      const candidateCompressed = encoded.map((stream) =>
        decodeLuraphAscii85(stream.text, {
          headerSkip: candidate.headerSkip,
          wordOrder: candidate.wordOrder,
        }),
      );
      const candidateDecompressed = candidateCompressed.map((stream) =>
        decodeLuraphRangeStream(stream, perStreamLimit),
      );
      compressed = candidateCompressed;
      decompressed = candidateDecompressed;
      diagnostics.push(`Selected the ${label} Luraph stream encoding.`);
      break;
    } catch (error) {
      diagnostics.push(
        `Encoding ${label} was rejected: ${error instanceof Error ? error.message : String(error)}`,
      );
    }
  }
  compressed ??= encoded.map((stream) =>
    decodeLuraphAscii85(stream.text, { headerSkip: 4, wordOrder: "little" }),
  );

  const artifacts: ExtractedArtifact[] = [
    artifact("jnkie-loader.compressed.bin", "application/octet-stream", compressed[0] ?? new Uint8Array()),
    artifact("jnkie-payload.compressed.bin", "application/octet-stream", compressed[1] ?? new Uint8Array()),
  ];
  const loader = decompressed[0];
  let loaderSource: string | undefined;
  if (loader) {
    artifacts.push(artifact("jnkie-loader.lua", textMediaType(loader), loader));
    loaderSource = new TextDecoder("utf-8", { fatal: true }).decode(loader);
    const formatted = formatLuauStatically(loaderSource);
    artifacts.push(
      artifact(
        "jnkie-loader.formatted.lua",
        "text/x-lua; charset=utf-8",
        Buffer.from(formatted.source, "utf8"),
      ),
    );
    diagnostics.push(
      `Formatted the loader into ${formatted.lineCount} lines while preserving all ${formatted.tokenCount} lexical tokens.`,
    );
  }
  const payload = decompressed[1];
  if (payload) {
    artifacts.push(artifact("jnkie-payload.bin", textMediaType(payload), payload));
    const profile = loader === undefined
      ? undefined
      : resolveKnownJnkieProfile(loader, payload);
    const fullAnalysis = buildJnkieFullStaticAnalysis(loaderSource ?? "", payload);
    const recordArtifacts: ExtractedArtifact[] = [];
    const semanticArtifacts: ExtractedArtifact[] = [];
    const recoveryAppendices: string[] = [];
    const loaderSha256 = loader === undefined ? undefined : sha256Bytes(loader);
    const payloadSha256 = sha256Bytes(payload);
    if (
      loader !== undefined &&
      loaderSha256 === KNOWN_JNKIE_LOADER_SHA256 &&
      payloadSha256 === KNOWN_JNKIE_PAYLOAD_SHA256
    ) {
      const records = decodeJnkieRecordStream(payload, {
        requireNestedSection: true,
        rejectTrailingBytes: true,
        nestedSectionPreludeBytes: 400,
        limits: {
          maxInputBytes: payload.byteLength,
          maxConstants: 20_000,
          maxConstantValueBytes: 1_024 * 1_024,
          maxPrototypes: 1_000,
          maxInstructionsPerPrototype: 100_000,
          maxInstructionsTotal: 300_000,
          maxCapturesPerPrototype: 10_000,
          maxCapturesTotal: 20_000,
        },
      });
      assertKnownJnkieRecordInvariants(records);
      recordArtifacts.push(...buildJnkieRecordArtifacts(records));
      const recordReport = recordArtifacts.find(
        (candidate) => candidate.fileName === "jnkie-record-report.md",
      );
      if (recordReport !== undefined) {
        recoveryAppendices.push(
          new TextDecoder("utf-8", { fatal: true }).decode(recordReport.bytes).trimEnd(),
        );
      }

      const semantics = emitKnownJnkieSemanticPseudocode(records, {
        loaderSha256,
        payloadSha256,
      });
      if (semantics.status === "emitted") {
        semanticArtifacts.push(
          artifact(
            "jnkie-semantic-pseudocode.compact.txt",
            "text/plain; charset=utf-8",
            Buffer.from(semantics.compactText, "utf8"),
          ),
          buildJnkieSemanticCoverageArtifact(
            semantics,
            { loaderSha256, payloadSha256 },
          ),
          artifact(
            semantics.fullArtifact.fileName,
            semantics.fullArtifact.mediaType,
            semantics.fullArtifact.bytes,
          ),
        );
        const coverage = semantics.coverage;
        recoveryAppendices.push(
          [
            "# JNKIE conservative semantic lift",
            "",
            `- Instruction records: ${coverage.totalInstructionRecords.toLocaleString("en-US")}`,
            `- Proven direct semantics: ${coverage.provenSemanticInstructions.toLocaleString("en-US")}`,
            `- Decoder protocol records: ${coverage.decoderProtocolInstructions.toLocaleString("en-US")}`,
            `- Raw unresolved records: ${coverage.rawUnresolvedInstructions.toLocaleString("en-US")}`,
            `- Direct semantic coverage: ${(coverage.sourceSemanticCoverageRatio * 100).toFixed(2)}%`,
            `- Explained-handler coverage: ${(coverage.explainedHandlerCoverageRatio * 100).toFixed(2)}%`,
            `- Compact view includes ${semantics.compactIncludedInstructionRecords.toLocaleString("en-US")} records and explicitly omits ${semantics.compactOmittedInstructionRecords.toLocaleString("en-US")}; the complete inert pseudocode is exported as \`${semantics.fullArtifact.fileName}\`.`,
            "- This is provenance-linked register pseudocode, not claimed original Lua/Luau source.",
            "- Submitted code execution: never.",
          ].join("\n"),
        );
        diagnostics.push(
          `Decoded both exact JNKIE record sections (${records.statistics.prototypeCount} prototypes, ${records.statistics.instructionCount} instructions) and emitted conservative semantic pseudocode with ${(coverage.sourceSemanticCoverageRatio * 100).toFixed(2)}% direct instruction coverage; ${records.statistics.unresolvedBytes} interstitial bytes remain explicitly untyped.`,
        );
      }

      /*
       * The outer section is the protected script itself: its constants carry
       * the script's own API names.  The nested section is Luraph's second
       * stage VM, whose constants are encrypted, so it stays in the audit
       * views rather than driving readable output.
       */
      const targetSection = records.sections[0];
      if (targetSection !== undefined) {
        const devirtualized = devirtualizeSection(targetSection, {
          sourceLabel: devirtualizationSourceLabel(payloadSha256),
        });
        devirtualizationResult = devirtualized;
        semanticArtifacts.push(
          artifact(
            JNKIE_READABLE_LUA_ARTIFACT,
            "text/x-lua; charset=utf-8",
            Buffer.from(devirtualized.lua, "utf8"),
          ),
        );
        recoveryAppendices.push(renderDevirtualizationAppendix(devirtualized));
        diagnostics.push(
          `Devirtualized the target script section into ${devirtualized.coverage.prototypesEmitted} Lua functions covering ${(devirtualized.coverage.provenRatio * 100).toFixed(2)}% of its instruction records; the emitted source ${devirtualized.reparses ? "re-parses cleanly" : "did not re-parse"}.`,
        );
      }
    }
    const payloadReport = [
      renderJnkiePayloadReport(loaderSource ?? "", payload).trimEnd(),
      "",
      renderJnkieFullAnalysisAppendix(fullAnalysis).trimEnd(),
      "",
      ...recoveryAppendices.flatMap((appendix) => [appendix, ""]),
      ...(profile === undefined ? [] : [renderKnownJnkieProfileReport(profile.manifest).trimEnd(), ""]),
    ].join("\n");
    artifacts.push(
      artifact(
        "jnkie-payload-report.md",
        "text/markdown; charset=utf-8",
        Buffer.from(payloadReport, "utf8"),
      ),
    );
    artifacts.push(
      artifact(
        "jnkie-full-static-analysis.json",
        "application/json",
        Buffer.from(`${JSON.stringify(fullAnalysis, null, 2)}\n`, "utf8"),
      ),
    );
    artifacts.push(...recordArtifacts, ...semanticArtifacts);

    if (profile) {
      artifacts.push(knownProfileManifestArtifact(profile.manifest));
      if (profile.status === "loaded") {
        artifacts.push(...profile.artifacts);
        diagnostics.push(
          `Loaded exact dual-hash current-stream evidence profile ${profile.manifest.profileId} with ${profile.artifacts.length} integrity-checked artifacts; earlier-sample references remain quarantined as warning-prefixed plain text.`,
        );
      } else if (profile.status === "rejected") {
        diagnostics.push(`Rejected the matching static knowledge pack: ${profile.manifest.rejectionReason ?? "validation failed"}`);
      } else {
        diagnostics.push("No exact dual-hash current-stream evidence profile matched this loader and payload pair.");
      }
    }
  }

  return {
    artifacts,
    encodedLengths: encoded.map((stream) => stream.text.length),
    diagnostics,
    ...(devirtualizationResult === undefined
      ? {}
      : { devirtualization: devirtualizationResult }),
  };
}

export function decodeLuraphRangeStream(
  input: Uint8Array,
  maxOutputBytes: number,
): Uint8Array {
  if (!Number.isSafeInteger(maxOutputBytes) || maxOutputBytes <= 0) {
    throw new Error("The extraction output limit must be a positive integer.");
  }
  let inputOffset = 0;
  let outputOffset = 0;
  const output = new Uint8Array(maxOutputBytes);
  const inputStream = {
    readByte(): number {
      const value = input[inputOffset];
      if (value === undefined) throw new Error("Compressed stream ended unexpectedly.");
      inputOffset += 1;
      return value;
    },
  };
  const outputStream = {
    writeByte(value: number): void {
      if (outputOffset >= maxOutputBytes) {
        throw new Error(`Decoded stream exceeds the ${maxOutputBytes}-byte limit.`);
      }
      output[outputOffset] = value & 0xff;
      outputOffset += 1;
    },
  };
  const decoder = new lzmaPurejs.LZMA.Decoder();
  if (!decoder.setDictionarySize(maxOutputBytes) || !decoder.setLcLpPb(3, 0, 0)) {
    throw new Error("Could not configure the bounded Luraph range decoder.");
  }
  if (!decoder.code(inputStream, outputStream, -1)) {
    throw new Error("Luraph range decoding failed structural validation.");
  }
  return output.slice(0, outputOffset);
}
