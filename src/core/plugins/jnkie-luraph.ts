import type {
  AnalysisContext,
  DeobfuscatorPlugin,
  DetectionContext,
  Diagnostic,
  ExtractedArtifact,
  JnkieRecoveryFacts,
  PluginManifest,
  StagePlan,
  ValidationContext,
  ValidationReport,
} from "../../shared/contracts";
import {
  inventoryBehavior,
  inventorySerializedBehaviorEvidence,
} from "../behavior/inventory";
import {
  buildJnkieFullStaticAnalysis,
  renderJnkieFullAnalysisAppendix,
  type JnkieFullStaticAnalysis,
} from "../analysis/jnkie-full-analysis";
import { renderJnkiePayloadReport } from "../analysis/jnkie-payload";
import { detectJnkieLuraph, JNKIE_LURAPH_PLUGIN_ID } from "../detectors/jnkie-luraph";
import { sha256Bytes } from "../hash";
import {
  devirtualizationSourceLabel,
  devirtualizeSection,
  renderDevirtualizationAppendix,
} from "../devirt";
import {
  buildJnkieSemanticCoverageArtifact,
  decodeLuraphAscii85,
  decodeLuraphRangeStream,
  extractJnkieLuraph,
  findJnkieEncodedStreams,
  JNKIE_READABLE_LUA_ARTIFACT,
} from "../extractors/jnkie-luraph";
import {
  KNOWN_JNKIE_LOADER_SHA256,
  KNOWN_JNKIE_PAYLOAD_SHA256,
  KNOWN_JNKIE_PROFILE_ARTIFACT,
  KNOWN_JNKIE_PROFILE_ID,
  knownProfileManifestArtifact,
  resolveKnownJnkieProfile,
} from "../recovery/jnkie-known-profile";
import { renderKnownJnkieProfileReport } from "../recovery/jnkie-profile-report";
import {
  buildJnkieRecordArtifacts,
  buildJnkieRecordSummary,
  parseJnkieRecordSummary,
  type JnkieRecordSummary,
} from "../recovery/jnkie-record-artifacts";
import {
  assertKnownJnkieRecordInvariants,
  decodeJnkieRecordStream,
} from "../recovery/jnkie-record-decoder";
import {
  emitKnownJnkieSemanticPseudocode,
  type JnkieSemanticCoverage,
} from "../recovery/jnkie-semantic-emitter";
import { formatLuauStatically } from "../source/luau-format";
import { parseLuaFacts } from "../source/parse-facts";

export const JNKIE_LURAPH_MANIFEST: PluginManifest = {
  id: JNKIE_LURAPH_PLUGIN_ID,
  name: "JNKIE / Luraph 14.7 extractor",
  version: "0.5.0",
  family: "jnkie-luraph",
  description: "Static two-layer record decoding, provenance-linked semantic lifting, and whole-buffer analysis for paired JNKIE/Luraph streams.",
  supportedKinds: ["lua-source", "luau-source", "text"],
  authoritative: true,
};

function artifactBytes(
  artifacts: readonly ExtractedArtifact[],
  fileName: string,
): Uint8Array | undefined {
  return artifacts.find((candidate) => candidate.fileName === fileName)?.bytes;
}

function artifactText(
  artifacts: readonly ExtractedArtifact[],
  fileName: string,
): string | undefined {
  const bytes = artifactBytes(artifacts, fileName);
  if (!bytes) return undefined;
  try {
    return new TextDecoder("utf-8", { fatal: true }).decode(bytes);
  } catch {
    return undefined;
  }
}

function profileStatus(
  artifacts: readonly ExtractedArtifact[],
): "loaded" | "not-matched" | "rejected" | "invalid" {
  const source = artifactText(artifacts, KNOWN_JNKIE_PROFILE_ARTIFACT);
  if (!source) return "invalid";
  try {
    const parsed: unknown = JSON.parse(source);
    if (typeof parsed !== "object" || parsed === null) return "invalid";
    const record = parsed as Record<string, unknown>;
    const match = record.match as Record<string, unknown> | undefined;
    const provenance = record.provenance as Record<string, unknown> | undefined;
    const status = record.status;
    const validStatus =
      status === "loaded" || status === "not-matched" || status === "rejected";
    const validHashes =
      typeof match?.loaderSha256 === "string" &&
      /^[0-9a-f]{64}$/.test(match.loaderSha256) &&
      typeof match.payloadSha256 === "string" &&
      /^[0-9a-f]{64}$/.test(match.payloadSha256) &&
      match.requiresBothHashes === true;
    const loadedShape =
      status !== "loaded" ||
      (typeof record.currentStreamMetrics === "object" &&
        record.currentStreamMetrics !== null &&
        typeof record.unverifiedReferenceMetrics === "object" &&
        record.unverifiedReferenceMetrics !== null &&
        Array.isArray(record.assets));
    return record.schemaVersion === 2 &&
      record.profileId === KNOWN_JNKIE_PROFILE_ID &&
      validStatus &&
      validHashes &&
      provenance?.submittedCodeExecuted === false &&
      loadedShape
      ? status
      : "invalid";
  } catch {
    return "invalid";
  }
}

function artifactMatches(
  artifacts: readonly ExtractedArtifact[],
  expected: ExtractedArtifact,
): boolean {
  const matches = artifacts.filter(
    (candidate) => candidate.fileName === expected.fileName,
  );
  const actual = matches[0];
  return matches.length === 1 &&
    actual !== undefined &&
    actual.mediaType === expected.mediaType &&
    actual.bytes.byteLength === expected.bytes.byteLength &&
    actual.sha256 === expected.sha256 &&
    sha256Bytes(actual.bytes) === expected.sha256;
}

function canonicalArtifact(
  fileName: string,
  mediaType: string,
  bytes: Uint8Array,
): ExtractedArtifact {
  return { fileName, mediaType, bytes, sha256: sha256Bytes(bytes) };
}

function inferredTextMediaType(bytes: Uint8Array): string {
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

interface CanonicalJnkieBase {
  readonly loader: Uint8Array;
  readonly loaderSource: string;
  readonly payload: Uint8Array;
  readonly fullAnalysis: JnkieFullStaticAnalysis;
  readonly profile: ReturnType<typeof resolveKnownJnkieProfile>;
  readonly artifacts: readonly ExtractedArtifact[];
}

function reconstructJnkieBase(
  source: string,
  maxOutputBytes: number,
): CanonicalJnkieBase {
  const encoded = findJnkieEncodedStreams(source);
  if (encoded.length !== 2) {
    throw new Error("The expected pair of JNKIE/Luraph streams was not found.");
  }
  const perStreamLimit = Math.max(1, Math.floor(maxOutputBytes / 2));
  let compressed: readonly Uint8Array[] | undefined;
  let decompressed: readonly Uint8Array[] | undefined;
  for (const headerLength of [4, 14] as const) {
    try {
      const candidateCompressed = encoded.map((stream) =>
        decodeLuraphAscii85(stream.slice(headerLength)),
      );
      const candidateDecompressed = candidateCompressed.map((stream) =>
        decodeLuraphRangeStream(stream, perStreamLimit),
      );
      compressed = candidateCompressed;
      decompressed = candidateDecompressed;
      break;
    } catch {
      // Match extraction's bounded header probing without trusting its artifacts.
    }
  }
  const compressedLoader = compressed?.[0];
  const compressedPayload = compressed?.[1];
  const loader = decompressed?.[0];
  const payload = decompressed?.[1];
  if (
    compressedLoader === undefined ||
    compressedPayload === undefined ||
    loader === undefined ||
    payload === undefined
  ) {
    throw new Error("Both bounded JNKIE streams could not be reconstructed.");
  }
  const loaderSource = new TextDecoder("utf-8", { fatal: true }).decode(loader);
  const formatted = formatLuauStatically(loaderSource);
  const fullAnalysis = buildJnkieFullStaticAnalysis(loaderSource, payload);
  const profile = resolveKnownJnkieProfile(loader, payload);
  const fullAnalysisBytes = Buffer.from(
    `${JSON.stringify(fullAnalysis, null, 2)}\n`,
    "utf8",
  );
  return {
    loader,
    loaderSource,
    payload,
    fullAnalysis,
    profile,
    artifacts: [
      canonicalArtifact(
        "jnkie-loader.compressed.bin",
        "application/octet-stream",
        compressedLoader,
      ),
      canonicalArtifact(
        "jnkie-payload.compressed.bin",
        "application/octet-stream",
        compressedPayload,
      ),
      canonicalArtifact("jnkie-loader.lua", inferredTextMediaType(loader), loader),
      canonicalArtifact(
        "jnkie-loader.formatted.lua",
        "text/x-lua; charset=utf-8",
        Buffer.from(formatted.source, "utf8"),
      ),
      canonicalArtifact("jnkie-payload.bin", inferredTextMediaType(payload), payload),
      canonicalArtifact(
        "jnkie-full-static-analysis.json",
        "application/json",
        fullAnalysisBytes,
      ),
      knownProfileManifestArtifact(profile.manifest),
    ],
  };
}

function renderCanonicalPayloadReport(
  base: CanonicalJnkieBase,
  recoveryAppendices: readonly string[],
): ExtractedArtifact {
  const payloadReport = [
    renderJnkiePayloadReport(base.loaderSource, base.payload).trimEnd(),
    "",
    renderJnkieFullAnalysisAppendix(base.fullAnalysis).trimEnd(),
    "",
    ...recoveryAppendices.flatMap((appendix) => [appendix, ""]),
    renderKnownJnkieProfileReport(base.profile.manifest).trimEnd(),
    "",
  ].join("\n");
  return canonicalArtifact(
    "jnkie-payload-report.md",
    "text/markdown; charset=utf-8",
    Buffer.from(payloadReport, "utf8"),
  );
}

function renderSemanticPayloadAppendix(
  semantics: Extract<
    ReturnType<typeof emitKnownJnkieSemanticPseudocode>,
    { readonly status: "emitted" }
  >,
): string {
  const coverage = semantics.coverage;
  return [
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
  ].join("\n");
}

interface ParsedJnkieSemanticManifest {
  readonly coverage: JnkieSemanticCoverage;
  readonly compact: Readonly<{
    byteLength: number;
    truncated: boolean;
    includedInstructionRecords: number;
    omittedInstructionRecords: number;
  }>;
}

function objectRecord(value: unknown): Record<string, unknown> | undefined {
  return typeof value === "object" && value !== null && !Array.isArray(value)
    ? value as Record<string, unknown>
    : undefined;
}

function safeIntegerField(
  record: Record<string, unknown>,
  field: string,
): number | undefined {
  const value = record[field];
  return Number.isSafeInteger(value) && (value as number) >= 0
    ? value as number
    : undefined;
}

function ratioField(
  record: Record<string, unknown>,
  field: string,
): number | undefined {
  const value = record[field];
  return typeof value === "number" && Number.isFinite(value) && value >= 0 && value <= 1
    ? value
    : undefined;
}

function parseSemanticManifest(
  source: string | undefined,
  loaderSha256: string,
  payloadSha256: string,
): ParsedJnkieSemanticManifest | undefined {
  if (source === undefined) return undefined;
  try {
    const root = objectRecord(JSON.parse(source));
    const identity = objectRecord(root?.identity);
    const coverageRecord = objectRecord(root?.coverage);
    const compact = objectRecord(root?.compact);
    const safety = objectRecord(root?.safety);
    if (
      root?.schemaVersion !== 1 ||
      root.scope !== "conservative-static-pseudocode-not-original-source" ||
      identity?.loaderSha256 !== loaderSha256 ||
      identity.payloadSha256 !== payloadSha256 ||
      safety?.submittedCodeExecution !== "never" ||
      safety.outputKind !== "inert-pseudocode" ||
      coverageRecord === undefined ||
      compact === undefined
    ) {
      return undefined;
    }
    const sectionCount = safeIntegerField(coverageRecord, "sectionCount");
    const prototypeCount = safeIntegerField(coverageRecord, "prototypeCount");
    const totalInstructionRecords = safeIntegerField(
      coverageRecord,
      "totalInstructionRecords",
    );
    const provenSemanticInstructions = safeIntegerField(
      coverageRecord,
      "provenSemanticInstructions",
    );
    const decoderProtocolInstructions = safeIntegerField(
      coverageRecord,
      "decoderProtocolInstructions",
    );
    const rawUnresolvedInstructions = safeIntegerField(
      coverageRecord,
      "rawUnresolvedInstructions",
    );
    const sourceSemanticCoverageRatio = ratioField(
      coverageRecord,
      "sourceSemanticCoverageRatio",
    );
    const explainedHandlerCoverageRatio = ratioField(
      coverageRecord,
      "explainedHandlerCoverageRatio",
    );
    const byteLength = safeIntegerField(compact, "byteLength");
    const includedInstructionRecords = safeIntegerField(
      compact,
      "includedInstructionRecords",
    );
    const omittedInstructionRecords = safeIntegerField(
      compact,
      "omittedInstructionRecords",
    );
    if (
      sectionCount === undefined ||
      prototypeCount === undefined ||
      totalInstructionRecords === undefined ||
      provenSemanticInstructions === undefined ||
      decoderProtocolInstructions === undefined ||
      rawUnresolvedInstructions === undefined ||
      sourceSemanticCoverageRatio === undefined ||
      explainedHandlerCoverageRatio === undefined ||
      byteLength === undefined ||
      typeof compact.truncated !== "boolean" ||
      includedInstructionRecords === undefined ||
      omittedInstructionRecords === undefined ||
      !Array.isArray(coverageRecord.sections) ||
      includedInstructionRecords + omittedInstructionRecords !==
        totalInstructionRecords ||
      provenSemanticInstructions + decoderProtocolInstructions +
        rawUnresolvedInstructions !== totalInstructionRecords
    ) {
      return undefined;
    }
    return {
      coverage: coverageRecord as unknown as JnkieSemanticCoverage,
      compact: {
        byteLength,
        truncated: compact.truncated,
        includedInstructionRecords,
        omittedInstructionRecords,
      },
    };
  } catch {
    return undefined;
  }
}

function buildRecoveryFacts(
  summary: JnkieRecordSummary,
  semantics: ParsedJnkieSemanticManifest,
): JnkieRecoveryFacts | undefined {
  const outer = summary.sections.find((section) => section.kind === "outer-loader");
  const nested = summary.sections.find((section) => section.kind === "nested-payload");
  const coverage = semantics.coverage;
  if (
    outer === undefined ||
    nested === undefined ||
    summary.coverage.sections !== coverage.sectionCount ||
    summary.totals.prototypes !== coverage.prototypeCount ||
    summary.totals.instructions !== coverage.totalInstructionRecords
  ) {
    return undefined;
  }
  return {
    schemaVersion: 1,
    recordSections: summary.coverage.sections,
    prototypes: summary.totals.prototypes,
    instructions: summary.totals.instructions,
    constants: summary.totals.constants,
    constantReferences: summary.totals.constantChannelReferences,
    stringReferences: summary.totals.stringConstantChannelReferences,
    resolvedConstantReferences:
      summary.totals.constantChannelReferences -
      summary.totals.unresolvedConstantReferences,
    childReferences: summary.totals.prototypeReferences,
    resolvedChildReferences:
      summary.totals.prototypeReferences -
      summary.totals.unresolvedPrototypeReferences,
    decodedBytes: summary.coverage.decodedRecordBytes,
    unresolvedBytes: summary.coverage.unresolvedBytes,
    outerRootPrototype: outer.rootPrototypeIndex,
    nestedRootPrototype: nested.rootPrototypeIndex,
    semanticInstructions: coverage.provenSemanticInstructions,
    protocolInstructions: coverage.decoderProtocolInstructions,
    unknownInstructions: coverage.rawUnresolvedInstructions,
    semanticCoverageRatio: coverage.sourceSemanticCoverageRatio,
    explainedHandlerCoverageRatio: coverage.explainedHandlerCoverageRatio,
    compactIncludedInstructions:
      semantics.compact.includedInstructionRecords,
    compactOmittedInstructions:
      semantics.compact.omittedInstructionRecords,
    sections: summary.sections.map((section) => ({
      index: section.index,
      kind: section.kind,
      byteStart: section.byteRange[0],
      byteEnd: section.byteRange[1],
      decodedBytes: section.byteRange[1] - section.byteRange[0],
      wrappedConstants: section.wrappedConstants,
      constants: section.constants,
      prototypes: section.prototypes,
      instructions: section.instructions,
      captures: section.captures,
      constantReferences: section.constantChannelReferences,
      stringReferences: section.stringConstantChannelReferences,
      resolvedConstantReferences:
        section.constantChannelReferences - section.unresolvedConstantReferences,
      childReferences: section.prototypeReferences,
      resolvedChildReferences:
        section.prototypeReferences - section.unresolvedPrototypeReferences,
      rootPrototype: section.rootPrototypeIndex,
      rootInstructions: section.rootInstructions,
    })),
    unresolvedRegions: summary.coverage.unresolvedRegions.map((region) => ({
      kind: region.kind,
      byteStart: region.byteRange[0],
      byteEnd: region.byteRange[1],
      byteLength: region.byteLength,
    })),
    submittedCodeExecuted: false,
  };
}

export const jnkieLuraphPlugin: DeobfuscatorPlugin = {
  manifest: JNKIE_LURAPH_MANIFEST,
  async detect(context: DetectionContext) {
    return detectJnkieLuraph(context);
  },
  async plan(_context: AnalysisContext): Promise<StagePlan> {
    return {
      pluginId: JNKIE_LURAPH_PLUGIN_ID,
      stages: [
        { id: "jnkie-confirm", description: "Confirm the Luraph 14.7 stream structure", authoritative: true },
        { id: "jnkie-ascii85", description: "Decode both embedded Ascii85 streams", authoritative: true },
        { id: "jnkie-range", description: "Decompress the bounded loader and payload streams", authoritative: true },
        { id: "jnkie-whole-buffer", description: "Inspect every recovered loader character and payload byte statically", authoritative: true },
        { id: "jnkie-records", description: "Decode both serialized record sections with exact byte provenance", authoritative: true },
        { id: "jnkie-semantics", description: "Lift loader-proven opcode effects into inert register pseudocode", authoritative: true },
        { id: "jnkie-known-profile", description: "Attach current-stream static evidence only when both recovered stream hashes match", authoritative: true },
        { id: "jnkie-preserve", description: "Export recovered bytes without executing the loader", authoritative: true },
      ],
    };
  },
  async extract(context: AnalysisContext) {
    if (!context.text) return [];
    return extractJnkieLuraph(context.text, context.limits.maxOutputBytes).artifacts;
  },
  async analyze(context: AnalysisContext) {
    const text = context.text ?? "";
    const artifacts = context.extractedArtifacts ?? [];
    const formattedLoader = artifactText(artifacts, "jnkie-loader.formatted.lua");
    const status = profileStatus(artifacts);
    const knownStrings = artifactText(artifacts, "jnkie-known-all-strings.tsv");
    const currentStreamProfileMatched = status === "loaded";
    const loaderBytes = artifactBytes(artifacts, "jnkie-loader.lua");
    const payloadBytes = artifactBytes(artifacts, "jnkie-payload.bin");
    const loaderSha256 = loaderBytes === undefined ? "" : sha256Bytes(loaderBytes);
    const payloadSha256 = payloadBytes === undefined ? "" : sha256Bytes(payloadBytes);
    let recordSummary: JnkieRecordSummary | undefined;
    try {
      const summaryText = artifactText(artifacts, "jnkie-record-summary.json");
      recordSummary = summaryText === undefined
        ? undefined
        : parseJnkieRecordSummary(summaryText);
    } catch {
      recordSummary = undefined;
    }
    const semanticManifest = parseSemanticManifest(
      artifactText(artifacts, "jnkie-semantic-coverage.json"),
      loaderSha256,
      payloadSha256,
    );
    const recovery =
      recordSummary === undefined || semanticManifest === undefined
        ? undefined
        : buildRecoveryFacts(recordSummary, semanticManifest);
    const semanticReadable = artifactText(
      artifacts,
      "jnkie-semantic-pseudocode.compact.txt",
    );
    /*
     * Preference order for the Readable pane: devirtualized Lua when the
     * target section was lifted, then conservative register pseudocode, then
     * the formatted loader.  Each tier is labelled by `readableKind` so the
     * UI never presents a weaker tier as recovered source.
     */
    const devirtualizedLua = artifactText(artifacts, JNKIE_READABLE_LUA_ARTIFACT);
    const readableSource =
      devirtualizedLua !== undefined
        ? devirtualizedLua
        : recovery !== undefined && semanticReadable !== undefined
        ? semanticReadable
        : formattedLoader === undefined
          ? undefined
          : [
              "--[[",
              "3ziz JNKIE / Luraph 14.7 - statically formatted VM loader",
              "",
              "This fallback is the recovered decoder/interpreter, not original payload source.",
              "Every loader token below was preserved exactly; only whitespace changed.",
              "The paired payload remained inert and was never executed.",
              "--]]",
              "",
              formattedLoader,
            ].join("\n");
    const diagnostics: Diagnostic[] = [
      {
        code: "JNKIE_STATIC_EXTRACTION",
        severity: "info",
        stage: "jnkie-extraction",
        message: `Extracted ${artifacts.length} inert artifact(s), including the token-verified loader, whole-buffer scan, decoded records, and complete compressed provenance exports where supported.`,
        evidence: artifacts.map(
          (artifact) => `${artifact.fileName}: ${artifact.bytes.byteLength} bytes, SHA-256 ${artifact.sha256}`,
        ),
      },
      {
        code: "JNKIE_VM_NOT_EXECUTED",
        severity: "warning",
        stage: "jnkie-extraction",
        message: "The recovered Luraph loader and payload buffer were preserved as data and were not executed.",
        suggestedAction: "Review Readable IR and Decoded Records as conservative static evidence; raw/protocol operations are deliberately not guessed.",
      },
      ...(recovery === undefined
        ? []
        : [
            {
              code: "JNKIE_TWO_SECTION_RECORD_DECODE",
              severity: "info" as const,
              stage: "jnkie-records",
              message: `Decoded ${recovery.recordSections} serialized sections across ${recovery.decodedBytes.toLocaleString("en-US")} bytes: ${recovery.prototypes.toLocaleString("en-US")} prototypes, ${recovery.instructions.toLocaleString("en-US")} instructions, and ${recovery.constants.toLocaleString("en-US")} constants.`,
              evidence: [
                `${recovery.resolvedChildReferences.toLocaleString("en-US")} / ${recovery.childReferences.toLocaleString("en-US")} prototype references resolved`,
                `${recovery.resolvedConstantReferences.toLocaleString("en-US")} / ${recovery.constantReferences.toLocaleString("en-US")} constant references resolved`,
                `${recovery.unresolvedBytes.toLocaleString("en-US")} interstitial bytes explicitly remain untyped; 0 bytes trail the final section`,
              ],
            },
            {
              code: "JNKIE_SEMANTIC_LIFT_PARTIAL",
              severity: "warning" as const,
              stage: "jnkie-semantics",
              message: `Emitted provenance-linked register pseudocode with ${(recovery.semanticCoverageRatio * 100).toFixed(2)}% direct semantic coverage: ${recovery.semanticInstructions.toLocaleString("en-US")} proven, ${recovery.protocolInstructions.toLocaleString("en-US")} decoder-protocol, and ${recovery.unknownInstructions.toLocaleString("en-US")} raw unresolved instruction records.`,
              evidence: [
                `Readable IR contains ${recovery.compactIncludedInstructions.toLocaleString("en-US")} selected records and names the ${recovery.compactOmittedInstructions.toLocaleString("en-US")} records available in the complete gzip export`,
                "No original identifiers, comments, source layout, or unproven opcode behavior were invented",
              ],
              suggestedAction: "Use the full semantic gzip and instruction JSONL gzip for complete provenance; the UI view is a bounded root-first excerpt.",
            },
          ]),
      ...(currentStreamProfileMatched
        ? [
            {
              code: "JNKIE_CURRENT_STREAM_PROFILE_MATCH",
              severity: "info" as const,
              stage: "jnkie-known-profile",
              message: "Both recovered stream hashes matched the integrity-checked JNKIE profile; live bounded decoding, not the older packaged inventory, supplies the displayed record counts.",
              evidence: recovery === undefined
                ? ["The exact dual-hash profile matched, but decoded record artifacts were unavailable."]
                : [
                    `Outer root P${recovery.outerRootPrototype}; nested payload root P${recovery.nestedRootPrototype}`,
                    `${recovery.recordSections} sections and ${recovery.instructions.toLocaleString("en-US")} total instructions were derived from the current payload bytes`,
                  ],
            },
            {
              code: "JNKIE_UNVERIFIED_EARLIER_SAMPLE_REFERENCES",
              severity: "warning" as const,
              stage: "jnkie-known-profile",
              message: "The supplied compact readable and VM-audit references describe a different earlier 324,503-byte sample; they are exported only as quarantined references and are not used as this payload\'s source or audit.",
              evidence: [
                "Current wrapper size: 1,663,542 bytes",
                "Earlier reference sample size reported in the handoff: 324,503 bytes",
                "No signed derivation manifest binds either reference to the current payload",
              ],
              suggestedAction: "Treat the two reference files as comparison material only.",
            },
          ]
        : [
            {
              code: status === "rejected" ? "JNKIE_KNOWN_PROFILE_REJECTED" : "JNKIE_FORMATTING_SCOPE",
              severity: status === "rejected" ? "warning" as const : "info" as const,
              stage: status === "rejected" ? "jnkie-known-profile" : "jnkie-static-format",
              message: status === "rejected"
                ? "An exact stream fingerprint was recognized, but its static knowledge pack failed integrity or metric validation; only generic static artifacts are shown."
                : "The readable fallback is a multi-line, token-preserving loader format. It is not payload devirtualization and does not invent source names.",
            },
          ]),
    ];
    return {
      status: "partial" as const,
      diagnostics,
      sourceFacts: parseLuaFacts(formattedLoader ?? text, context.classification, context.limits.maxAstNodes),
      behavior: currentStreamProfileMatched && knownStrings !== undefined
        ? inventorySerializedBehaviorEvidence(knownStrings)
        : inventoryBehavior(formattedLoader ?? text),
      passes: [],
      ...(recovery === undefined ? {} : { jnkieRecovery: recovery }),
      ...(readableSource === undefined ? {} : { readableSource }),
      ...(readableSource === undefined
        ? {}
        : {
            readableKind:
              devirtualizedLua !== undefined
                ? ("devirtualized-lua" as const)
                : recovery === undefined
                  ? ("vm-loader" as const)
                  : ("register-pseudocode" as const),
          }),
    };
  },
  async validate(context: ValidationContext): Promise<ValidationReport> {
    const artifacts = context.extractedArtifacts ?? [];
    const diagnostics: Diagnostic[] = [];
    let base: CanonicalJnkieBase | undefined;
    try {
      if (context.text === undefined) {
        throw new Error("The original UTF-8 wrapper text is unavailable.");
      }
      base = reconstructJnkieBase(context.text, context.limits.maxOutputBytes);
    } catch (error) {
      diagnostics.push({
        code: "JNKIE_BASE_PROVENANCE_VALIDATION_FAILED",
        severity: "error",
        stage: "jnkie-validation",
        message: `Could not independently reconstruct both bounded streams from the submitted wrapper: ${error instanceof Error ? error.message : String(error)}`,
      });
    }

    const baseRequired = [
      "jnkie-loader.compressed.bin",
      "jnkie-payload.compressed.bin",
      "jnkie-loader.lua",
      "jnkie-loader.formatted.lua",
      "jnkie-payload.bin",
      "jnkie-payload-report.md",
      "jnkie-full-static-analysis.json",
      KNOWN_JNKIE_PROFILE_ARTIFACT,
    ] as const;
    const exactRecoveryExpected =
      base !== undefined &&
      sha256Bytes(base.loader) === KNOWN_JNKIE_LOADER_SHA256 &&
      sha256Bytes(base.payload) === KNOWN_JNKIE_PAYLOAD_SHA256;
    const recoveryRequired = exactRecoveryExpected
      ? [
          "jnkie-record-summary.json",
          "jnkie-record-prototypes.jsonl",
          "jnkie-record-constants.jsonl.gz",
          "jnkie-record-root.jsonl.gz",
          "jnkie-record-instructions.jsonl.gz",
          "jnkie-records-readable.txt",
          "jnkie-record-report.md",
          "jnkie-semantic-pseudocode.compact.txt",
          "jnkie-semantic-coverage.json",
          "jnkie-semantic-pseudocode.full.txt.gz",
        ] as const
      : [];
    const required = [...baseRequired, ...recoveryRequired];
    const missing = required.filter(
      (name) => !artifacts.some((artifact) => artifact.fileName === name && artifact.bytes.byteLength > 0),
    );

    const expectedBaseArtifact = (fileName: string): ExtractedArtifact | undefined =>
      base?.artifacts.find((artifact) => artifact.fileName === fileName);
    const expectedCompressedLoader = expectedBaseArtifact("jnkie-loader.compressed.bin");
    const expectedCompressedPayload = expectedBaseArtifact("jnkie-payload.compressed.bin");
    const expectedLoader = expectedBaseArtifact("jnkie-loader.lua");
    const expectedFormattedLoader = expectedBaseArtifact("jnkie-loader.formatted.lua");
    const expectedPayload = expectedBaseArtifact("jnkie-payload.bin");
    const expectedFullAnalysis = expectedBaseArtifact("jnkie-full-static-analysis.json");
    const expectedProfileManifest = expectedBaseArtifact(KNOWN_JNKIE_PROFILE_ARTIFACT);
    let submittedTextValid = false;
    try {
      submittedTextValid =
        context.text !== undefined &&
        new TextDecoder("utf-8", { fatal: true }).decode(context.bytes) ===
          context.text;
    } catch {
      submittedTextValid = false;
    }
    const inputIdentityValid =
      submittedTextValid && sha256Bytes(context.bytes) === context.inputSha256;
    const baseProvenanceValid =
      inputIdentityValid &&
      expectedCompressedLoader !== undefined &&
      expectedCompressedPayload !== undefined &&
      expectedLoader !== undefined &&
      expectedPayload !== undefined &&
      artifactMatches(artifacts, expectedCompressedLoader) &&
      artifactMatches(artifacts, expectedCompressedPayload) &&
      artifactMatches(artifacts, expectedLoader) &&
      artifactMatches(artifacts, expectedPayload);
    const formatted = base === undefined
      ? undefined
      : formatLuauStatically(base.loaderSource);
    const formattingValid =
      formatted !== undefined &&
      formatted.verifiedTokenPreservation &&
      expectedFormattedLoader !== undefined &&
      artifactMatches(artifacts, expectedFormattedLoader);
    const fullAnalysisValid =
      expectedFullAnalysis !== undefined &&
      artifactMatches(artifacts, expectedFullAnalysis);
    const profileManifestValid =
      expectedProfileManifest !== undefined &&
      artifactMatches(artifacts, expectedProfileManifest);
    const status = profileStatus(artifacts);
    let knownProfileValid = profileManifestValid;
    let recordRecoveryValid = !exactRecoveryExpected;
    let payloadReportValid = false;
    let readableAnalysisValid = false;
    const baseReadyForRecovery =
      base !== undefined &&
      baseProvenanceValid &&
      formattingValid &&
      fullAnalysisValid &&
      profileManifestValid;

    if (exactRecoveryExpected && baseReadyForRecovery && base !== undefined) {
      try {
        const loaderSha256 = sha256Bytes(base.loader);
        const payloadSha256 = sha256Bytes(base.payload);
        const decoded = decodeJnkieRecordStream(base.payload, {
          requireNestedSection: true,
          rejectTrailingBytes: true,
          nestedSectionPreludeBytes: 400,
          limits: {
            maxInputBytes: base.payload.byteLength,
            maxConstants: 20_000,
            maxConstantValueBytes: 1_024 * 1_024,
            maxPrototypes: 1_000,
            maxInstructionsPerPrototype: 100_000,
            maxInstructionsTotal: 300_000,
            maxCapturesPerPrototype: 10_000,
            maxCapturesTotal: 20_000,
          },
        });
        assertKnownJnkieRecordInvariants(decoded);
        const expectedRecordArtifacts = buildJnkieRecordArtifacts(decoded);
        const recordArtifactsValid = expectedRecordArtifacts.every((expected) =>
          artifactMatches(artifacts, expected),
        );
        const summarySource = artifactText(artifacts, "jnkie-record-summary.json");
        const parsedSummary = summarySource === undefined
          ? undefined
          : parseJnkieRecordSummary(summarySource);
        const expectedSummary = buildJnkieRecordSummary(decoded);
        const summaryValid =
          parsedSummary !== undefined &&
          JSON.stringify(parsedSummary) === JSON.stringify(expectedSummary);
        const semantics = emitKnownJnkieSemanticPseudocode(decoded, {
          loaderSha256,
          payloadSha256,
        });
        let semanticArtifactsValid = false;
        let reportFactsValid = false;
        const recoveryAppendices: string[] = [];
        const expectedRecordReport = expectedRecordArtifacts.find(
          (artifact) => artifact.fileName === "jnkie-record-report.md",
        );
        if (expectedRecordReport !== undefined) {
          recoveryAppendices.push(
            new TextDecoder("utf-8", { fatal: true })
              .decode(expectedRecordReport.bytes)
              .trimEnd(),
          );
        }
        if (semantics.status === "emitted" && parsedSummary !== undefined) {
          const compactBytes = Buffer.from(semantics.compactText, "utf8");
          const expectedCompact: ExtractedArtifact = {
            fileName: "jnkie-semantic-pseudocode.compact.txt",
            mediaType: "text/plain; charset=utf-8",
            bytes: compactBytes,
            sha256: sha256Bytes(compactBytes),
          };
          const expectedFull: ExtractedArtifact = {
            fileName: semantics.fullArtifact.fileName,
            mediaType: semantics.fullArtifact.mediaType,
            bytes: semantics.fullArtifact.bytes,
            sha256: sha256Bytes(semantics.fullArtifact.bytes),
          };
          const expectedCoverage = buildJnkieSemanticCoverageArtifact(
            semantics,
            { loaderSha256, payloadSha256 },
          );
          const semanticManifest = parseSemanticManifest(
            artifactText(artifacts, "jnkie-semantic-coverage.json"),
            loaderSha256,
            payloadSha256,
          );
          semanticArtifactsValid =
            artifactMatches(artifacts, expectedCompact) &&
            artifactMatches(artifacts, expectedCoverage) &&
            artifactMatches(artifacts, expectedFull) &&
            semanticManifest !== undefined &&
            JSON.stringify(semanticManifest.coverage) ===
              JSON.stringify(semantics.coverage) &&
            semanticManifest.compact.byteLength ===
              semantics.compactByteLength &&
            semanticManifest.compact.truncated ===
              semantics.compactTruncated &&
            semanticManifest.compact.includedInstructionRecords ===
              semantics.compactIncludedInstructionRecords &&
            semanticManifest.compact.omittedInstructionRecords ===
              semantics.compactOmittedInstructionRecords;
          const expectedFacts = buildRecoveryFacts(parsedSummary, {
            coverage: semantics.coverage,
            compact: {
              byteLength: semantics.compactByteLength,
              truncated: semantics.compactTruncated,
              includedInstructionRecords:
                semantics.compactIncludedInstructionRecords,
              omittedInstructionRecords:
                semantics.compactOmittedInstructionRecords,
            },
          });
          reportFactsValid =
            expectedFacts !== undefined &&
            JSON.stringify(context.analysis.jnkieRecovery) ===
              JSON.stringify(expectedFacts);
          /*
           * Independently redo the devirtualization and require the published
           * readable source to match it byte for byte.  Falling back to the
           * pseudocode tier stays valid for streams whose target section could
           * not be lifted.
           */
          const targetSection = decoded.sections[0];
          const expectedDevirtualized =
            targetSection === undefined
              ? undefined
              : devirtualizeSection(targetSection, {
                  sourceLabel: devirtualizationSourceLabel(sha256Bytes(base.payload)),
                });
          readableAnalysisValid =
            expectedDevirtualized === undefined
              ? context.analysis.readableKind === "register-pseudocode" &&
                context.analysis.readableSource === semantics.compactText
              : context.analysis.readableKind === "devirtualized-lua" &&
                context.analysis.readableSource === expectedDevirtualized.lua;
          recoveryAppendices.push(renderSemanticPayloadAppendix(semantics));
          if (expectedDevirtualized !== undefined) {
            recoveryAppendices.push(
              renderDevirtualizationAppendix(expectedDevirtualized),
            );
          }
        }
        payloadReportValid = artifactMatches(
          artifacts,
          renderCanonicalPayloadReport(base, recoveryAppendices),
        );
        recordRecoveryValid =
          recordArtifactsValid &&
          summaryValid &&
          semanticArtifactsValid &&
          reportFactsValid &&
          readableAnalysisValid;
        diagnostics.push(
          recordRecoveryValid
            ? {
                code: "JNKIE_RECORD_RECOVERY_VALIDATED",
                severity: "info",
                stage: "jnkie-validation",
                message: `Re-decoded and deterministically reproduced both record sections, all ${decoded.statistics.instructionCount.toLocaleString("en-US")} instruction rows, semantic coverage, and compressed provenance artifacts without executing Lua.`,
              }
            : {
                code: "JNKIE_RECORD_RECOVERY_VALIDATION_FAILED",
              severity: "error",
              stage: "jnkie-validation",
              message: "The exact record decode, strict summary, semantic coverage, readable analysis, report facts, or deterministic artifact reproduction did not match.",
            },
        );
      } catch (error) {
        recordRecoveryValid = false;
        diagnostics.push({
          code: "JNKIE_RECORD_RECOVERY_VALIDATION_FAILED",
          severity: "error",
          stage: "jnkie-validation",
          message: `Bounded record recovery validation failed: ${error instanceof Error ? error.message : String(error)}`,
        });
      }
    } else if (exactRecoveryExpected) {
      recordRecoveryValid = false;
      diagnostics.push({
        code: "JNKIE_RECORD_RECOVERY_VALIDATION_FAILED",
        severity: "error",
        stage: "jnkie-validation",
        message: "Exact recovery validation was withheld because the independently reconstructed base artifacts did not pass provenance checks.",
      });
    } else if (base !== undefined) {
      const expectedReadable = [
        "--[[",
        "3ziz JNKIE / Luraph 14.7 - statically formatted VM loader",
        "",
        "This fallback is the recovered decoder/interpreter, not original payload source.",
        "Every loader token below was preserved exactly; only whitespace changed.",
        "The paired payload remained inert and was never executed.",
        "--]]",
        "",
        formatLuauStatically(base.loaderSource).source,
      ].join("\n");
      readableAnalysisValid =
        context.analysis.jnkieRecovery === undefined &&
        context.analysis.readableKind === "vm-loader" &&
        context.analysis.readableSource === expectedReadable;
      recordRecoveryValid = context.analysis.jnkieRecovery === undefined;
      payloadReportValid = artifactMatches(
        artifacts,
        renderCanonicalPayloadReport(base, []),
      );
    }

    if (status === "loaded") {
      if (base?.profile.status !== "loaded") {
        knownProfileValid = false;
      } else {
        knownProfileValid =
          profileManifestValid &&
          base.profile.artifacts.every((expectedArtifact) =>
            artifactMatches(artifacts, expectedArtifact),
          );
      }
      if (!knownProfileValid) {
        diagnostics.push({
          code: "JNKIE_KNOWN_PROFILE_VALIDATION_FAILED",
          severity: "error",
          stage: "jnkie-validation",
          message: "The matched JNKIE evidence profile did not pass its canonical manifest, asset SHA-256, inventory, raw-IR, and quarantined-reference integrity gates.",
        });
      }
    } else if (status === "rejected") {
      knownProfileValid =
        profileManifestValid && base?.profile.status === "rejected";
      diagnostics.push({
        code: "JNKIE_KNOWN_PROFILE_REJECTED",
        severity: "warning",
        stage: "jnkie-validation",
        message: "The matching profile was rejected atomically; generic static extraction remains available.",
      });
    } else if (status === "invalid") {
      knownProfileValid = false;
      diagnostics.push({
        code: "JNKIE_PROFILE_MANIFEST_INVALID",
        severity: "error",
        stage: "jnkie-validation",
        message: "The JNKIE profile manifest was missing or malformed.",
      });
    } else {
      knownProfileValid =
        profileManifestValid && base?.profile.status === "not-matched";
    }

    if (missing.length > 0) {
      diagnostics.push({
        code: "JNKIE_EXTRACTION_VALIDATION_FAILED",
        severity: "error",
        stage: "jnkie-validation",
        message: "One or more required JNKIE extraction artifacts are missing or empty.",
        evidence: missing,
      });
    }
    if (!baseProvenanceValid && base !== undefined) {
      diagnostics.push({
        code: "JNKIE_BASE_PROVENANCE_VALIDATION_FAILED",
        severity: "error",
        stage: "jnkie-validation",
        message: "The compressed streams or recovered loader/payload artifacts did not exactly match an independent bounded reconstruction from the submitted wrapper.",
      });
    }
    if (!formattingValid) {
      diagnostics.push({
        code: "JNKIE_LOADER_TOKEN_VALIDATION_FAILED",
        severity: "error",
        stage: "jnkie-validation",
        message: "The formatted loader did not reproduce the raw loader's complete token stream.",
      });
    }
    if (!fullAnalysisValid) {
      diagnostics.push({
        code: "JNKIE_WHOLE_BUFFER_VALIDATION_FAILED",
        severity: "error",
        stage: "jnkie-validation",
        message: "Whole-buffer analysis coverage does not match the recovered loader and payload sizes.",
      });
    }
    if (!payloadReportValid) {
      diagnostics.push({
        code: "JNKIE_PAYLOAD_REPORT_VALIDATION_FAILED",
        severity: "error",
        stage: "jnkie-validation",
        message: "The payload report did not exactly match the independently reconstructed loader, payload, full scan, record evidence, semantics, and profile provenance.",
      });
    }
    if (!readableAnalysisValid) {
      diagnostics.push({
        code: "JNKIE_READABLE_ANALYSIS_VALIDATION_FAILED",
        severity: "error",
        stage: "jnkie-validation",
        message: "The reported readable output or readable kind did not exactly match the regenerated static result.",
      });
    }

    const valid =
      missing.length === 0 &&
      baseProvenanceValid &&
      formattingValid &&
      fullAnalysisValid &&
      payloadReportValid &&
      readableAnalysisValid &&
      knownProfileValid &&
      recordRecoveryValid;
    return { valid, diagnostics };
  },
};
