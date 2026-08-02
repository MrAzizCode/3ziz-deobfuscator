import { open, realpath } from "node:fs/promises";

import type { PersistedBrokerAnalysisResult } from "../core/broker";
import { physicalLineCount } from "../core/source/lexical";
import type {
  AnalysisReport,
  ArtifactRecord,
  Diagnostic as CoreDiagnostic,
  ReadableKind,
} from "../shared/contracts";
import { verifyArtifactSha256 } from "./artifact-integrity";
import {
  isPathWithin,
  resolveArtifactFilePath,
} from "./security";

export interface RendererArtifacts {
  readonly original?: string;
  readonly readable?: string;
  readonly decodedRecords?: string;
  readonly exactAudit?: string;
  readonly behaviorReport?: string;
  readonly payloadReport?: string;
  readonly validationReport?: string;
  readonly warnings?: string;
  readonly reportJson?: string;
}

export interface RendererDiagnostic {
  readonly code?: string;
  readonly severity?: "info" | "warning" | "error";
  readonly stage?: string;
  readonly message: string;
  readonly evidence?: string[];
  readonly suggestedAction?: string;
  readonly location?: string;
}

export interface RendererAnalysisResult {
  readonly jobId: string;
  readonly status: string;
  readonly readableKind: ReadableKind;
  readonly input: {
    readonly path: string;
    readonly name: string;
    readonly size: number;
    readonly lineCount?: number;
    readonly sha256: string;
    readonly dialect: string;
  };
  readonly inputSha256: string;
  readonly detection: {
    readonly pluginId: string;
    readonly pluginName: string;
    readonly confidence: number;
    readonly evidence: readonly {
      readonly rule: string;
      readonly label: string;
      readonly detail: string;
      readonly matched: boolean;
      readonly weight: number;
    }[];
  };
  readonly artifacts: RendererArtifacts;
  readonly statistics: {
    readonly functions?: number;
    readonly prototypeSummaries?: number;
    readonly topIrRows?: number;
    readonly recordSections?: number;
    readonly prototypes?: number;
    readonly instructions?: number;
    readonly constants?: number;
    readonly constantReferences?: number;
    readonly stringReferences?: number;
    readonly childReferences?: number;
    readonly resolvedChildReferences?: number;
    readonly decodedBytes?: number;
    readonly unresolvedBytes?: number;
    readonly outerRootPrototype?: number;
    readonly nestedRootPrototype?: number;
    readonly semanticInstructions?: number;
    readonly protocolInstructions?: number;
    readonly unknownInstructions?: number;
    readonly semanticCoverageRatio?: number;
    readonly transformations: number;
    readonly unresolved: number;
    readonly warnings: number;
    readonly durationMs: number;
  };
  readonly diagnostics: readonly RendererDiagnostic[];
  readonly validationChecks: readonly {
    readonly id: string;
    readonly label: string;
    readonly detail: string;
    readonly status: "passed" | "warning" | "failed" | "not-run";
  }[];
  readonly stages: readonly {
    readonly id: string;
    readonly label: string;
    readonly status:
      | "queued"
      | "active"
      | "complete"
      | "warning"
      | "skipped"
      | "error";
    readonly detail: string;
  }[];
  readonly summary: string;
}

export interface ArtifactReadLimits {
  readonly maxArtifactBytes: number;
  readonly maxTotalBytes: number;
}

export const DEFAULT_RENDERER_ARTIFACT_LIMITS: Readonly<ArtifactReadLimits> =
  Object.freeze({
    maxArtifactBytes: 4 * 1024 * 1024,
    maxTotalBytes: 12 * 1024 * 1024,
  });

type ArtifactKey = keyof RendererArtifacts;
type MutableArtifacts = Partial<Record<ArtifactKey, string>>;

interface LoadedArtifacts {
  readonly artifacts: RendererArtifacts;
  readonly diagnostics: readonly RendererDiagnostic[];
}

const UTF8_FATAL_DECODER = new TextDecoder("utf-8", { fatal: true });
const JNKIE_CURRENT_STREAM_PROFILE_CODE =
  "JNKIE_CURRENT_STREAM_PROFILE_MATCH";
const HARD_ARTIFACT_INTEGRITY_CODES = new Set([
  "DESKTOP_JOB_DIRECTORY_UNAVAILABLE",
  "DESKTOP_ARTIFACT_PATH_REJECTED",
  "DESKTOP_ARTIFACT_MISSING",
  "DESKTOP_ARTIFACT_READ_REJECTED",
]);
const ARTIFACT_PRESENTATION_WARNING_CODES = new Set([
  "DESKTOP_ARTIFACT_MEDIA_REJECTED",
  "DESKTOP_ARTIFACT_SIZE_LIMIT",
  "DESKTOP_ARTIFACT_TOTAL_LIMIT",
  "DESKTOP_SYNTHESIZED_ARTIFACT_LIMIT",
]);

function hasDiagnosticCode(report: AnalysisReport, code: string): boolean {
  return report.diagnostics.some((diagnostic) => diagnostic.code === code);
}

export async function adaptBrokerAnalysisResult(
  brokerResult: PersistedBrokerAnalysisResult,
  inputPath: string,
  durationMs: number,
  limits: Readonly<ArtifactReadLimits> = DEFAULT_RENDERER_ARTIFACT_LIMITS,
): Promise<RendererAnalysisResult> {
  assertArtifactLimits(limits);
  const report = brokerResult.analysis.report;
  const loaded = await loadRendererArtifacts(brokerResult, limits);
  const selectedDetection =
    report.detections.find(
      (detection) => detection.pluginId === report.selectedPlugin.id,
    ) ?? report.detections[0];
  const coreDiagnostics = report.diagnostics.map(mapCoreDiagnostic);
  const diagnostics = [...coreDiagnostics, ...loaded.diagnostics];
  const artifactIntegrityFailed = loaded.diagnostics.some((diagnostic) =>
    HARD_ARTIFACT_INTEGRITY_CODES.has(diagnostic.code ?? ""),
  );
  const artifactPresentationWarning = loaded.diagnostics.some((diagnostic) =>
    ARTIFACT_PRESENTATION_WARNING_CODES.has(diagnostic.code ?? ""),
  );
  const rendererStatus = artifactIntegrityFailed
    ? "failed-validation"
    : report.status;
  const warningCount = diagnostics.filter(
    (diagnostic) =>
      diagnostic.severity === "warning" ||
      diagnostic.severity === "error",
  ).length;
  const sourceFacts = report.analysis.sourceFacts;
  const isJnkie = report.selectedPlugin.family === "jnkie-luraph";
  const recovery = report.analysis.jnkieRecovery;
  const hasCurrentJnkieProfile =
    isJnkie &&
    hasDiagnosticCode(report, JNKIE_CURRENT_STREAM_PROFILE_CODE);
  const functionCount = isJnkie
    ? recovery === undefined
      ? sourceFacts?.functionCount ?? report.analysis.bytecode?.prototypeCount
      : undefined
    : sourceFacts?.functionCount ??
      report.analysis.luraphAudit?.functionCount ??
      report.analysis.bytecode?.prototypeCount;
  const inputLineCount =
    report.input.classification.isText && loaded.artifacts.original !== undefined
      ? physicalLineCount(loaded.artifacts.original)
      : sourceFacts?.lineCount;
  const transformations = report.analysis.passes.reduce(
    (sum, pass) => sum + (pass.applied ? pass.edits.length : 0),
    0,
  );
  const evidence = (selectedDetection?.evidence ?? []).map((item) => ({
    rule: item.id,
    label: item.description,
    detail: item.description,
    matched: item.polarity === "positive",
    weight: item.weight,
  }));

  return {
    jobId: report.jobId,
    status: rendererStatus,
    readableKind: report.analysis.readableKind ?? "source-code",
    input: {
      path: inputPath,
      name: report.input.fileName,
      size: report.input.byteLength,
      ...(inputLineCount === undefined ? {} : { lineCount: inputLineCount }),
      sha256: report.input.sha256,
      dialect: report.input.classification.dialect,
    },
    inputSha256: report.input.sha256,
    detection: {
      pluginId: report.selectedPlugin.id,
      pluginName: report.selectedPlugin.name,
      confidence:
        selectedDetection?.confidence ??
        report.input.classification.confidence,
      evidence,
    },
    artifacts: loaded.artifacts,
    statistics: {
      ...(functionCount === undefined ? {} : { functions: functionCount }),
      ...(recovery === undefined && hasCurrentJnkieProfile
        ? {
            prototypeSummaries: 371,
            topIrRows: 1_409,
          }
        : {}),
      ...(recovery === undefined
        ? {}
        : {
            recordSections: recovery.recordSections,
            prototypes: recovery.prototypes,
            instructions: recovery.instructions,
            constants: recovery.constants,
            constantReferences: recovery.constantReferences,
            stringReferences: recovery.stringReferences,
            childReferences: recovery.childReferences,
            resolvedChildReferences: recovery.resolvedChildReferences,
            decodedBytes: recovery.decodedBytes,
            unresolvedBytes: recovery.unresolvedBytes,
            outerRootPrototype: recovery.outerRootPrototype,
            nestedRootPrototype: recovery.nestedRootPrototype,
            semanticInstructions: recovery.semanticInstructions,
            protocolInstructions: recovery.protocolInstructions,
            unknownInstructions: recovery.unknownInstructions,
            semanticCoverageRatio: recovery.semanticCoverageRatio,
          }),
      transformations,
      unresolved: recovery?.unknownInstructions ?? warningCount,
      warnings: warningCount,
      durationMs: Math.max(0, Math.round(durationMs)),
    },
    diagnostics,
    validationChecks: [
      {
        id: "core-validation",
        label: "Static validation",
        detail: report.validation.valid
          ? "The selected plugin's static validation checks passed."
          : "One or more static validation checks failed; review diagnostics.",
        status: report.validation.valid ? "passed" : "failed",
      },
      {
        id: "artifact-integrity",
        label: "Artifact integrity",
        detail: artifactIntegrityFailed
          ? "One or more generated artifacts failed bounded path, size, encoding, or SHA-256 verification."
          : artifactPresentationWarning
            ? "Persisted artifact integrity passed, but one or more renderer views were safely omitted because of media-type or bounded output limits."
            : "Generated renderer artifacts passed bounded path, size, encoding, and SHA-256 verification.",
        status: artifactIntegrityFailed
          ? "failed"
          : artifactPresentationWarning
            ? "warning"
            : "passed",
      },
    ],
    stages: makeRendererStages(report, artifactIntegrityFailed),
    summary: artifactIntegrityFailed
      ? "Generated artifact integrity failed; the result is not presented as verified."
      : makeSummary(report),
  };
}

export async function loadRendererArtifacts(
  brokerResult: PersistedBrokerAnalysisResult,
  limits: Readonly<ArtifactReadLimits> = DEFAULT_RENDERER_ARTIFACT_LIMITS,
): Promise<LoadedArtifacts> {
  assertArtifactLimits(limits);
  const artifacts: MutableArtifacts = {};
  const diagnostics: RendererDiagnostic[] = [];
  const jobDirectory = brokerResult.writtenJob.jobDirectory;
  let realJobDirectory: string;
  try {
    realJobDirectory = await realpath(jobDirectory);
  } catch {
    return {
      artifacts: withSynthesizedFallbacks(
        artifacts,
        brokerResult,
        limits,
        diagnostics,
        0,
      ),
      diagnostics: [
        {
          code: "DESKTOP_JOB_DIRECTORY_UNAVAILABLE",
          severity: "error",
          stage: "desktop-broker",
          message: "The generated job directory could not be opened safely.",
        },
        ...diagnostics,
      ],
    };
  }

  let totalBytes = 0;
  for (const record of brokerResult.writtenJob.manifest.artifacts) {
    const key = artifactKeyForRecord(
      record,
      brokerResult.analysis.report.input.classification.isText,
    );
    if (key === null || artifacts[key] !== undefined) {
      continue;
    }
    if (!isRenderableTextMediaType(record.mediaType)) {
      if (record.role !== "original") {
        diagnostics.push(
          artifactDiagnostic(
            "DESKTOP_ARTIFACT_MEDIA_REJECTED",
            record,
            `Artifact ${record.fileName} was not exposed because its media type is not textual.`,
          ),
        );
      }
      continue;
    }
    if (
      !Number.isSafeInteger(record.byteLength) ||
      record.byteLength < 0 ||
      record.byteLength > limits.maxArtifactBytes
    ) {
      diagnostics.push(
        artifactDiagnostic(
          "DESKTOP_ARTIFACT_SIZE_LIMIT",
          record,
          `Artifact ${record.fileName} exceeds the renderer's ${limits.maxArtifactBytes}-byte per-file limit.`,
        ),
      );
      continue;
    }
    if (totalBytes + record.byteLength > limits.maxTotalBytes) {
      diagnostics.push(
        artifactDiagnostic(
          "DESKTOP_ARTIFACT_TOTAL_LIMIT",
          record,
          `Artifact ${record.fileName} would exceed the renderer's ${limits.maxTotalBytes}-byte total limit.`,
        ),
      );
      continue;
    }

    const candidate = resolveArtifactFilePath(
      jobDirectory,
      record.fileName,
    );
    if (candidate === null) {
      diagnostics.push(
        artifactDiagnostic(
          "DESKTOP_ARTIFACT_PATH_REJECTED",
          record,
          `Artifact ${record.fileName} has an unsafe manifest path.`,
        ),
      );
      continue;
    }

    let realCandidate: string;
    try {
      realCandidate = await realpath(candidate);
    } catch {
      diagnostics.push(
        artifactDiagnostic(
          "DESKTOP_ARTIFACT_MISSING",
          record,
          `Artifact ${record.fileName} is missing from the generated job.`,
        ),
      );
      continue;
    }
    if (!isPathWithin(realJobDirectory, realCandidate)) {
      diagnostics.push(
        artifactDiagnostic(
          "DESKTOP_ARTIFACT_PATH_REJECTED",
          record,
          `Artifact ${record.fileName} resolves outside the generated job directory.`,
        ),
      );
      continue;
    }

    try {
      const bytes = await readCappedFile(
        realCandidate,
        record.byteLength,
        limits.maxArtifactBytes,
      );
      if (!verifyArtifactSha256(bytes, record.sha256)) {
        throw new Error("SHA-256 does not match the artifact manifest");
      }
      const text = UTF8_FATAL_DECODER.decode(bytes);
      artifacts[key] = text;
      totalBytes += bytes.byteLength;
    } catch (error) {
      diagnostics.push(
        artifactDiagnostic(
          "DESKTOP_ARTIFACT_READ_REJECTED",
          record,
          error instanceof Error
            ? `Artifact ${record.fileName} was not exposed: ${error.message}`
            : `Artifact ${record.fileName} could not be read safely.`,
        ),
      );
    }
  }

  return {
    artifacts: withSynthesizedFallbacks(
      artifacts,
      brokerResult,
      limits,
      diagnostics,
      totalBytes,
    ),
    diagnostics,
  };
}

export async function readCappedFile(
  filePath: string,
  expectedBytes: number,
  maximumBytes: number,
): Promise<Uint8Array> {
  if (
    !Number.isSafeInteger(expectedBytes) ||
    expectedBytes < 0 ||
    !Number.isSafeInteger(maximumBytes) ||
    maximumBytes <= 0 ||
    expectedBytes > maximumBytes
  ) {
    throw new Error("declared size is outside the configured read cap");
  }

  const handle = await open(filePath, "r");
  try {
    const metadata = await handle.stat();
    if (!metadata.isFile()) {
      throw new Error("path is not a regular file");
    }
    if (
      metadata.size !== expectedBytes ||
      metadata.size > maximumBytes
    ) {
      throw new Error("file size does not match its bounded manifest entry");
    }
    const buffer = Buffer.alloc(metadata.size);
    let offset = 0;
    while (offset < buffer.length) {
      const { bytesRead } = await handle.read(
        buffer,
        offset,
        buffer.length - offset,
        offset,
      );
      if (bytesRead === 0) {
        throw new Error("file ended before its declared size");
      }
      offset += bytesRead;
    }
    const probe = Buffer.alloc(1);
    const { bytesRead: extraBytes } = await handle.read(
      probe,
      0,
      1,
      offset,
    );
    if (extraBytes !== 0) {
      throw new Error("file grew beyond its declared size");
    }
    return Uint8Array.from(buffer);
  } finally {
    await handle.close();
  }
}

export function isRenderableTextMediaType(mediaType: string): boolean {
  const normalized = mediaType.split(";", 1)[0]?.trim().toLowerCase();
  return (
    normalized?.startsWith("text/") === true ||
    normalized === "application/json"
  );
}

function artifactKeyForRecord(
  record: ArtifactRecord,
  inputIsText: boolean,
): ArtifactKey | null {
  const role = record.role as string;
  if (role === "extracted-payload" && record.fileName === "jnkie-payload-report.md") {
    return "payloadReport";
  }
  if (role === "extracted-payload" && record.fileName === "jnkie-records-readable.txt") {
    return "decodedRecords";
  }
  switch (role) {
    case "original":
    case "exact":
      return inputIsText ? "original" : null;
    case "readable":
      return "readable";
    case "exact-audit":
      return "exactAudit";
    case "disassembly":
      return "exactAudit";
    case "behavior-report":
      return "behaviorReport";
    case "validation-report":
      return "validationReport";
    case "warnings":
      return "warnings";
    case "report":
      return "reportJson";
    default:
      return null;
  }
}

function withSynthesizedFallbacks(
  existing: MutableArtifacts,
  brokerResult: PersistedBrokerAnalysisResult,
  limits: Readonly<ArtifactReadLimits>,
  diagnostics: RendererDiagnostic[],
  initialTotalBytes: number,
): RendererArtifacts {
  const artifacts: MutableArtifacts = { ...existing };
  const analysis = brokerResult.analysis;
  const report = analysis.report;
  let totalBytes = initialTotalBytes;

  const addText = (key: ArtifactKey, text: string | undefined): void => {
    if (artifacts[key] !== undefined || text === undefined) {
      return;
    }
    const byteLength = Buffer.byteLength(text, "utf8");
    if (
      byteLength > limits.maxArtifactBytes ||
      totalBytes + byteLength > limits.maxTotalBytes
    ) {
      diagnostics.push({
        code: "DESKTOP_SYNTHESIZED_ARTIFACT_LIMIT",
        severity: "warning",
        stage: "desktop-broker",
        message: `The ${key} view was omitted because it exceeds renderer output limits.`,
      });
      return;
    }
    artifacts[key] = text;
    totalBytes += byteLength;
  };

  addText("readable", report.analysis.readableSource);
  addText(
    "exactAudit",
    report.input.classification.isText
      ? artifacts.original
      : report.analysis.bytecode?.disassembly,
  );
  addText("behaviorReport", renderBehaviorReport(report));
  addText("validationReport", renderValidationReport(report));
  addText("warnings", renderWarnings(report));
  addText("reportJson", `${JSON.stringify(report, null, 2)}\n`);
  return artifacts;
}

function renderBehaviorReport(report: AnalysisReport): string {
  const inventory = report.analysis.behavior;
  const serializedInventory =
    inventory?.evidenceSource === "serialized-string-inventory";
  const locationLabel = serializedInventory ? "row(s)" : "line(s)";
  const introduction = serializedInventory
    ? "Reachability was not evaluated. Findings come from decoded string/constant inventory; row numbers refer to jnkie-known-all-strings.tsv, not source lines."
    : "Reachability was not evaluated. Findings are visible source-code references only.";

  const lines = [
    "# Static behavior inventory",
    "",
    introduction,
    "",
  ];
  if (inventory === undefined || inventory.capabilities.length === 0) {
    lines.push("No configured capability API references were found.", "");
  } else {
    for (const finding of inventory.capabilities) {
      lines.push(
        `- ${finding.category} / ${finding.api}: ${finding.occurrences} occurrence(s), ${locationLabel} ${finding.lines.join(", ")}`,
      );
    }
    lines.push("");
  }
  for (const finding of inventory?.urls ?? []) {
    lines.push(`- URL at ${serializedInventory ? "row" : "line"} ${finding.line}: ${finding.url}`);
  }
  return lines.join("\n");
}

function renderValidationReport(report: AnalysisReport): string {
  const lines = [
    "# Validation report",
    "",
    `Result: ${report.validation.valid ? "passed" : "failed"}`,
    "",
  ];
  for (const diagnostic of report.validation.diagnostics) {
    lines.push(
      `- ${diagnostic.severity.toUpperCase()} ${diagnostic.code}: ${diagnostic.message}`,
    );
  }
  return lines.join("\n");
}

function renderWarnings(report: AnalysisReport): string {
  const warnings = report.diagnostics.filter(
    (diagnostic) => diagnostic.severity !== "info",
  );
  if (warnings.length === 0) {
    return [
      "# 3ziz Deobfuscator warnings",
      "",
      "No warnings or errors were reported.",
      "",
    ].join("\n");
  }
  return [
    "# 3ziz Deobfuscator warnings",
    "",
    ...warnings.map(
      (diagnostic) =>
        `- ${diagnostic.severity.toUpperCase()} ${diagnostic.code}: ${diagnostic.message}`,
    ),
    "",
  ].join("\n");
}

function mapCoreDiagnostic(diagnostic: CoreDiagnostic): RendererDiagnostic {
  return {
    code: diagnostic.code,
    severity: diagnostic.severity,
    stage: diagnostic.stage,
    message: diagnostic.message,
    ...(diagnostic.evidence === undefined
      ? {}
      : { evidence: [...diagnostic.evidence] }),
    ...(diagnostic.suggestedAction === undefined
      ? {}
      : { suggestedAction: diagnostic.suggestedAction }),
  };
}

function artifactDiagnostic(
  code: string,
  record: ArtifactRecord,
  message: string,
): RendererDiagnostic {
  return {
    code,
    severity: "warning",
    stage: "desktop-broker",
    message,
    location: record.fileName,
  };
}

function makeRendererStages(
  report: AnalysisReport,
  artifactIntegrityFailed = false,
): RendererAnalysisResult["stages"] {
  const unsupported = report.status === "unsupported";
  const failed =
    report.status === "failed-validation" || artifactIntegrityFailed;
  const isMoonSec = report.selectedPlugin.family === "moonsec-v3";
  const isLuraphAudit = report.selectedPlugin.family === "luraph-audit";
  const isJnkie = report.selectedPlugin.family === "jnkie-luraph";
  const recovery = report.analysis.jnkieRecovery;
  const hasCurrentJnkieProfile =
    isJnkie &&
    hasDiagnosticCode(report, JNKIE_CURRENT_STREAM_PROFILE_CODE);
  const isBytecode =
    report.input.classification.kind === "lua-bytecode";
  const hasReadable = report.analysis.readableSource !== undefined;
  const appliedPasses = report.analysis.passes.filter(
    (pass) => pass.applied && pass.edits.length > 0,
  ).length;
  const hasWarnings = report.diagnostics.some(
    (diagnostic) => diagnostic.severity !== "info",
  );
  const extractionStatus =
    isJnkie ? "complete" : isMoonSec ? "warning" : isBytecode ? "complete" : "skipped";
  const reconstructionStatus =
    recovery !== undefined
      ? recovery.unknownInstructions > 0 || recovery.unresolvedBytes > 0
        ? "warning"
        : "complete"
      : hasCurrentJnkieProfile
      ? "warning"
      : hasReadable ? "complete" : isMoonSec || isLuraphAudit ? "skipped" : "skipped";
  const simplifyStatus =
    recovery !== undefined
      ? recovery.unknownInstructions > 0
        ? "warning"
        : "complete"
      : hasCurrentJnkieProfile
      ? "warning"
      : appliedPasses > 0 ? "complete" : "skipped";
  return [
    {
      id: "ingesting",
      label: "Import & hash",
      status: "complete",
      detail: "The original bytes were preserved and hashed.",
    },
    {
      id: "fingerprinting",
      label: "Fingerprint",
      status: "complete",
      detail: `Selected ${report.selectedPlugin.name}.`,
    },
    {
      id: "extracting",
      label: "Extract",
      status: unsupported ? "skipped" : extractionStatus,
      detail: isMoonSec
        ? "The reviewed MoonSec extractor is not installed; the wrapper was preserved only."
        : isJnkie
          ? "The paired JNKIE streams were decoded, preserved, and inspected across every recovered byte without execution."
        : isBytecode
          ? "The bytecode structure was decoded into an exact static audit."
          : "No extraction stage was required for this source/audit route.",
    },
    {
      id: "reconstructing",
      label: "Reconstruct",
      status: unsupported ? "skipped" : reconstructionStatus,
      detail: recovery !== undefined
        ? `Decoded ${recovery.recordSections} record sections with ${recovery.prototypes.toLocaleString("en-US")} prototypes and ${recovery.instructions.toLocaleString("en-US")} instructions; ${recovery.semanticInstructions.toLocaleString("en-US")} instructions have proven direct semantics and every remaining record retains raw provenance.`
        : hasCurrentJnkieProfile
          ? "Exact current-stream inventory is available: 371 prototype summary records and 1,409 top-prototype raw IR rows; high-level payload source was not reconstructed."
        : hasReadable
          ? isJnkie
            ? "The recovered VM loader was formatted token-for-token; payload source reconstruction was not claimed."
            : "A readable artifact was produced from evidence-backed transformations."
          : "No high-level source reconstruction was claimed.",
    },
    {
      id: "simplifying",
      label: "Simplify",
      status: unsupported ? "skipped" : simplifyStatus,
      detail:
        recovery !== undefined
          ? `${recovery.protocolInstructions.toLocaleString("en-US")} decoder-protocol and ${recovery.unknownInstructions.toLocaleString("en-US")} unproven instruction records remain explicit; no names or effects were guessed.`
          : hasCurrentJnkieProfile
          ? "No proof-gated high-level simplification was applied to the current payload."
          : appliedPasses > 0
          ? `${appliedPasses} proof-gated pass(es) produced edits.`
          : "No proof-gated simplification edits were applied.",
    },
    {
      id: "validating",
      label: "Validate",
      status: failed
        ? "error"
        : unsupported
          ? "skipped"
          : hasWarnings
            ? "warning"
            : "complete",
      detail: report.validation.valid
        ? recovery !== undefined
          ? `Both record sections, all ${recovery.childReferences.toLocaleString("en-US")} child references, complete artifact hashes, and exact EOF coverage were checked without executing submitted code; ${recovery.unresolvedBytes.toLocaleString("en-US")} interstitial byte(s) remain deliberately untyped.`
          : hasCurrentJnkieProfile
          ? "Current-stream dual-hash, packaged asset SHA-256, prototype inventory, top-IR, whole-buffer, and token-preservation gates passed; high-level source recovery was not asserted."
          : isJnkie
            ? "Static extraction, token preservation, and whole-buffer coverage gates passed; payload source recovery was not asserted."
            : "Static validation completed; it does not assert lost source recovery."
        : "Static validation reported errors.",
    },
    {
      id: "emitting",
      label: "Emit",
      status: "complete",
      detail: "A non-overwriting job bundle was created.",
    },
  ];
}

function makeSummary(report: AnalysisReport): string {
  if (report.selectedPlugin.family === "jnkie-luraph") {
    const recovery = report.analysis.jnkieRecovery;
    if (recovery !== undefined) {
      return `Decoded ${recovery.recordSections} JNKIE record sections end to end: ${recovery.prototypes.toLocaleString("en-US")} prototypes, ${recovery.instructions.toLocaleString("en-US")} instructions, and ${recovery.constants.toLocaleString("en-US")} constants. Proven semantics cover ${(recovery.semanticCoverageRatio * 100).toFixed(1)}% of instruction records; ${recovery.unknownInstructions.toLocaleString("en-US")} records and ${recovery.unresolvedBytes.toLocaleString("en-US")} interstitial byte(s) remain explicit rather than guessed.`;
    }
    return hasDiagnosticCode(report, JNKIE_CURRENT_STREAM_PROFILE_CODE)
      ? "Exact current-stream inventory matched: 371 prototype summary records and 1,409 top-prototype raw IR rows are available; high-level payload source was not reconstructed."
      : "JNKIE loader and payload streams were extracted and fully scanned locally; payload source reconstruction is still unknown.";
  }
  if (report.selectedPlugin.family === "moonsec-v3") {
    return "MoonSec evidence was recorded, but no reviewed extractor is installed; no recovered source is claimed.";
  }
  if (report.selectedPlugin.family === "luraph-audit") {
    return "The Luraph audit structure was checked statically; this is an audit result, not recovered executable source.";
  }
  if (report.input.classification.kind === "lua-bytecode") {
    return report.status === "failed-validation"
      ? "The Lua 5.1 chunk failed structural validation."
      : "Lua 5.1 structure was validated and disassembled; no high-level source recovery is claimed.";
  }
  switch (report.status) {
    case "verified":
      return report.analysis.readableSource === undefined
        ? "Static validation completed; this status does not claim restoration of lost source."
        : "Static analysis completed with an evidence-backed readable artifact.";
    case "recovered-with-warnings":
      return "An evidence-backed readable artifact was produced with warnings and explicit unknowns.";
    case "partial":
      return "Static analysis is partial; review unsupported stages and diagnostics before using the output.";
    case "unsupported":
      return "The input was preserved and audited, but no safe static recovery route was supported.";
    case "failed-validation":
      return "Analysis completed, but validation failed; no uncertain reconstruction is presented as verified.";
    case "cancelled":
      return "Analysis was cancelled before completion.";
  }
}

function assertArtifactLimits(limits: Readonly<ArtifactReadLimits>): void {
  if (
    !Number.isSafeInteger(limits.maxArtifactBytes) ||
    limits.maxArtifactBytes <= 0 ||
    !Number.isSafeInteger(limits.maxTotalBytes) ||
    limits.maxTotalBytes <= 0 ||
    limits.maxArtifactBytes > limits.maxTotalBytes
  ) {
    throw new Error("Renderer artifact limits must be positive bounded integers.");
  }
}
