import type {
  AnalysisArtifacts,
  AnalysisResult,
  AnalysisStage,
  AnalysisStatistics,
  DetectionResult,
  Diagnostic,
  ReadableKind,
  ValidationCheck,
} from "./api";

export type ViewStatus =
  | "verified"
  | "partial"
  | "unsupported"
  | "failed"
  | "cancelled"
  | "sample";

export interface JobViewModel {
  jobId: string;
  status: ViewStatus;
  readableKind: ReadableKind;
  input: {
    path?: string | undefined;
    name: string;
    size?: number | undefined;
    lineCount?: number | undefined;
    sha256?: string | undefined;
    dialect?: string | undefined;
  };
  detection: DetectionResult;
  artifacts: AnalysisArtifacts;
  statistics: AnalysisStatistics;
  diagnostics: Diagnostic[];
  validationChecks: ValidationCheck[];
  stages: AnalysisStage[];
  summary?: string | undefined;
}

export const STAGE_DEFINITIONS = [
  {
    id: "ingesting",
    label: "Import & hash",
    description: "Preserve the original bytes",
  },
  {
    id: "fingerprinting",
    label: "Fingerprint",
    description: "Detect dialect and obfuscator",
  },
  {
    id: "extracting",
    label: "Extract",
    description: "Recover static payload artifacts",
  },
  {
    id: "reconstructing",
    label: "Reconstruct",
    description: "Build source and evidence",
  },
  {
    id: "simplifying",
    label: "Simplify",
    description: "Apply conservative AST passes",
  },
  {
    id: "validating",
    label: "Validate",
    description: "Check semantic invariants",
  },
  {
    id: "emitting",
    label: "Emit",
    description: "Write the result bundle",
  },
] as const;

export function normalizeStatus(status?: string): ViewStatus {
  const value = status?.trim().toLowerCase();

  if (
    value === "completed" ||
    value === "complete" ||
    value === "verified" ||
    value === "success"
  ) {
    return "verified";
  }

  if (
    value === "partial" ||
    value === "recovered-with-warnings" ||
    value === "warning" ||
    value === "warnings"
  ) {
    return "partial";
  }

  if (value === "unsupported") {
    return "unsupported";
  }

  if (value === "cancelled" || value === "canceled") {
    return "cancelled";
  }

  if (value === "sample") {
    return "sample";
  }

  return "failed";
}

export function normalizeConfidence(value?: number): number | undefined {
  if (value === undefined || !Number.isFinite(value)) {
    return undefined;
  }

  const normalized = value > 1 ? value / 100 : value;
  return Math.min(1, Math.max(0, normalized));
}

export function formatBytes(value?: number): string {
  if (value === undefined || !Number.isFinite(value) || value < 0) {
    return "—";
  }

  if (value < 1024) {
    return `${Math.round(value)} B`;
  }

  const units = ["KB", "MB", "GB"];
  let amount = value / 1024;
  let unit = units[0];

  for (let index = 1; index < units.length && amount >= 1024; index += 1) {
    amount /= 1024;
    unit = units[index];
  }

  return `${amount >= 10 ? amount.toFixed(1) : amount.toFixed(2)} ${unit}`;
}

export function formatDuration(value?: number): string {
  if (value === undefined || !Number.isFinite(value) || value < 0) {
    return "—";
  }

  if (value < 1000) {
    return `${Math.round(value)} ms`;
  }

  return `${(value / 1000).toFixed(value < 10_000 ? 1 : 0)} s`;
}

export function fileNameFromPath(path?: string): string {
  if (!path) {
    return "Untitled analysis";
  }

  const parts = path.split(/[\\/]/);
  return parts.at(-1) || path;
}

function defaultStages(status: ViewStatus): AnalysisStage[] {
  return STAGE_DEFINITIONS.map((stage, index) => {
    if (status === "verified" || status === "sample") {
      return { id: stage.id, label: stage.label, status: "complete" };
    }

    if (status === "partial") {
      return {
        id: stage.id,
        label: stage.label,
        status: index < 5 ? "complete" : index === 5 ? "warning" : "complete",
      };
    }

    if (status === "unsupported") {
      return {
        id: stage.id,
        label: stage.label,
        status: index < 2 ? "complete" : "skipped",
      };
    }

    return {
      id: stage.id,
      label: stage.label,
      status: index === 0 ? "complete" : index === 1 ? "error" : "skipped",
    };
  });
}

export function normalizeAnalysisResult(
  result: AnalysisResult,
  requestedPath?: string,
): JobViewModel {
  const status = normalizeStatus(result.status);
  const artifacts = result.artifacts ?? result.outputs ?? {};
  const inputPath = result.input?.path ?? requestedPath;
  const diagnostics = result.diagnostics ?? [];
  const warningCount = diagnostics.filter(
    (diagnostic) => diagnostic.severity === "warning",
  ).length;
  const readableKind =
    result.readableKind ??
    (result.detection?.pluginId === "jnkie-luraph-14-static"
      ? "vm-loader"
      : "source-code");

  return {
    jobId: result.jobId,
    status,
    readableKind,
    input: {
      path: inputPath,
      name: result.input?.name ?? fileNameFromPath(inputPath),
      size: result.input?.size,
      lineCount: result.input?.lineCount,
      sha256: result.input?.sha256 ?? result.inputSha256,
      dialect: result.input?.dialect,
    },
    detection: {
      ...result.detection,
      confidence: normalizeConfidence(result.detection?.confidence),
    },
    artifacts,
    statistics: {
      ...result.statistics,
      warnings: result.statistics?.warnings ?? warningCount,
    },
    diagnostics,
    validationChecks: result.validationChecks ?? [],
    stages:
      result.stages && result.stages.length > 0
        ? result.stages
        : defaultStages(status),
    summary: result.summary,
  };
}

const sampleOriginal = `-- Safe built-in preview. No local file is read.
local message = "he" .. "llo"

local function pairWithMessage(firstValue, ...)
    return firstValue, message
end

print(pairWithMessage("3ziz"))
`;

const sampleReadable = `-- Safe built-in preview. No local file is read.
local message = "hello"

local function pairWithMessage(firstValue, ...)
    return firstValue, message
end

print(pairWithMessage("3ziz"))
`;

const sampleAudit = sampleOriginal;

const sampleBehavior = `# Behavior report

## Summary

This small sample concatenates two literal strings, preserves an open vararg
list, and writes two values through the global \`print\` function.

## Observed capabilities

- Global reads: \`string\`, \`print\`
- Network operations: none observed
- File operations: none observed
- Process operations: none observed
- Persistent changes: none observed

## Confidence and unknowns

All reachable statements in this synthetic sample were reconstructed. This
preview is not evidence about any user file.
`;

const sampleValidation = `VALIDATION SUMMARY

[PASS] Input and output parse as Lua
[PASS] Function and vararg-function counts preserved
[PASS] Call count and register-identifier facts preserved
[PASS] Literal concatenation contains only proven short-string operands
[PASS] Readable output reparsed after the exact-range edit

Result: Verified synthetic preview
`;

export function createSampleJob(): JobViewModel {
  return {
    jobId: "sample-preview",
    status: "sample",
    readableKind: "source-code",
    input: {
      name: "sample-obfuscated.lua",
      size: sampleOriginal.length,
      lineCount: sampleOriginal.split("\n").length,
      dialect: "Lua 5.1",
    },
    detection: {
      pluginId: "generic",
      pluginName: "Generic Lua",
      confidence: 0.94,
      evidence: [
        {
          rule: "lua.parse",
          detail: "Source parsed successfully as Lua 5.1.",
          matched: true,
          weight: 0.55,
        },
        {
          rule: "literal.concat",
          detail: "A literal-only concatenation is safe to fold exactly.",
          matched: true,
          weight: 0.39,
        },
      ],
    },
    artifacts: {
      original: sampleOriginal,
      readable: sampleReadable,
      exactAudit: sampleAudit,
      behaviorReport: sampleBehavior,
      validationReport: sampleValidation,
      warnings: "",
    },
    statistics: {
      functions: 1,
      strings: 2,
      stringsPreserved: 2,
      transformations: 1,
      unresolved: 0,
      warnings: 0,
      durationMs: 184,
    },
    diagnostics: [
      {
        code: "SAMPLE_PREVIEW",
        severity: "info",
        stage: "renderer",
        message: "This is a built-in UI preview. No local source was analyzed.",
      },
    ],
    validationChecks: [
      {
        id: "parse",
        label: "Source parses",
        detail: "Original and readable output parse as Lua.",
        status: "passed",
      },
      {
        id: "strings",
        label: "Strings preserved",
        detail: "The same five string bytes are represented after folding.",
        status: "passed",
      },
      {
        id: "varargs",
        label: "Varargs preserved",
        detail: "Open argument and return-list semantics remain intact.",
        status: "passed",
      },
    ],
    stages: defaultStages("sample"),
    summary:
      "A small synthetic fixture demonstrating evidence-backed reconstruction.",
  };
}




