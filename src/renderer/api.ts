export type AnalysisStatus =
  | "queued"
  | "running"
  | "completed"
  | "verified"
  | "recovered-with-warnings"
  | "partial"
  | "unsupported"
  | "failed"
  | "failed-validation"
  | "cancelled"
  | string;

export type DiagnosticSeverity = "info" | "warning" | "error";

export interface DetectionEvidence {
  rule?: string;
  label?: string;
  detail?: string;
  matched?: boolean;
  weight?: number;
}

export interface DetectionResult {
  pluginId?: string;
  pluginName?: string;
  confidence?: number | undefined;
  evidence?: DetectionEvidence[];
}

export interface AnalysisInput {
  path?: string;
  name?: string;
  size?: number;
  lineCount?: number;
  sha256?: string;
  dialect?: string;
}

export interface AnalysisArtifacts {
  original?: string;
  readable?: string;
  decodedRecords?: string;
  exactAudit?: string;
  behaviorReport?: string;
  payloadReport?: string;
  validationReport?: string;
  warnings?: string;
  reportJson?: string;
}

export interface AnalysisStatistics {
  functions?: number;
  strings?: number;
  stringsPreserved?: number;
  prototypeSummaries?: number;
  topIrRows?: number;
  recordSections?: number;
  prototypes?: number;
  instructions?: number;
  constants?: number;
  constantReferences?: number;
  stringReferences?: number;
  childReferences?: number;
  resolvedChildReferences?: number;
  decodedBytes?: number;
  unresolvedBytes?: number;
  outerRootPrototype?: number;
  nestedRootPrototype?: number;
  semanticInstructions?: number;
  protocolInstructions?: number;
  unknownInstructions?: number;
  semanticCoverageRatio?: number;
  transformations?: number;
  unresolved?: number;
  warnings?: number;
  durationMs?: number;
}

export type ReadableKind =
  | "source-code"
  /** Lua reconstructed from proven VM opcode effects; local names synthesized. */
  | "devirtualized-lua"
  | "vm-loader"
  | "register-pseudocode";

export interface Diagnostic {
  code?: string;
  severity?: DiagnosticSeverity;
  stage?: string;
  message: string;
  evidence?: string[];
  suggestedAction?: string;
  location?: string;
}

export interface ValidationCheck {
  id?: string;
  label: string;
  detail?: string;
  status: "passed" | "warning" | "failed" | "not-run";
}

export interface AnalysisStage {
  id: string;
  label?: string;
  status?: "queued" | "active" | "complete" | "warning" | "skipped" | "error";
  detail?: string;
}

export interface AnalysisResult {
  jobId: string;
  status: AnalysisStatus;
  readableKind?: ReadableKind;
  input?: AnalysisInput;
  inputSha256?: string;
  detection?: DetectionResult;
  artifacts?: AnalysisArtifacts;
  outputs?: AnalysisArtifacts;
  statistics?: AnalysisStatistics;
  diagnostics?: Diagnostic[];
  validationChecks?: ValidationCheck[];
  stages?: AnalysisStage[];
  summary?: string;
}

export interface AnalysisProgressEvent {
  jobId?: string;
  stage?: string;
  status?: string;
  percent?: number;
  message?: string;
  inputPath?: string;
}

export interface ProgressAcceptanceContext {
  accepting: boolean;
  expectedInputPath: string | undefined;
  activeJobId: string | undefined;
  retiredJobIds: ReadonlySet<string>;
}

function normalizedProgressPath(value: string): string {
  return value.replace(/\//g, "\\").toLocaleLowerCase("en-US");
}

/**
 * Progress may arrive after a prior run has settled. Require both the current
 * input path and a non-retired job ID before an event can capture an empty
 * active-job slot.
 */
export function shouldAcceptProgressEvent(
  event: AnalysisProgressEvent,
  context: ProgressAcceptanceContext,
): boolean {
  if (
    !context.accepting ||
    event.jobId === undefined ||
    event.inputPath === undefined ||
    context.expectedInputPath === undefined ||
    context.retiredJobIds.has(event.jobId) ||
    normalizedProgressPath(event.inputPath) !==
      normalizedProgressPath(context.expectedInputPath)
  ) {
    return false;
  }
  return (
    context.activeJobId === undefined ||
    context.activeJobId === event.jobId
  );
}

export type CancelJobOutcome =
  | {
      outcome: "cancelled";
    }
  | {
      outcome: "already-complete";
    };

/** Waits for an in-flight cancellation decision before exposing a result. */
export async function cancellationAllowsCompletedResult(
  cancellation: Promise<CancelJobOutcome> | undefined,
): Promise<boolean> {
  if (cancellation === undefined) {
    return true;
  }
  try {
    return (await cancellation).outcome === "already-complete";
  } catch {
    return false;
  }
}

export type ChosenFile =
  | string
  | {
      path: string;
      name?: string;
    }
  | null;

export type ExportResult =
  | string
  | {
      path?: string;
      cancelled?: boolean;
    }
  | null
  | void;

export interface DeobfuscatorApi {
  chooseFile(): Promise<ChosenFile>;
  getPathForFile?(file: File): string;
  analyzeFile(path: string): Promise<AnalysisResult>;
  exportJob(jobId: string): Promise<ExportResult>;
  cancelJob(jobId: string): Promise<CancelJobOutcome>;
  onProgress(
    callback: (event: AnalysisProgressEvent) => void,
  ): void | (() => void);
}

declare global {
  interface Window {
    deobfuscator?: DeobfuscatorApi;
  }
}

export {};


