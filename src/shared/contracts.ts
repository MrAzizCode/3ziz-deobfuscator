export const ANALYSIS_SCHEMA_VERSION = 1 as const;

export type JobStatus =
  | "verified"
  | "recovered-with-warnings"
  | "partial"
  | "unsupported"
  | "failed-validation"
  | "cancelled";

export type DiagnosticSeverity = "info" | "warning" | "error";

export interface Diagnostic {
  readonly code: string;
  readonly severity: DiagnosticSeverity;
  readonly stage: string;
  readonly message: string;
  readonly evidence?: readonly string[];
  readonly suggestedAction?: string;
}

export type InputKind =
  | "lua-source"
  | "luau-source"
  | "lua-bytecode"
  | "vm-audit-ir"
  | "text"
  | "binary";

export type LuaDialect = "lua-5.1" | "luau" | "vm-ir" | "unknown";

export interface SourceClassification {
  readonly kind: InputKind;
  readonly dialect: LuaDialect;
  readonly confidence: number;
  readonly isText: boolean;
  readonly reasons: readonly string[];
}

export interface DetectionEvidence {
  readonly id: string;
  readonly description: string;
  readonly weight: number;
  readonly polarity: "positive" | "negative";
  readonly occurrences?: number;
}

export interface DetectionResult {
  readonly pluginId: string;
  readonly confidence: number;
  readonly evidence: readonly DetectionEvidence[];
}

export type PluginFamily =
  | "generic"
  | "moonsec-v3"
  | "luraph-audit"
  | "jnkie-luraph";

export interface ExtractedArtifact {
  readonly fileName: string;
  readonly mediaType: string;
  readonly bytes: Uint8Array;
  readonly sha256: string;
}

export interface PluginManifest {
  readonly id: string;
  readonly name: string;
  readonly version: string;
  readonly family: PluginFamily;
  readonly description: string;
  readonly supportedKinds: readonly InputKind[];
  readonly authoritative: boolean;
}

export interface DetectionContext {
  readonly fileName: string;
  readonly bytes: Uint8Array;
  readonly text?: string;
  readonly classification: SourceClassification;
}

export interface AnalysisContext extends DetectionContext {
  readonly inputSha256: string;
  readonly selectedDetection: DetectionResult;
  readonly limits: AnalysisLimits;
  readonly extractedArtifacts?: readonly ExtractedArtifact[];
}

export interface ValidationContext extends AnalysisContext {
  readonly analysis: PluginAnalysis;
}

export interface AnalysisLimits {
  readonly maxInputBytes: number;
  readonly maxOutputBytes: number;
  readonly maxAstNodes: number;
}

export interface StagePlanEntry {
  readonly id: string;
  readonly description: string;
  readonly authoritative: boolean;
}

export interface StagePlan {
  readonly pluginId: string;
  readonly stages: readonly StagePlanEntry[];
}

export interface ValidationReport {
  readonly valid: boolean;
  readonly diagnostics: readonly Diagnostic[];
}

export interface StructuralFacts {
  readonly sha256: string;
  readonly byteLength: number;
  readonly lineCount: number;
  readonly astNodeCount: number;
  readonly functionCount: number;
  readonly callCount: number;
  readonly varargCount: number;
  readonly registerIdentifierOccurrences: number;
  readonly uniqueRegisterIdentifiers: number;
}

export type ParseMode =
  | "lua-5.1-ast"
  /** Parsed by the in-tree Luau front end after Lua 5.1 rejected the source. */
  | "luau-ast"
  | "luau-static-fallback"
  | "vm-ir"
  | "unparsed";

export interface LuaParseFacts extends StructuralFacts {
  readonly mode: ParseMode;
  readonly parsed: boolean;
  readonly syntaxError?: string;
  readonly luauMarkers: readonly string[];
  readonly vmIrMarkers: readonly string[];
}

export type CapabilityCategory =
  | "dynamic-code"
  | "executor-hook"
  | "filesystem"
  | "network"
  | "clipboard"
  | "environment"
  | "debug-introspection"
  | "roblox-remote";

export interface CapabilityFinding {
  readonly category: CapabilityCategory;
  readonly api: string;
  readonly occurrences: number;
  readonly lines: readonly number[];
}

export interface UrlFinding {
  readonly url: string;
  readonly scheme: "http" | "https";
  readonly line: number;
}

export interface BehaviorInventory {
  readonly reachability: "not-evaluated";
  readonly evidenceSource?: "source-code" | "serialized-string-inventory";
  readonly capabilities: readonly CapabilityFinding[];
  readonly urls: readonly UrlFinding[];
}

export interface LuraphFunctionFacts {
  readonly name: string;
  readonly decodedInstructions?: number;
  readonly reachableInstructions?: number;
  readonly appliedPatches?: number;
  readonly omittedInstructions?: number;
  readonly labelDefinitions: number;
  readonly gotoReferences: number;
  readonly duplicateLabels: readonly string[];
  readonly unresolvedTargets: readonly string[];
}

export interface LuraphAuditFacts {
  readonly functionCount: number;
  readonly decodedInstructions: number;
  readonly reachableInstructions: number;
  readonly omittedInstructions: number;
  readonly deterministicPatches: number;
  readonly ambiguousDecoderWrites: number;
  readonly labelDefinitions: number;
  readonly gotoReferences: number;
  readonly vmFragments: number;
  readonly functions: readonly LuraphFunctionFacts[];
  readonly summaryMatchesMetadata: boolean;
  readonly nonExecutableReasons: readonly string[];
}

export interface SourceEdit {
  readonly start: number;
  readonly end: number;
  readonly replacement: string;
  readonly reason: string;
}

export interface SourcePassRecord {
  readonly id: string;
  readonly version: string;
  readonly applied: boolean;
  readonly confidence: number;
  readonly edits: readonly SourceEdit[];
  readonly factsBefore: StructuralFacts;
  readonly factsAfter: StructuralFacts;
  readonly diagnostics: readonly Diagnostic[];
}

export interface BytecodeAnalysisSummary {
  readonly valid: boolean;
  readonly version?: number;
  readonly format?: number;
  readonly instructionCount?: number;
  readonly prototypeCount?: number;
  readonly disassembly?: string;
}

/** Describes what the Readable pane contains so the UI never labels IR as source. */
export type ReadableKind =
  | "source-code"
  /** Lua reconstructed from proven VM opcode effects; local names synthesized. */
  | "devirtualized-lua"
  | "vm-loader"
  | "register-pseudocode";

export interface JnkieRecoverySectionFacts {
  readonly index: number;
  readonly kind: "outer-loader" | "nested-payload";
  readonly byteStart: number;
  readonly byteEnd: number;
  readonly decodedBytes: number;
  readonly wrappedConstants: boolean;
  readonly constants: number;
  readonly prototypes: number;
  readonly instructions: number;
  readonly captures: number;
  readonly constantReferences: number;
  readonly stringReferences: number;
  readonly resolvedConstantReferences: number;
  readonly childReferences: number;
  readonly resolvedChildReferences: number;
  readonly rootPrototype: number;
  readonly rootInstructions: number;
}

/**
 * Compact, JSON-safe facts derived from the bounded JNKIE record decoder.
 * The full typed records stay in exported artifacts rather than report.json.
 */
export interface JnkieRecoveryFacts {
  readonly schemaVersion: 1;
  readonly recordSections: number;
  readonly prototypes: number;
  readonly instructions: number;
  readonly constants: number;
  readonly constantReferences: number;
  readonly stringReferences: number;
  readonly resolvedConstantReferences: number;
  readonly childReferences: number;
  readonly resolvedChildReferences: number;
  readonly decodedBytes: number;
  readonly unresolvedBytes: number;
  readonly outerRootPrototype: number;
  readonly nestedRootPrototype: number;
  readonly semanticInstructions: number;
  readonly protocolInstructions: number;
  readonly unknownInstructions: number;
  readonly semanticCoverageRatio: number;
  readonly explainedHandlerCoverageRatio: number;
  readonly compactIncludedInstructions: number;
  readonly compactOmittedInstructions: number;
  readonly sections: readonly JnkieRecoverySectionFacts[];
  readonly unresolvedRegions: readonly {
    readonly kind: "interstitial-prelude" | "trailing-data";
    readonly byteStart: number;
    readonly byteEnd: number;
    readonly byteLength: number;
  }[];
  readonly submittedCodeExecuted: false;
}

export interface PluginAnalysis {
  readonly status: JobStatus;
  readonly diagnostics: readonly Diagnostic[];
  readonly sourceFacts?: LuaParseFacts;
  readonly behavior?: BehaviorInventory;
  readonly luraphAudit?: LuraphAuditFacts;
  readonly jnkieRecovery?: JnkieRecoveryFacts;
  readonly passes: readonly SourcePassRecord[];
  readonly readableSource?: string;
  readonly readableKind?: ReadableKind;
  readonly bytecode?: BytecodeAnalysisSummary;
}

export interface DeobfuscatorPlugin {
  readonly manifest: PluginManifest;
  detect(context: DetectionContext): Promise<DetectionResult>;
  plan(context: AnalysisContext): Promise<StagePlan>;
  extract?(context: AnalysisContext): Promise<readonly ExtractedArtifact[]>;
  analyze(context: AnalysisContext): Promise<PluginAnalysis>;
  validate(context: ValidationContext): Promise<ValidationReport>;
}

export interface PluginSelection {
  readonly pluginId: string;
  readonly reason: string;
  readonly ambiguous: boolean;
  readonly rankedDetections: readonly DetectionResult[];
}

export interface AnalysisInputRecord {
  readonly fileName: string;
  readonly byteLength: number;
  readonly sha256: string;
  readonly classification: SourceClassification;
}

export interface AnalysisReport {
  readonly schemaVersion: typeof ANALYSIS_SCHEMA_VERSION;
  readonly jobId: string;
  readonly createdAt: string;
  readonly input: AnalysisInputRecord;
  readonly selectedPlugin: PluginManifest;
  readonly selection: PluginSelection;
  readonly detections: readonly DetectionResult[];
  readonly plan: StagePlan;
  readonly status: JobStatus;
  readonly analysis: PluginAnalysis;
  readonly validation: ValidationReport;
  readonly diagnostics: readonly Diagnostic[];
}

export interface AnalysisResult {
  readonly report: AnalysisReport;
  readonly exactBytes: Uint8Array;
  readonly readableSource?: string;
  readonly disassembly?: string;
  readonly extractedArtifacts?: readonly ExtractedArtifact[];
}

export type ArtifactRole =
  | "original"
  | "exact-audit"
  | "readable"
  | "disassembly"
  | "behavior-report"
  | "extracted-payload"
  | "validation-report"
  | "report"
  | "warnings";

export interface ArtifactRecord {
  readonly role: ArtifactRole;
  readonly fileName: string;
  readonly byteLength: number;
  readonly sha256: string;
  readonly mediaType: string;
}

export interface JobManifest {
  readonly schemaVersion: typeof ANALYSIS_SCHEMA_VERSION;
  readonly jobId: string;
  readonly createdAt: string;
  readonly input: {
    readonly fileName: string;
    readonly byteLength: number;
    readonly sha256: string;
  };
  readonly artifacts: readonly ArtifactRecord[];
}

export interface WrittenJob {
  readonly jobDirectory: string;
  readonly manifestPath: string;
  readonly manifest: JobManifest;
}
