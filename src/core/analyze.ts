import { randomUUID } from "node:crypto";

import {
  ANALYSIS_SCHEMA_VERSION,
  type AnalysisContext,
  type AnalysisLimits,
  type AnalysisReport,
  type AnalysisResult,
  type DetectionContext,
  type Diagnostic,
  type ValidationContext,
} from "../shared/contracts";
import { classifyInput } from "./classification";
import { runDetectors } from "./detectors";
import { sha256Bytes } from "./hash";
import { deepFreeze } from "./immutable";
import { getPlugin, selectPlugin } from "./plugins";

export const DEFAULT_ANALYSIS_LIMITS: AnalysisLimits = {
  maxInputBytes: 10 * 1_024 * 1_024,
  maxOutputBytes: 40 * 1_024 * 1_024,
  maxAstNodes: 500_000,
};

export interface AnalyzeBytesOptions {
  readonly fileName: string;
  readonly bytes: Uint8Array;
  readonly limits?: AnalysisLimits;
  readonly jobId?: string;
  readonly createdAt?: string;
}

export async function analyzeBytes(
  options: AnalyzeBytesOptions,
): Promise<AnalysisResult> {
  const limits = options.limits ?? DEFAULT_ANALYSIS_LIMITS;
  if (options.bytes.byteLength > limits.maxInputBytes) {
    throw new Error(
      `Input exceeds the ${limits.maxInputBytes}-byte analysis limit.`,
    );
  }

  const exactBytes = Uint8Array.from(options.bytes);
  const classified = classifyInput(exactBytes, options.fileName);
  const inputSha256 = sha256Bytes(exactBytes);
  const detectionContext: DetectionContext = {
    fileName: options.fileName,
    bytes: exactBytes,
    classification: classified.classification,
    ...(classified.text === undefined ? {} : { text: classified.text }),
  };
  const detections = await runDetectors(detectionContext);
  const selection = selectPlugin(detections);
  const plugin = getPlugin(selection.pluginId);
  const selectedDetection =
    detections.find((result) => result.pluginId === plugin.manifest.id) ??
    (() => {
      throw new Error(`Detector result missing for ${plugin.manifest.id}`);
    })();
  const baseAnalysisContext: AnalysisContext = {
    ...detectionContext,
    inputSha256,
    selectedDetection,
    limits,
  };
  const extractedArtifacts =
    (await plugin.extract?.(baseAnalysisContext)) ?? [];
  const analysisContext: AnalysisContext =
    extractedArtifacts.length === 0
      ? baseAnalysisContext
      : { ...baseAnalysisContext, extractedArtifacts };
  const plan = await plugin.plan(analysisContext);
  const pluginAnalysis = await plugin.analyze(analysisContext);
  const validationContext: ValidationContext = {
    ...analysisContext,
    analysis: pluginAnalysis,
  };
  const validation = await plugin.validate(validationContext);
  const diagnostics: Diagnostic[] = [
    ...(selection.ambiguous
      ? [
          {
            code: "PLUGIN_SELECTION_AMBIGUOUS",
            severity: "warning" as const,
            stage: "detection",
            message: selection.reason,
            evidence: detections
              .filter((result) => result.pluginId !== "generic-static")
              .map(
                (result) =>
                  `${result.pluginId}=${result.confidence.toFixed(3)}`,
              ),
          },
        ]
      : []),
    ...pluginAnalysis.diagnostics,
    ...validation.diagnostics.filter(
      (diagnostic) =>
        !pluginAnalysis.diagnostics.some(
          (existing) =>
            existing.code === diagnostic.code &&
            existing.message === diagnostic.message,
        ),
    ),
  ];

  const report: AnalysisReport = {
    schemaVersion: ANALYSIS_SCHEMA_VERSION,
    jobId: options.jobId ?? randomUUID(),
    createdAt: options.createdAt ?? new Date().toISOString(),
    input: {
      fileName: options.fileName,
      byteLength: exactBytes.byteLength,
      sha256: inputSha256,
      classification: classified.classification,
    },
    selectedPlugin: plugin.manifest,
    selection,
    detections,
    plan,
    status: validation.valid ? pluginAnalysis.status : "failed-validation",
    analysis: pluginAnalysis,
    validation,
    diagnostics,
  };
  deepFreeze(report);

  return {
    report,
    exactBytes,
    ...(pluginAnalysis.readableSource === undefined
      ? {}
      : { readableSource: pluginAnalysis.readableSource }),
    ...(pluginAnalysis.bytecode?.disassembly === undefined
      ? {}
      : { disassembly: pluginAnalysis.bytecode.disassembly }),
    ...(extractedArtifacts.length === 0
      ? {}
      : { extractedArtifacts }),
  };
}
