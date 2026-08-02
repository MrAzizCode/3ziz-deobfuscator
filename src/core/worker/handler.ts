import type { AnalysisLimits } from "../../shared/contracts";
import {
  analyzeFileToJob,
  type PersistedBrokerAnalysisResult,
} from "../broker";

export interface AnalyzeWorkerRequest {
  readonly type: "analyze-file";
  readonly requestId: string;
  readonly inputPath: string;
  readonly jobsRoot: string;
  readonly limits?: AnalysisLimits;
}

export type AnalyzeWorkerResponse =
  | {
      readonly type: "analysis-complete";
      readonly requestId: string;
      readonly result: PersistedBrokerAnalysisResult;
    }
  | {
      readonly type: "analysis-error";
      readonly requestId: string;
      readonly error: string;
    };

function asRecord(value: unknown): Record<string, unknown> | null {
  return value !== null && typeof value === "object"
    ? (value as Record<string, unknown>)
    : null;
}

function parseRequest(message: unknown): AnalyzeWorkerRequest {
  const record = asRecord(message);
  if (
    record?.type !== "analyze-file" ||
    typeof record.requestId !== "string" ||
    typeof record.inputPath !== "string" ||
    typeof record.jobsRoot !== "string"
  ) {
    throw new Error("Malformed static-worker request.");
  }
  const limitsRecord = asRecord(record.limits);
  const limits =
    limitsRecord &&
    typeof limitsRecord.maxInputBytes === "number" &&
    typeof limitsRecord.maxOutputBytes === "number" &&
    typeof limitsRecord.maxAstNodes === "number"
      ? {
          maxInputBytes: limitsRecord.maxInputBytes,
          maxOutputBytes: limitsRecord.maxOutputBytes,
          maxAstNodes: limitsRecord.maxAstNodes,
        }
      : undefined;
  return {
    type: "analyze-file",
    requestId: record.requestId,
    inputPath: record.inputPath,
    jobsRoot: record.jobsRoot,
    ...(limits === undefined ? {} : { limits }),
  };
}

export async function handleWorkerMessage(
  message: unknown,
): Promise<AnalyzeWorkerResponse> {
  let requestId = "unknown";
  try {
    const request = parseRequest(message);
    requestId = request.requestId;
    const result = await analyzeFileToJob({
      inputPath: request.inputPath,
      jobsRoot: request.jobsRoot,
      jobId: request.requestId,
      ...(request.limits === undefined ? {} : { limits: request.limits }),
    });
    return {
      type: "analysis-complete",
      requestId,
      result: {
        analysis: { report: result.analysis.report },
        writtenJob: result.writtenJob,
      },
    };
  } catch (error) {
    return {
      type: "analysis-error",
      requestId,
      error: error instanceof Error ? error.message : "Static analysis failed.",
    };
  }
}
