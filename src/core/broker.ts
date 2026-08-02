import { readFile, stat } from "node:fs/promises";
import { basename, extname, isAbsolute } from "node:path";

import type {
  AnalysisLimits,
  AnalysisResult,
  WrittenJob,
} from "../shared/contracts";
import { analyzeBytes, DEFAULT_ANALYSIS_LIMITS } from "./analyze";
import { writeExpandedJobBundle } from "./artifacts/expanded-store";

const ALLOWED_INPUT_EXTENSIONS = new Set([".lua", ".luau", ".luac", ".txt"]);

export interface AnalyzeFileRequest {
  readonly inputPath: string;
  readonly jobsRoot: string;
  readonly limits?: AnalysisLimits;
  readonly jobId?: string;
}

export interface BrokerAnalysisResult {
  readonly analysis: AnalysisResult;
  readonly writtenJob: WrittenJob;
}

/**
 * Bounded result returned after the worker has persisted the complete bundle.
 * Large exact/extracted byte arrays stay in the worker and on disk.
 */
export interface PersistedBrokerAnalysisResult {
  readonly analysis: Pick<AnalysisResult, "report">;
  readonly writtenJob: WrittenJob;
}

function assertAbsolutePath(path: string, label: string): void {
  if (!isAbsolute(path)) throw new Error(`${label} must be an absolute path.`);
  if (path.includes("\0")) throw new Error(`${label} contains a NUL byte.`);
}

export async function analyzeFileToJob(
  request: AnalyzeFileRequest,
): Promise<BrokerAnalysisResult> {
  assertAbsolutePath(request.inputPath, "Input path");
  assertAbsolutePath(request.jobsRoot, "Jobs root");
  if (
    request.jobId !== undefined &&
    !/^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i.test(
      request.jobId,
    )
  ) {
    throw new Error("Job ID must be a canonical UUID.");
  }
  const extension = extname(request.inputPath).toLowerCase();
  if (!ALLOWED_INPUT_EXTENSIONS.has(extension)) {
    throw new Error(
      `Unsupported input extension "${extension || "(none)"}"; expected .lua, .luau, .luac, or .txt.`,
    );
  }

  const limits = request.limits ?? DEFAULT_ANALYSIS_LIMITS;
  const metadata = await stat(request.inputPath);
  if (!metadata.isFile()) throw new Error("Input path must refer to a regular file.");
  if (metadata.size > limits.maxInputBytes) {
    throw new Error(
      `Input exceeds the ${limits.maxInputBytes}-byte analysis limit.`,
    );
  }

  const bytes = await readFile(request.inputPath);
  if (bytes.byteLength > limits.maxInputBytes) {
    throw new Error("Input grew beyond the analysis limit while being read.");
  }
  const analysis = await analyzeBytes({
    fileName: basename(request.inputPath),
    bytes,
    limits,
    ...(request.jobId === undefined ? {} : { jobId: request.jobId }),
  });
  const writtenJob = await writeExpandedJobBundle(
    request.jobsRoot,
    analysis,
    limits.maxOutputBytes,
  );
  return { analysis, writtenJob };
}

