#!/usr/bin/env node

import { readFile, stat } from "node:fs/promises";
import { basename, resolve } from "node:path";

import { DEFAULT_ANALYSIS_LIMITS } from "../core/analyze";
import { analyzeFileToJob } from "../core/broker";
import { classifyInput } from "../core/classification";
import { runDetectors } from "../core/detectors";
import { listPlugins, selectPlugin } from "../core/plugins";

export interface CliIo {
  readonly stdout: (text: string) => void;
  readonly stderr: (text: string) => void;
}

const DEFAULT_IO: CliIo = {
  stdout: (text) => process.stdout.write(text),
  stderr: (text) => process.stderr.write(text),
};

function printJson(io: CliIo, value: unknown): void {
  io.stdout(`${JSON.stringify(value, null, 2)}\n`);
}

function usage(): string {
  return [
    "3ziz Deobfuscator — static analysis only",
    "",
    "Usage:",
    "  3ziz detect <input.lua|input.luau|input.luac|input.txt>",
    "  3ziz analyze <input> --out <absolute-or-relative-jobs-root>",
    "  3ziz plugins",
    "",
  ].join("\n");
}

async function readBounded(path: string): Promise<Uint8Array> {
  const metadata = await stat(path);
  if (!metadata.isFile()) throw new Error("Input path must be a regular file.");
  if (metadata.size > DEFAULT_ANALYSIS_LIMITS.maxInputBytes) {
    throw new Error("Input exceeds the 10 MiB analysis limit.");
  }
  const bytes = await readFile(path);
  if (bytes.byteLength > DEFAULT_ANALYSIS_LIMITS.maxInputBytes) {
    throw new Error("Input grew beyond the analysis limit while being read.");
  }
  return bytes;
}

function outputOption(args: readonly string[]): string {
  const index = args.indexOf("--out");
  if (index === -1) return resolve("3ziz-jobs");
  const value = args[index + 1];
  if (!value) throw new Error("--out requires a jobs-root path.");
  return resolve(value);
}

export async function runCli(
  args: readonly string[],
  io: CliIo = DEFAULT_IO,
): Promise<number> {
  const command = args[0];
  try {
    if (!command || command === "--help" || command === "-h" || command === "help") {
      io.stdout(usage());
      return 0;
    }

    if (command === "plugins") {
      printJson(
        io,
        listPlugins().map((plugin) => plugin.manifest),
      );
      return 0;
    }

    if (command === "detect") {
      const rawPath = args[1];
      if (!rawPath) throw new Error("detect requires an input path.");
      const inputPath = resolve(rawPath);
      const bytes = await readBounded(inputPath);
      const classified = classifyInput(bytes, basename(inputPath));
      const context = {
        fileName: basename(inputPath),
        bytes,
        classification: classified.classification,
        ...(classified.text === undefined ? {} : { text: classified.text }),
      };
      const detections = await runDetectors(context);
      printJson(io, {
        input: {
          fileName: basename(inputPath),
          byteLength: bytes.byteLength,
        },
        classification: classified.classification,
        detections,
        selection: selectPlugin(detections),
      });
      return 0;
    }

    if (command === "analyze") {
      const rawPath = args[1];
      if (!rawPath) throw new Error("analyze requires an input path.");
      const result = await analyzeFileToJob({
        inputPath: resolve(rawPath),
        jobsRoot: outputOption(args.slice(2)),
      });
      printJson(io, {
        jobId: result.analysis.report.jobId,
        status: result.analysis.report.status,
        selectedPlugin: result.analysis.report.selectedPlugin.id,
        jobDirectory: result.writtenJob.jobDirectory,
        manifestPath: result.writtenJob.manifestPath,
        artifacts: result.writtenJob.manifest.artifacts,
      });
      return result.analysis.report.status === "failed-validation" ? 2 : 0;
    }

    throw new Error(`Unknown command "${command}".`);
  } catch (error) {
    io.stderr(
      `${error instanceof Error ? error.message : "Command failed."}\n\n${usage()}`,
    );
    return 1;
  }
}

if (require.main === module) {
  void runCli(process.argv.slice(2)).then((code) => {
    process.exitCode = code;
  });
}
