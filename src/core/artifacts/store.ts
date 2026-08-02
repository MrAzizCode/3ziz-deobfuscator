import { mkdir, writeFile } from "node:fs/promises";
import { extname, isAbsolute, join, resolve } from "node:path";

import {
  ANALYSIS_SCHEMA_VERSION,
  type AnalysisResult,
  type ArtifactRecord,
  type ArtifactRole,
  type JobManifest,
  type WrittenJob,
} from "../../shared/contracts";
import { sha256Bytes } from "../hash";
import { deepFreeze } from "../immutable";

interface ArtifactPayload {
  readonly role: ArtifactRole;
  readonly fileName: string;
  readonly mediaType: string;
  readonly bytes: Uint8Array;
}

const EXACT_EXTENSIONS = new Set([".lua", ".luau", ".luac", ".txt"]);

function jsonBytes(value: unknown): Uint8Array {
  return Buffer.from(`${JSON.stringify(value, null, 2)}\n`, "utf8");
}

function exactFileName(inputName: string): string {
  const extension = extname(inputName).toLowerCase();
  return `exact${EXACT_EXTENSIONS.has(extension) ? extension : ".bin"}`;
}

function warningsMarkdown(result: AnalysisResult): string {
  const warnings = result.report.diagnostics.filter(
    (diagnostic) => diagnostic.severity !== "info",
  );
  const lines = [
    "# 3ziz Deobfuscator warnings",
    "",
    `Status: \`${result.report.status}\``,
    "",
  ];
  if (warnings.length === 0) {
    lines.push("No warnings or errors were reported.", "");
  } else {
    for (const warning of warnings) {
      lines.push(
        `- **${warning.severity.toUpperCase()} - ${warning.code}**: ${warning.message}`,
      );
      if (warning.suggestedAction) {
        lines.push(`  Suggested action: ${warning.suggestedAction}`);
      }
    }
    lines.push("");
  }
  lines.push(
    "Submitted Lua/Luau was analyzed statically and was never executed.",
    "",
  );
  return lines.join("\n");
}

export function buildArtifactPayloads(
  result: AnalysisResult,
): readonly ArtifactPayload[] {
  const payloads: ArtifactPayload[] = [
    {
      role: "original",
      fileName: exactFileName(result.report.input.fileName),
      mediaType:
        result.report.input.classification.isText
          ? "text/plain; charset=utf-8"
          : "application/octet-stream",
      bytes: Uint8Array.from(result.exactBytes),
    },
  ];
  if (result.readableSource !== undefined) {
    payloads.push({
      role: "readable",
      fileName:
        result.report.input.classification.kind === "luau-source"
          ? "readable.luau"
          : "readable.lua",
      mediaType: "text/plain; charset=utf-8",
      bytes: Buffer.from(result.readableSource, "utf8"),
    });
  }
  if (result.disassembly !== undefined) {
    payloads.push({
      role: "disassembly",
      fileName: "disassembly.txt",
      mediaType: "text/plain; charset=utf-8",
      bytes: Buffer.from(result.disassembly, "utf8"),
    });
  }
  for (const extracted of result.extractedArtifacts ?? []) {
    assertGeneratedArtifactName(extracted.fileName);
    if (sha256Bytes(extracted.bytes) !== extracted.sha256) {
      throw new Error(`Extracted artifact hash mismatch: ${extracted.fileName}`);
    }
    payloads.push({
      role: "extracted-payload",
      fileName: extracted.fileName,
      mediaType: extracted.mediaType,
      bytes: Uint8Array.from(extracted.bytes),
    });
  }
  payloads.push(
    {
      role: "report",
      fileName: "report.json",
      mediaType: "application/json",
      bytes: jsonBytes(result.report),
    },
    {
      role: "warnings",
      fileName: "warnings.md",
      mediaType: "text/markdown; charset=utf-8",
      bytes: Buffer.from(warningsMarkdown(result), "utf8"),
    },
  );
  return payloads;
}

async function writeExclusive(path: string, bytes: Uint8Array): Promise<void> {
  await writeFile(path, bytes, { flag: "wx" });
}

export async function writeJobBundle(
  jobsRoot: string,
  result: AnalysisResult,
  maxOutputBytes = 40 * 1_024 * 1_024,
): Promise<WrittenJob> {
  if (!isAbsolute(jobsRoot)) {
    throw new Error("Jobs root must be an absolute path.");
  }

  const root = resolve(jobsRoot);
  await mkdir(root, { recursive: true });
  const jobDirectory = join(root, result.report.jobId);
  await mkdir(jobDirectory, { recursive: false });

  const payloads = buildArtifactPayloads(result);
  const totalBytes = payloads.reduce(
    (sum, payload) => sum + payload.bytes.byteLength,
    0,
  );
  if (totalBytes > maxOutputBytes) {
    throw new Error(
      `Artifact payload exceeds the ${maxOutputBytes}-byte output limit.`,
    );
  }

  const records: ArtifactRecord[] = [];
  for (const payload of payloads) {
    await writeExclusive(join(jobDirectory, payload.fileName), payload.bytes);
    records.push({
      role: payload.role,
      fileName: payload.fileName,
      byteLength: payload.bytes.byteLength,
      sha256: sha256Bytes(payload.bytes),
      mediaType: payload.mediaType,
    });
  }

  const manifest: JobManifest = {
    schemaVersion: ANALYSIS_SCHEMA_VERSION,
    jobId: result.report.jobId,
    createdAt: result.report.createdAt,
    input: {
      fileName: result.report.input.fileName,
      byteLength: result.report.input.byteLength,
      sha256: result.report.input.sha256,
    },
    artifacts: records,
  };
  deepFreeze(manifest);
  const manifestPath = join(jobDirectory, "manifest.json");
  await writeExclusive(manifestPath, jsonBytes(manifest));

  return {
    jobDirectory,
    manifestPath,
    manifest,
  };
}

function assertGeneratedArtifactName(fileName: string): void {
  if (!/^[a-zA-Z0-9][a-zA-Z0-9._-]{0,127}$/.test(fileName) || fileName === "manifest.json") {
    throw new Error(`Unsafe generated artifact name: ${fileName}`);
  }
}
