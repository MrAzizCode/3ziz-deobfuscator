import { mkdir, writeFile } from "node:fs/promises";
import { extname, isAbsolute, join, resolve } from "node:path";

import {
  ANALYSIS_SCHEMA_VERSION,
  type AnalysisResult,
  type ArtifactRecord,
  type ArtifactRole,
  type BehaviorInventory,
  type JobManifest,
  type ValidationReport,
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

const INPUT_EXTENSIONS = new Set([".lua", ".luau", ".luac", ".txt"]);

function jsonBytes(value: unknown): Uint8Array {
  return Buffer.from(`${JSON.stringify(value, null, 2)}\n`, "utf8");
}

function originalFileName(inputName: string): string {
  const extension = extname(inputName).toLowerCase();
  return `original${INPUT_EXTENSIONS.has(extension) ? extension : ".bin"}`;
}

function renderWarnings(result: AnalysisResult): string {
  const diagnostics = result.report.diagnostics.filter(
    (diagnostic) => diagnostic.severity !== "info",
  );
  const lines = [
    "# 3ziz Deobfuscator warnings",
    "",
    `Status: \`${result.report.status}\``,
    "",
  ];
  if (diagnostics.length === 0) {
    lines.push("No warnings or errors were reported.", "");
  } else {
    for (const diagnostic of diagnostics) {
      lines.push(
        `- **${diagnostic.severity.toUpperCase()} - ${diagnostic.code}**: ${diagnostic.message}`,
      );
      if (diagnostic.evidence?.length) {
        for (const evidence of diagnostic.evidence) {
          lines.push(`  - ${evidence}`);
        }
      }
      if (diagnostic.suggestedAction) {
        lines.push(`  - Suggested action: ${diagnostic.suggestedAction}`);
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

function renderBehavior(inventory: BehaviorInventory | undefined): string {
  const serializedInventory =
    inventory?.evidenceSource === "serialized-string-inventory";
  const locationLabel = serializedInventory ? "row(s)" : "line(s)";
  const introduction = serializedInventory
    ? "Reachability was not evaluated. Findings come from decoded string/constant inventory; row numbers refer to jnkie-known-all-strings.tsv, not source lines."
    : "Reachability was not evaluated. Findings show visible source-code API references only.";

  const lines = [
    "# Static behavior inventory",
    "",
    introduction,
    "",
  ];
  if (!inventory || inventory.capabilities.length === 0) {
    lines.push("No configured capability API references were found.", "");
  } else {
    lines.push("## Capability references", "");
    for (const finding of inventory.capabilities) {
      lines.push(
        `- **${finding.category} / ${finding.api}**: ${finding.occurrences} occurrence(s); ${locationLabel} ${finding.lines.join(", ")}`,
      );
    }
    lines.push("");
  }
  if (inventory?.urls.length) {
    lines.push("## URLs", "");
    for (const finding of inventory.urls) {
      lines.push(`- ${serializedInventory ? "Row" : "Line"} ${finding.line}: \`${finding.url}\``);
    }
    lines.push("");
  }
  return lines.join("\n");
}

function renderValidation(validation: ValidationReport): string {
  const lines = [
    "# Validation report",
    "",
    `Result: **${validation.valid ? "passed" : "failed"}**`,
    "",
  ];
  if (validation.diagnostics.length === 0) {
    lines.push("No validation diagnostics were reported.", "");
  } else {
    for (const diagnostic of validation.diagnostics) {
      lines.push(
        `- **${diagnostic.severity.toUpperCase()} - ${diagnostic.code}**: ${diagnostic.message}`,
      );
    }
    lines.push("");
  }
  return lines.join("\n");
}

function exactAuditBytes(result: AnalysisResult): Uint8Array {
  if (result.report.input.classification.isText) {
    return Uint8Array.from(result.exactBytes);
  }
  if (result.disassembly !== undefined) {
    return Buffer.from(result.disassembly, "utf8");
  }
  return Buffer.from(
    [
      "3ziz Deobfuscator exact audit",
      `Input SHA-256: ${result.report.input.sha256}`,
      `Classification: ${result.report.input.classification.kind}`,
      `Status: ${result.report.status}`,
      "No structural disassembly was available.",
      "",
    ].join("\n"),
    "utf8",
  );
}

export function buildExpandedArtifactPayloads(
  result: AnalysisResult,
): readonly ArtifactPayload[] {
  const payloads: ArtifactPayload[] = [
    {
      role: "original",
      fileName: originalFileName(result.report.input.fileName),
      mediaType:
        result.report.input.classification.isText
          ? "text/plain; charset=utf-8"
          : "application/octet-stream",
      bytes: Uint8Array.from(result.exactBytes),
    },
    {
      role: "exact-audit",
      fileName: "exact-audit.txt",
      mediaType: "text/plain; charset=utf-8",
      bytes: exactAuditBytes(result),
    },
  ];
  if (result.readableSource !== undefined) {
    const readableKind = result.report.analysis.readableKind ?? "source-code";
    payloads.push({
      role: "readable",
      fileName: readableKind === "register-pseudocode"
        ? "readable-ir.txt"
        : readableKind === "vm-loader"
          ? "readable-loader.lua"
          : result.report.input.classification.kind === "luau-source"
            ? "readable.luau"
            : "readable.lua",
      mediaType: "text/plain; charset=utf-8",
      bytes: Buffer.from(result.readableSource, "utf8"),
    });
  }
  if (
    result.disassembly !== undefined &&
    !result.report.input.classification.isText
  ) {
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
      role: "behavior-report",
      fileName: "behavior-report.md",
      mediaType: "text/markdown; charset=utf-8",
      bytes: Buffer.from(
        renderBehavior(result.report.analysis.behavior),
        "utf8",
      ),
    },
    {
      role: "validation-report",
      fileName: "validation-report.md",
      mediaType: "text/markdown; charset=utf-8",
      bytes: Buffer.from(renderValidation(result.report.validation), "utf8"),
    },
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
      bytes: Buffer.from(renderWarnings(result), "utf8"),
    },
  );
  return payloads;
}

async function writeExclusive(path: string, bytes: Uint8Array): Promise<void> {
  await writeFile(path, bytes, { flag: "wx" });
}

export async function writeExpandedJobBundle(
  jobsRoot: string,
  result: AnalysisResult,
  maxOutputBytes = 40 * 1_024 * 1_024,
): Promise<WrittenJob> {
  if (!isAbsolute(jobsRoot)) throw new Error("Jobs root must be an absolute path.");

  const payloads = buildExpandedArtifactPayloads(result);
  const totalBytes = payloads.reduce(
    (sum, payload) => sum + payload.bytes.byteLength,
    0,
  );
  if (totalBytes > maxOutputBytes) {
    throw new Error(
      `Artifact payload exceeds the ${maxOutputBytes}-byte output limit.`,
    );
  }

  const root = resolve(jobsRoot);
  await mkdir(root, { recursive: true });
  const jobDirectory = join(root, result.report.jobId);
  await mkdir(jobDirectory, { recursive: false });

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
  return { jobDirectory, manifestPath, manifest };
}

function assertGeneratedArtifactName(fileName: string): void {
  if (!/^[a-zA-Z0-9][a-zA-Z0-9._-]{0,127}$/.test(fileName) || fileName === "manifest.json") {
    throw new Error(`Unsafe generated artifact name: ${fileName}`);
  }
}
