import { mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";

import { afterEach, describe, expect, it } from "vitest";

import { analyzeBytes } from "../../src/core/analyze";
import { writeExpandedJobBundle } from "../../src/core/artifacts/expanded-store";
import { sha256Bytes } from "../../src/core/hash";
import type {
  AnalysisResult,
  JnkieRecoveryFacts,
  LuraphAuditFacts,
} from "../../src/shared/contracts";
import {
  adaptBrokerAnalysisResult,
  loadRendererArtifacts,
} from "../../src/desktop/result-adapter";
import {
  cleanupStaleJobStorage,
  createManagedJobStorage,
  isManagedJobStoragePath,
  removeManagedJobStorage,
} from "../../src/desktop/job-retention";
import {
  EXPLICIT_DEV_RENDERER_URL,
  selectRendererTarget,
} from "../../src/desktop/runtime-policy";

const temporaryDirectories: string[] = [];

async function temporaryDirectory(): Promise<string> {
  const directory = await mkdtemp(join(tmpdir(), "3ziz-desktop-test-"));
  temporaryDirectories.push(directory);
  return resolve(directory);
}

afterEach(async () => {
  while (temporaryDirectories.length > 0) {
    const directory = temporaryDirectories.pop();
    if (directory !== undefined) {
      await rm(directory, { recursive: true, force: true });
    }
  }
});

describe("desktop trust boundaries", () => {
  it("uses the local bundle unless the exact development URL is explicitly set", () => {
    expect(selectRendererTarget(false, undefined)).toEqual({
      kind: "bundle",
      url: "app://bundle/index.html",
    });
    expect(selectRendererTarget(false, "http://localhost:4317/")).toEqual({
      kind: "bundle",
      url: "app://bundle/index.html",
    });
    expect(selectRendererTarget(false, EXPLICIT_DEV_RENDERER_URL)).toEqual({
      kind: "dev-server",
      url: EXPLICIT_DEV_RENDERER_URL,
    });
    expect(selectRendererTarget(true, EXPLICIT_DEV_RENDERER_URL)).toEqual({
      kind: "bundle",
      url: "app://bundle/index.html",
    });
  });

  it("creates and deletes only UUID-named managed job storage", async () => {
    const root = await temporaryDirectory();
    const requestId = "10000000-0000-4000-8000-000000000001";
    const storage = await createManagedJobStorage(root, requestId);
    expect(isManagedJobStoragePath(root, storage)).toBe(true);
    expect(isManagedJobStoragePath(root, resolve(root, "other"))).toBe(false);
    await expect(
      removeManagedJobStorage(root, resolve(root, "other")),
    ).rejects.toThrow(/outside managed job storage/);
    await removeManagedJobStorage(root, storage);
    await expect(readFile(storage)).rejects.toMatchObject({ code: "ENOENT" });
  });

  it("cleans stale managed UUID directories while retaining unknown entries", async () => {
    const root = await temporaryDirectory();
    const requestId = "20000000-0000-4000-8000-000000000002";
    const storage = await createManagedJobStorage(root, requestId);
    const retained = join(root, "pending", "keep-me");
    await writeFile(retained, "owned by the user", "utf8");
    await cleanupStaleJobStorage(root);
    await expect(readFile(storage)).rejects.toMatchObject({ code: "ENOENT" });
    await expect(readFile(retained, "utf8")).resolves.toBe("owned by the user");
  });

  it("fails renderer verification after same-size artifact tampering", async () => {
    const root = await temporaryDirectory();
    const analysis = await analyzeBytes({
      fileName: "sample.lua",
      bytes: Buffer.from('return "a" .. "b"\n', "utf8"),
      jobId: "30000000-0000-4000-8000-000000000003",
      createdAt: "2026-08-01T00:00:00.000Z",
    });
    const writtenJob = await writeExpandedJobBundle(root, analysis);
    const brokerResult = {
      analysis: { report: analysis.report },
      writtenJob,
    };
    const readable = writtenJob.manifest.artifacts.find(
      (artifact) => artifact.role === "readable",
    );
    expect(readable).toBeDefined();
    const readablePath = join(
      writtenJob.jobDirectory,
      readable?.fileName ?? "readable.lua",
    );
    const bytes = await readFile(readablePath);
    const tampered = Buffer.from(bytes);
    tampered[0] = tampered[0] === 45 ? 32 : 45;
    await writeFile(readablePath, tampered);

    const loaded = await loadRendererArtifacts(brokerResult);
    expect(loaded.diagnostics).toEqual(
      expect.arrayContaining([
        expect.objectContaining({
          code: "DESKTOP_ARTIFACT_READ_REJECTED",
        }),
      ]),
    );
    const adapted = await adaptBrokerAnalysisResult(
      brokerResult,
      resolve(root, "sample.lua"),
      10,
    );
    expect(adapted.status).toBe("failed-validation");
    expect(adapted.validationChecks).toEqual(
      expect.arrayContaining([
        expect.objectContaining({
          id: "artifact-integrity",
          status: "failed",
        }),
      ]),
    );
  });

  it("warns without failing when renderer presentation limits omit safe artifacts", async () => {
    const root = await temporaryDirectory();
    const analysis = await analyzeBytes({
      fileName: "bounded.lua",
      bytes: Buffer.from('return "bounded renderer output"\n', "utf8"),
      jobId: "35000000-0000-4000-8000-000000000003",
      createdAt: "2026-08-01T00:00:00.000Z",
    });
    const writtenJob = await writeExpandedJobBundle(root, analysis);
    const brokerResult = {
      analysis: { report: analysis.report },
      writtenJob,
    };
    const largestArtifact = Math.max(
      ...writtenJob.manifest.artifacts.map((artifact) => artifact.byteLength),
    );

    const totalLimited = await adaptBrokerAnalysisResult(
      brokerResult,
      resolve(root, "bounded.lua"),
      10,
      {
        maxArtifactBytes: largestArtifact,
        maxTotalBytes: largestArtifact,
      },
    );
    expect(totalLimited.status).toBe(analysis.report.status);
    expect(totalLimited.diagnostics).toEqual(
      expect.arrayContaining([
        expect.objectContaining({ code: "DESKTOP_ARTIFACT_TOTAL_LIMIT" }),
      ]),
    );
    expect(totalLimited.validationChecks).toEqual(
      expect.arrayContaining([
        expect.objectContaining({
          id: "artifact-integrity",
          status: "warning",
        }),
      ]),
    );

    const sizeLimited = await adaptBrokerAnalysisResult(
      brokerResult,
      resolve(root, "bounded.lua"),
      10,
      {
        maxArtifactBytes: 1,
        maxTotalBytes: largestArtifact,
      },
    );
    expect(sizeLimited.status).toBe(analysis.report.status);
    expect(sizeLimited.diagnostics).toEqual(
      expect.arrayContaining([
        expect.objectContaining({ code: "DESKTOP_ARTIFACT_SIZE_LIMIT" }),
      ]),
    );
    expect(sizeLimited.validationChecks).toEqual(
      expect.arrayContaining([
        expect.objectContaining({
          id: "artifact-integrity",
          status: "warning",
        }),
      ]),
    );

    const readable = writtenJob.manifest.artifacts.find(
      (artifact) => artifact.role === "readable",
    );
    expect(readable).toBeDefined();
    const mediaLimitedJob = {
      ...writtenJob,
      manifest: {
        ...writtenJob.manifest,
        artifacts: writtenJob.manifest.artifacts.map((artifact) =>
          artifact === readable
            ? { ...artifact, mediaType: "application/octet-stream" }
            : artifact,
        ),
      },
    };
    const mediaLimited = await adaptBrokerAnalysisResult(
      {
        analysis: { report: analysis.report },
        writtenJob: mediaLimitedJob,
      },
      resolve(root, "bounded.lua"),
      10,
    );
    expect(mediaLimited.status).toBe(analysis.report.status);
    expect(mediaLimited.artifacts.readable).toBe(
      analysis.report.analysis.readableSource,
    );
    expect(mediaLimited.diagnostics).toEqual(
      expect.arrayContaining([
        expect.objectContaining({ code: "DESKTOP_ARTIFACT_MEDIA_REJECTED" }),
      ]),
    );
    expect(mediaLimited.validationChecks).toEqual(
      expect.arrayContaining([
        expect.objectContaining({
          id: "artifact-integrity",
          status: "warning",
        }),
      ]),
    );
  });

  it("presents exact decoded JNKIE records and recovery facts instead of legacy inventory", async () => {
    const root = await temporaryDirectory();
    const base = await analyzeBytes({
      fileName: "matched.lua",
      bytes: Buffer.from("local first = 1\nlocal second = 2\nreturn first + second", "utf8"),
      jobId: "40000000-0000-4000-8000-000000000004",
      createdAt: "2026-08-01T00:00:00.000Z",
    });
    const sourceFacts = base.report.analysis.sourceFacts;
    expect(sourceFacts).toBeDefined();
    if (sourceFacts === undefined) {
      throw new Error("Expected source facts for the adapter fixture.");
    }
    const associatedAudit = {
      functionCount: 36,
      decodedInstructions: 9_414,
      reachableInstructions: 6_644,
      omittedInstructions: 2_770,
      deterministicPatches: 667,
      ambiguousDecoderWrites: 74,
      labelDefinitions: 6_644,
      gotoReferences: 2_789,
      vmFragments: 495,
      functions: [],
      summaryMatchesMetadata: true,
      nonExecutableReasons: [],
    } satisfies LuraphAuditFacts;
    const recoveryFacts = {
      schemaVersion: 1,
      recordSections: 2,
      prototypes: 902,
      instructions: 261_864,
      constants: 16_907,
      constantReferences: 111_017,
      stringReferences: 50_896,
      resolvedConstantReferences: 111_017,
      childReferences: 1_088,
      resolvedChildReferences: 1_088,
      decodedBytes: 2_284_527,
      unresolvedBytes: 400,
      outerRootPrototype: 302,
      nestedRootPrototype: 149,
      semanticInstructions: 239_010,
      protocolInstructions: 15_781,
      unknownInstructions: 7_073,
      semanticCoverageRatio: 0.912725689670974,
      explainedHandlerCoverageRatio: 0.972989796230104,
      compactIncludedInstructions: 16_596,
      compactOmittedInstructions: 245_268,
      sections: [
        {
          index: 1,
          kind: "outer-loader",
          byteStart: 0,
          byteEnd: 221_167,
          decodedBytes: 221_167,
          wrappedConstants: false,
          constants: 2_335,
          prototypes: 371,
          instructions: 34_696,
          captures: 106,
          constantReferences: 15_505,
          stringReferences: 727,
          resolvedConstantReferences: 15_505,
          childReferences: 370,
          resolvedChildReferences: 370,
          rootPrototype: 302,
          rootInstructions: 1_409,
        },
        {
          index: 2,
          kind: "nested-payload",
          byteStart: 221_567,
          byteEnd: 2_284_927,
          decodedBytes: 2_063_360,
          wrappedConstants: true,
          constants: 14_572,
          prototypes: 531,
          instructions: 227_168,
          captures: 319,
          constantReferences: 95_512,
          stringReferences: 50_169,
          resolvedConstantReferences: 95_512,
          childReferences: 718,
          resolvedChildReferences: 718,
          rootPrototype: 149,
          rootInstructions: 86_843,
        },
      ],
      unresolvedRegions: [
        {
          kind: "interstitial-prelude",
          byteStart: 221_167,
          byteEnd: 221_567,
          byteLength: 400,
        },
      ],
      submittedCodeExecuted: false,
    } satisfies JnkieRecoveryFacts;
    const decodedRecordReport = Buffer.from(
      [
        "# JNKIE decoded record report",
        "",
        "- Sections: 2",
        "- Prototypes: 902",
        "- Instructions: 261,864",
        "- Untyped interstitial bytes: 400",
        "",
      ].join("\n"),
      "utf8",
    );
    const analysis = {
      ...base,
      extractedArtifacts: [
        ...(base.extractedArtifacts ?? []),
        {
          fileName: "jnkie-records-readable.txt",
          mediaType: "text/markdown; charset=utf-8",
          bytes: decodedRecordReport,
          sha256: sha256Bytes(decodedRecordReport),
        },
      ],
      report: {
        ...base.report,
        status: "partial",
        selectedPlugin: {
          ...base.report.selectedPlugin,
          id: "jnkie-luraph-14-static",
          name: "JNKIE / Luraph 14.7 extractor",
          family: "jnkie-luraph",
        },
        analysis: {
          ...base.report.analysis,
          status: "partial",
          sourceFacts: {
            ...sourceFacts,
            lineCount: 202,
            functionCount: 6,
          },
          luraphAudit: associatedAudit,
          jnkieRecovery: recoveryFacts,
          readableKind: "register-pseudocode",
        },
        diagnostics: [
          {
            code: "JNKIE_CURRENT_STREAM_PROFILE_MATCH",
            severity: "info",
            stage: "jnkie-known-profile",
            message: "The exact current-stream profile matched.",
          },
          {
            code: "JNKIE_SEMANTIC_COVERAGE_PARTIAL",
            severity: "warning",
            stage: "jnkie-semantic-lift",
            message: "Unknown instruction semantics remain explicit.",
          },
        ],
      },
    } satisfies AnalysisResult;
    const writtenJob = await writeExpandedJobBundle(root, analysis);
    const adapted = await adaptBrokerAnalysisResult(
      {
        analysis: { report: analysis.report },
        writtenJob,
      },
      resolve(root, "matched.lua"),
      25,
    );

    expect(adapted.input.lineCount).toBe(3);
    expect(adapted.readableKind).toBe("register-pseudocode");
    expect(adapted.artifacts.decodedRecords).toBe(
      decodedRecordReport.toString("utf8"),
    );
    expect(adapted.statistics).toMatchObject({
      recordSections: 2,
      prototypes: 902,
      instructions: 261_864,
      constants: 16_907,
      constantReferences: 111_017,
      stringReferences: 50_896,
      childReferences: 1_088,
      resolvedChildReferences: 1_088,
      decodedBytes: 2_284_527,
      unresolvedBytes: 400,
      outerRootPrototype: 302,
      nestedRootPrototype: 149,
      semanticInstructions: 239_010,
      protocolInstructions: 15_781,
      unknownInstructions: 7_073,
      semanticCoverageRatio: 0.912725689670974,
      unresolved: 7_073,
      warnings: 1,
    });
    expect(adapted.statistics.functions).toBeUndefined();
    expect(adapted.statistics.prototypeSummaries).toBeUndefined();
    expect(adapted.statistics.topIrRows).toBeUndefined();
    expect(adapted.statistics.unresolved).not.toBe(
      adapted.statistics.warnings,
    );
    const presentation = [
      adapted.summary,
      ...adapted.stages.map((stage) => stage.detail),
    ].join("\n");
    expect(presentation).toContain("2 JNKIE record sections end to end");
    expect(presentation).toContain("902 prototypes");
    expect(presentation).toContain("261,864 instructions");
    expect(presentation).toContain("16,907 constants");
    expect(presentation).toContain("239,010 instructions have proven direct semantics");
    expect(presentation).toContain("15,781 decoder-protocol");
    expect(presentation).toContain("7,073 unproven instruction records");
    expect(presentation).toContain("all 1,088 child references");
    expect(presentation).toContain("400 interstitial byte(s)");
    expect(presentation).not.toContain("371 prototype summary records");
    expect(presentation).not.toContain("1,409 top-prototype raw IR rows");
    expect(presentation).not.toMatch(/36 decoded|9,414|667|495|CFG/i);
  });
});
