import { readFileSync } from "node:fs";

import { describe, expect, it } from "vitest";

import {
  analyzeBytes,
  DEFAULT_ANALYSIS_LIMITS,
} from "../../src/core/analyze";
import { buildExpandedArtifactPayloads } from "../../src/core/artifacts/expanded-store";
import {
  decodeLuraphAscii85,
  extractJnkieLuraph,
  findJnkieEncodedStreams,
} from "../../src/core/extractors/jnkie-luraph";
import { sha256Bytes } from "../../src/core/hash";
import {
  KNOWN_JNKIE_AUDIT_ARTIFACT,
  KNOWN_JNKIE_PROFILE_ARTIFACT,
  KNOWN_JNKIE_READABLE_ARTIFACT,
  resolveKnownJnkieProfile,
} from "../../src/core/recovery/jnkie-known-profile";
import { jnkieLuraphPlugin } from "../../src/core/plugins/jnkie-luraph";
import { parseLuau } from "../../src/core/source/luau-parser";
import type {
  ExtractedArtifact,
  PluginAnalysis,
} from "../../src/shared/contracts";

/*
 * This suite exercises an authorized private sample that is not part of the
 * repository.  Point THREEZIZ_JNKIE_FIXTURE at your own copy to run it; the
 * suite is skipped when the file is absent.
 */
const fixturePath =
  process.env.THREEZIZ_JNKIE_FIXTURE ?? "fixtures/jnkie_payload.lua";

/**
 * `it.runIf` takes a boolean, not a predicate: passing a function made this
 * suite run unconditionally and fail on a clone without the sample.
 */
const hasFixture = ((): boolean => {
  try {
    readFileSync(fixturePath);
    return true;
  } catch {
    return false;
  }
})();

function replaceArtifactBytes(
  artifacts: readonly ExtractedArtifact[],
  fileName: string,
  replacement: Uint8Array,
): readonly ExtractedArtifact[] {
  return artifacts.map((artifact) =>
    artifact.fileName === fileName
      ? {
          ...artifact,
          bytes: replacement,
          sha256: sha256Bytes(replacement),
        }
      : artifact,
  );
}

describe("JNKIE / Luraph static extraction", () => {
  it("implements the wrapper's little-endian Ascii85 transform", () => {
    expect([...decodeLuraphAscii85("!!!!!")]).toEqual([0, 0, 0, 0]);
    expect([...decodeLuraphAscii85("z")]).toEqual([0, 0, 0, 0]);
  });

  it("finds long-bracket streams with different delimiter depths", () => {
    const source = "local V,y=Y([=[!!!!!]=]),Y([==[!!!!!]==]);";
    expect(findJnkieEncodedStreams(source)).toEqual(["!!!!!", "!!!!!"]);
  });

  it("requires both recovered stream hashes before loading known recovery", () => {
    const result = resolveKnownJnkieProfile(Buffer.from("loader"), Buffer.from("payload"));
    expect(result.status).toBe("not-matched");
    expect(result.artifacts).toHaveLength(0);
    expect(result.manifest.match.requiresBothHashes).toBe(true);
  });

  it.runIf(hasFixture)("extracts and scans the authorized supplied payload without executing Lua", async () => {
    const bytes = readFileSync(fixturePath);
    expect(bytes.byteLength).toBe(1_663_542);
    expect(sha256Bytes(bytes)).toBe("948d4039bf0640b2f2e07501e8761f9364f34b28a4a0adfe6d2464b57355e2c1");

    const source = bytes.toString("utf8");
    const extraction = extractJnkieLuraph(source, 40 * 1_024 * 1_024);
    expect(extraction.artifacts.map((artifact) => artifact.fileName)).toEqual([
      "jnkie-loader.compressed.bin",
      "jnkie-payload.compressed.bin",
      "jnkie-loader.lua",
      "jnkie-loader.formatted.lua",
      "jnkie-payload.bin",
      "jnkie-payload-report.md",
      "jnkie-full-static-analysis.json",
      "jnkie-record-summary.json",
      "jnkie-record-prototypes.jsonl",
      "jnkie-record-constants.jsonl.gz",
      "jnkie-record-root.jsonl.gz",
      "jnkie-record-instructions.jsonl.gz",
      "jnkie-records-readable.txt",
      "jnkie-record-report.md",
      "jnkie-semantic-pseudocode.compact.txt",
      "jnkie-semantic-coverage.json",
      "jnkie-semantic-pseudocode.full.txt.gz",
      "jnkie-devirtualized.lua",
      KNOWN_JNKIE_PROFILE_ARTIFACT,
      KNOWN_JNKIE_READABLE_ARTIFACT,
      KNOWN_JNKIE_AUDIT_ARTIFACT,
      "jnkie-known-prototypes.json",
      "jnkie-known-top-ir.json",
      "jnkie-known-all-strings.tsv",
      "jnkie-known-constants.txt",
      "jnkie-known-prototypes-report.txt",
      "jnkie-known-ir-report.txt",
      "jnkie-known-prototype-0-rough.lua",
      "jnkie-known-prototype-0-min.lua",
      "jnkie-known-prototype-3-rough.lua",
      "jnkie-known-prototype-3-min.lua",
    ]);
    expect(extraction.artifacts.every((artifact) => artifact.bytes.byteLength > 0)).toBe(true);

    const loader = extraction.artifacts.find((artifact) => artifact.fileName === "jnkie-loader.lua")!;
    const payload = extraction.artifacts.find((artifact) => artifact.fileName === "jnkie-payload.bin")!;
    const profile = resolveKnownJnkieProfile(loader.bytes, payload.bytes);
    expect(profile.status).toBe("loaded");
    if (profile.status !== "loaded") throw new Error("Expected the exact profile to load.");
    expect(profile.manifest).toMatchObject({
      schemaVersion: 2,
      currentStreamMetrics: {
        prototypeSummaryRecords: 371,
        aggregateDeclaredInstructionCount: 34_696,
        topPrototypeRawIrRows: 1_409,
        constants: 9_270,
        stringConstants: 669,
        scope: "inventory-and-raw-ir-not-opcode-cfg-or-source-recovery",
      },
      unverifiedReferenceMetrics: {
        sourceSampleInputBytes: 324_503,
        compactReferenceLines: 201,
        auditFunctions: 36,
        auditInstructions: 9_414,
        currentStreamEvidence: false,
      },
    });
    const references = profile.artifacts.filter((artifact) =>
      artifact.fileName.includes("unverified-earlier-sample"),
    );
    expect(references).toHaveLength(2);
    expect(references.every((artifact) => artifact.mediaType === "text/plain; charset=utf-8")).toBe(true);
    expect(references.every((artifact) =>
      Buffer.from(artifact.bytes).toString("utf8").startsWith(
        "3ziz Deobfuscator - UNVERIFIED EARLIER-SAMPLE REFERENCE",
      ))).toBe(true);

    const payloadReport = extraction.artifacts.find(
      (artifact) => artifact.fileName === "jnkie-payload-report.md",
    )!;
    const payloadReportText = Buffer.from(payloadReport.bytes).toString("utf8");
    expect(payloadReportText).toContain("Exact-stream static evidence profile");
    expect(payloadReportText).toContain("Aggregate declared instruction count across those summaries");
    expect(payloadReportText).toContain("do not prove opcode meanings");
    expect(payloadReportText).toContain("different from the current JNKIE input");
    expect(payloadReportText).toContain("# JNKIE bounded record decode");
    expect(payloadReportText).toContain("# JNKIE conservative semantic lift");
    expect(payloadReportText).toContain("261,864");
    expect(payloadReportText).not.toContain("Associated decoded VM audit");

    const recordSummaryArtifact = extraction.artifacts.find(
      (artifact) => artifact.fileName === "jnkie-record-summary.json",
    )!;
    const recordSummary = JSON.parse(
      Buffer.from(recordSummaryArtifact.bytes).toString("utf8"),
    );
    expect(recordSummary).toMatchObject({
      schemaVersion: 1,
      safety: {
        submittedCodeExecution: "never",
        decodeMode: "bounded-static-record-reader",
      },
      coverage: {
        inputBytes: 2_284_927,
        decodedRecordBytes: 2_284_527,
        unresolvedBytes: 400,
        trailingBytes: 0,
        sections: 2,
        unresolvedRegions: [
          {
            kind: "interstitial-prelude",
            byteRange: [221_167, 221_567],
            byteLength: 400,
          },
        ],
      },
      totals: {
        constants: 16_907,
        prototypes: 902,
        instructions: 261_864,
        constantChannelReferences: 111_017,
        stringConstantChannelReferences: 50_896,
        prototypeReferences: 1_088,
        unresolvedConstantReferences: 0,
        unresolvedPrototypeReferences: 0,
      },
      semanticSectionIndex: 2,
      sections: [
        {
          index: 1,
          kind: "outer-loader",
          byteRange: [0, 221_167],
          wrappedConstants: false,
          constants: 2_335,
          prototypes: 371,
          instructions: 34_696,
          captures: 106,
          constantChannelReferences: 15_505,
          stringConstantChannelReferences: 727,
          prototypeReferences: 370,
          unresolvedConstantReferences: 0,
          unresolvedPrototypeReferences: 0,
          rootPrototypeIndex: 302,
          rootInstructions: 1_409,
        },
        {
          index: 2,
          kind: "nested-payload",
          byteRange: [221_567, 2_284_927],
          wrappedConstants: true,
          constants: 14_572,
          prototypes: 531,
          instructions: 227_168,
          captures: 319,
          constantChannelReferences: 95_512,
          stringConstantChannelReferences: 50_169,
          prototypeReferences: 718,
          unresolvedConstantReferences: 0,
          unresolvedPrototypeReferences: 0,
          rootPrototypeIndex: 149,
          rootInstructions: 86_843,
        },
      ],
    });

    const stableRecordArtifacts = [
      ["jnkie-record-summary.json", 2_135, "37c1498f7c8c5e006ed36f88f398afbe3a81f737d6a107f21aed56e0a6f24236"],
      ["jnkie-record-prototypes.jsonl", 129_072, "0a5188e3f180f91ddf2a2ae1a89519563d2c114f78086d8c2b6446ebcbc8d449"],
      ["jnkie-record-constants.jsonl.gz", 1_058_377, "72d04015fd22a285657a8e31fb97bc9d3bca44c378b46cb641ed1794bc3f7421"],
      ["jnkie-record-root.jsonl.gz", 914_330, "737a38fea99012dac5e4c631d05b85c6e4a96c30357f40e958641463850aa6c8"],
      ["jnkie-record-instructions.jsonl.gz", 2_574_060, "642b67e253df5ca9c9e40d26680e2b6dbad7c839311a5aeedc0401f70d2929fb"],
      ["jnkie-records-readable.txt", 117_487, "5031bded474a49a5b85b556c23875159dbe03e2c664a0007eac363fc03df751a"],
      ["jnkie-record-report.md", 1_856, "c7b2d18e50cb8168a70ddccf77b6522c94d81c4e87dcb4e42cf6cddea6012aa4"],
    ] as const;
    for (const [fileName, byteLength, sha256] of stableRecordArtifacts) {
      const recovered = extraction.artifacts.find(
        (artifact) => artifact.fileName === fileName,
      )!;
      expect(recovered.bytes.byteLength, fileName).toBe(byteLength);
      expect(recovered.sha256, fileName).toBe(sha256);
      expect(sha256Bytes(recovered.bytes), fileName).toBe(sha256);
    }

    // The devirtualized target section is the readable deliverable: it must be
    // real Lua that re-parses, carrying the script's own names.
    const devirtualization = extraction.devirtualization!;
    expect(devirtualization.reparses, devirtualization.reparseError).toBe(true);
    expect(devirtualization.coverage.prototypesEmitted).toBe(371);
    expect(devirtualization.coverage.instructionRecords).toBe(34_696);
    expect(devirtualization.coverage.provenRatio).toBeGreaterThan(0.75);
    // Collected from environment lookups with constant keys, not scraped from
    // rendered text, so a global bound to a register still counts.
    expect(devirtualization.coverage.resolvedGlobalNames).toEqual(
      expect.arrayContaining([
        "CFrame",
        "Instance",
        "game",
        "pcall",
        "setmetatable",
      ]),
    );
    // Branch operands carry an addressing mode; resolving it is what makes
    // most of the stream reachable and the decoy remainder prunable.
    expect(devirtualization.coverage.reachableInstructions).toBeGreaterThan(
      devirtualization.coverage.unreachableInstructions * 4,
    );
    expect(devirtualization.coverage.explainedRatio).toBeGreaterThan(0.9);
    // Lua's own keywords are not evidence of a recovered name.
    expect(devirtualization.coverage.resolvedGlobalNames).not.toContain("then");
    // Decoder-protocol records are explained, not unknown.
    expect(devirtualization.coverage.protocolInstructions).toBeGreaterThan(0);
    expect(devirtualization.coverage.explainedRatio).toBeGreaterThan(
      devirtualization.coverage.provenRatio,
    );
    const readableLua = extraction.artifacts.find(
      (artifact) => artifact.fileName === "jnkie-devirtualized.lua",
    )!;
    const readableText = Buffer.from(readableLua.bytes).toString("utf8");
    expect(() => parseLuau(readableText)).not.toThrow();
    // Every unproven opcode keeps its operands rather than being dropped.
    expect(readableText).toContain("[3ziz] unresolved VM op");
    expect(readableText).toContain("synthesized here");

    const semanticArtifact = extraction.artifacts.find(
      (artifact) => artifact.fileName === "jnkie-semantic-pseudocode.compact.txt",
    )!;
    const semanticManifestArtifact = extraction.artifacts.find(
      (artifact) => artifact.fileName === "jnkie-semantic-coverage.json",
    )!;
    const semanticFullArtifact = extraction.artifacts.find(
      (artifact) => artifact.fileName === "jnkie-semantic-pseudocode.full.txt.gz",
    )!;
    const semanticManifest = JSON.parse(
      Buffer.from(semanticManifestArtifact.bytes).toString("utf8"),
    );
    expect(semanticManifest).toMatchObject({
      schemaVersion: 1,
      scope: "conservative-static-pseudocode-not-original-source",
      identity: {
        loaderSha256: sha256Bytes(loader.bytes),
        payloadSha256: sha256Bytes(payload.bytes),
      },
      coverage: {
        sectionCount: 2,
        prototypeCount: 902,
        totalInstructionRecords: 261_864,
      },
      compact: {
        byteLength: semanticArtifact.bytes.byteLength,
        truncated: true,
      },
      fullArtifact: {
        fileName: "jnkie-semantic-pseudocode.full.txt.gz",
        mediaType: "application/gzip",
        compressedByteLength: semanticFullArtifact.bytes.byteLength,
        deterministicHeader: true,
      },
      safety: {
        submittedCodeExecution: "never",
        outputKind: "inert-pseudocode",
      },
    });
    const semanticCoverage = semanticManifest.coverage;
    expect(
      semanticCoverage.provenSemanticInstructions +
        semanticCoverage.decoderProtocolInstructions +
        semanticCoverage.rawUnresolvedInstructions,
    ).toBe(semanticCoverage.totalInstructionRecords);
    expect(semanticCoverage.rawUnresolvedInstructions).toBeGreaterThan(0);
    expect(semanticCoverage.sourceSemanticCoverageRatio).toBeCloseTo(
      semanticCoverage.provenSemanticInstructions /
        semanticCoverage.totalInstructionRecords,
      12,
    );
    expect(
      semanticManifest.compact.includedInstructionRecords +
        semanticManifest.compact.omittedInstructionRecords,
    ).toBe(semanticCoverage.totalInstructionRecords);
    expect(semanticArtifact.bytes.byteLength).toBeLessThanOrEqual(3.5 * 1_024 * 1_024);
    expect(semanticManifest.fullArtifact.uncompressedByteLength).toBeGreaterThan(
      semanticArtifact.bytes.byteLength,
    );

    const mutatedPayload = Uint8Array.from(payload.bytes);
    mutatedPayload[mutatedPayload.length - 1] ^= 1;
    expect(resolveKnownJnkieProfile(loader.bytes, mutatedPayload).status).toBe("not-matched");

    const fullAnalysisArtifact = extraction.artifacts.find(
      (artifact) => artifact.fileName === "jnkie-full-static-analysis.json",
    )!;
    const fullAnalysis = JSON.parse(Buffer.from(fullAnalysisArtifact.bytes).toString("utf8"));
    expect(fullAnalysis.schemaVersion).toBe(2);
    expect(fullAnalysis.identity).toEqual({
      loaderSha256: sha256Bytes(loader.bytes),
      payloadSha256: sha256Bytes(payload.bytes),
    });
    expect(fullAnalysis.safety).toEqual({
      execution: "not-executed",
      reachability: "not-evaluated",
      scope: "whole-loader-and-payload-static-scan",
    });
    expect(fullAnalysis.loader.inspectedCharacters).toBe(96_895);
    expect(fullAnalysis.payload.inspectedBytes).toBe(2_284_927);

    const result = await analyzeBytes({ fileName: "jnkie_payload.lua", bytes });
    expect(result.report.selectedPlugin.id).toBe("jnkie-luraph-14-static");
    expect(result.report.status).toBe("partial");
    expect(result.extractedArtifacts).toHaveLength(31);
    // The Readable pane now serves devirtualized Lua; the register pseudocode
    // remains available as an artifact rather than as the headline output.
    expect(result.report.analysis.readableKind).toBe("devirtualized-lua");
    expect(result.readableSource).toContain("Recovered by 3ziz Deobfuscator");
    expect(result.readableSource).toContain("submitted code was never executed");
    expect(result.readableSource).toContain("local function fn");
    expect(result.readableSource).not.toContain("statically formatted current VM loader");
    expect(result.readableSource?.split(/\r?\n/).length).toBeGreaterThan(10_000);
    expect(() => parseLuau(result.readableSource!)).not.toThrow();
    const pseudocode = result.extractedArtifacts.find(
      (artifact) => artifact.fileName === "jnkie-semantic-pseudocode.compact.txt",
    )!;
    expect(Buffer.from(pseudocode.bytes).toString("utf8")).toContain(
      "3ZIZ JNKIE CONSERVATIVE SEMANTIC PSEUDOCODE",
    );
    expect(result.report.analysis.luraphAudit).toBeUndefined();
    expect(result.report.analysis.jnkieRecovery).toMatchObject({
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
      submittedCodeExecuted: false,
    });
    expect(result.report.validation.valid).toBe(true);
    expect(result.report.diagnostics.some((item) => item.code === "JNKIE_TWO_SECTION_RECORD_DECODE")).toBe(true);
    expect(result.report.diagnostics.some((item) => item.code === "JNKIE_SEMANTIC_LIFT_PARTIAL")).toBe(true);
    expect(result.report.diagnostics.some((item) => item.code === "JNKIE_CURRENT_STREAM_PROFILE_MATCH")).toBe(true);
    expect(result.report.diagnostics.some((item) => item.code === "JNKIE_UNVERIFIED_EARLIER_SAMPLE_REFERENCES")).toBe(true);
    expect(result.report.diagnostics.some((item) => item.code === "JNKIE_VM_NOT_EXECUTED")).toBe(true);
    expect(result.report.diagnostics.some((item) => item.code === "JNKIE_RECORD_RECOVERY_VALIDATED")).toBe(true);

    const validatedArtifacts = result.extractedArtifacts;
    const selectedDetection = result.report.detections.find(
      (detection) => detection.pluginId === jnkieLuraphPlugin.manifest.id,
    );
    if (validatedArtifacts === undefined || selectedDetection === undefined) {
      throw new Error("Expected complete JNKIE validation context.");
    }
    const validateTamper = (
      tamperedArtifacts: readonly ExtractedArtifact[],
      analysis: PluginAnalysis = result.report.analysis,
    ) => jnkieLuraphPlugin.validate({
      fileName: "jnkie_payload.lua",
      bytes: result.exactBytes,
      text: source,
      classification: result.report.input.classification,
      inputSha256: result.report.input.sha256,
      selectedDetection,
      limits: DEFAULT_ANALYSIS_LIMITS,
      extractedArtifacts: tamperedArtifacts,
      analysis,
    });

    const compressedLoader = validatedArtifacts.find(
      (artifact) => artifact.fileName === "jnkie-loader.compressed.bin",
    )!;
    const tamperedCompressedBytes = Uint8Array.from(compressedLoader.bytes);
    tamperedCompressedBytes[0] ^= 1;
    const compressedTamperValidation = await validateTamper(
      replaceArtifactBytes(
        validatedArtifacts,
        compressedLoader.fileName,
        tamperedCompressedBytes,
      ),
    );
    expect(compressedTamperValidation.valid).toBe(false);
    expect(compressedTamperValidation.diagnostics.some(
      (diagnostic) => diagnostic.code === "JNKIE_BASE_PROVENANCE_VALIDATION_FAILED",
    )).toBe(true);

    for (const fileName of [
      "jnkie-payload.compressed.bin",
      "jnkie-payload.bin",
    ] as const) {
      const originalArtifact = validatedArtifacts.find(
        (artifact) => artifact.fileName === fileName,
      )!;
      const tamperedBytes = Uint8Array.from(originalArtifact.bytes);
      tamperedBytes[0] ^= 1;
      const validation = await validateTamper(
        replaceArtifactBytes(validatedArtifacts, fileName, tamperedBytes),
      );
      expect(validation.valid, fileName).toBe(false);
      expect(validation.diagnostics.some(
        (diagnostic) => diagnostic.code === "JNKIE_BASE_PROVENANCE_VALIDATION_FAILED",
      ), fileName).toBe(true);
    }

    const tamperedFullAnalysis = structuredClone(fullAnalysis);
    tamperedFullAnalysis.payload.inspectedBytes += 1;
    const fullAnalysisTamperValidation = await validateTamper(
      replaceArtifactBytes(
        validatedArtifacts,
        "jnkie-full-static-analysis.json",
        Buffer.from(`${JSON.stringify(tamperedFullAnalysis, null, 2)}\n`, "utf8"),
      ),
    );
    expect(fullAnalysisTamperValidation.valid).toBe(false);
    expect(fullAnalysisTamperValidation.diagnostics.some(
      (diagnostic) => diagnostic.code === "JNKIE_WHOLE_BUFFER_VALIDATION_FAILED",
    )).toBe(true);

    const payloadReportTamperValidation = await validateTamper(
      replaceArtifactBytes(
        validatedArtifacts,
        "jnkie-payload-report.md",
        Buffer.from(`${payloadReportText}\n<!-- self-consistent tamper -->\n`, "utf8"),
      ),
    );
    expect(payloadReportTamperValidation.valid).toBe(false);
    expect(payloadReportTamperValidation.diagnostics.some(
      (diagnostic) => diagnostic.code === "JNKIE_PAYLOAD_REPORT_VALIDATION_FAILED",
    )).toBe(true);

    const tamperedSemanticManifest = structuredClone(semanticManifest);
    tamperedSemanticManifest.fullArtifact.uncompressedByteLength += 1;
    const semanticManifestTamperValidation = await validateTamper(
      replaceArtifactBytes(
        validatedArtifacts,
        "jnkie-semantic-coverage.json",
        Buffer.from(`${JSON.stringify(tamperedSemanticManifest, null, 2)}\n`, "utf8"),
      ),
    );
    expect(semanticManifestTamperValidation.valid).toBe(false);
    expect(semanticManifestTamperValidation.diagnostics.some(
      (diagnostic) => diagnostic.code === "JNKIE_RECORD_RECOVERY_VALIDATION_FAILED",
    )).toBe(true);

    const readableSourceTamperValidation = await validateTamper(
      validatedArtifacts,
      {
        ...result.report.analysis,
        readableSource: `${result.report.analysis.readableSource}\n-- tampered`,
      },
    );
    expect(readableSourceTamperValidation.valid).toBe(false);
    expect(readableSourceTamperValidation.diagnostics.some(
      (diagnostic) => diagnostic.code === "JNKIE_READABLE_ANALYSIS_VALIDATION_FAILED",
    )).toBe(true);

    const readableKindTamperValidation = await validateTamper(
      validatedArtifacts,
      {
        ...result.report.analysis,
        readableKind: "vm-loader",
      },
    );
    expect(readableKindTamperValidation.valid).toBe(false);
    expect(readableKindTamperValidation.diagnostics.some(
      (diagnostic) => diagnostic.code === "JNKIE_READABLE_ANALYSIS_VALIDATION_FAILED",
    )).toBe(true);

    const payloads = buildExpandedArtifactPayloads(result);
    const exportedNames = payloads.map((artifact) => artifact.fileName);
    expect(exportedNames).toContain("jnkie-loader.lua");
    expect(exportedNames).toContain("jnkie-payload.bin");
    expect(exportedNames).toContain("jnkie-record-summary.json");
    expect(exportedNames).toContain("jnkie-record-instructions.jsonl.gz");
    expect(exportedNames).toContain("jnkie-semantic-pseudocode.compact.txt");
    expect(exportedNames).toContain("jnkie-semantic-pseudocode.full.txt.gz");
    expect(exportedNames).toContain("jnkie-known-prototypes.json");
    expect(exportedNames).toContain(KNOWN_JNKIE_READABLE_ARTIFACT);
    expect(exportedNames).toContain(KNOWN_JNKIE_AUDIT_ARTIFACT);
    expect(payloads.filter((artifact) => artifact.role === "extracted-payload")).toHaveLength(31);
    const exactAudit = payloads.find((artifact) => artifact.role === "exact-audit")!;
    expect(exactAudit.bytes.byteLength).toBe(bytes.byteLength);
    expect(sha256Bytes(exactAudit.bytes)).toBe("948d4039bf0640b2f2e07501e8761f9364f34b28a4a0adfe6d2464b57355e2c1");
    expect(Buffer.from(exactAudit.bytes).equals(bytes)).toBe(true);
    expect(payloads.every((artifact) => artifact.bytes.byteLength > 0)).toBe(true);
  }, 60_000);
});
