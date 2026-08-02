import { describe, expect, it } from "vitest";

import {
  fileNameFromPath,
  formatBytes,
  normalizeAnalysisResult,
  normalizeConfidence,
  normalizeStatus,
} from "./model";
import type { AnalysisResult } from "./api";

describe("renderer model helpers", () => {
  it("maps honest recovery states without treating warnings as verified", () => {
    expect(normalizeStatus("completed")).toBe("verified");
    expect(normalizeStatus("recovered-with-warnings")).toBe("partial");
    expect(normalizeStatus("unsupported")).toBe("unsupported");
    expect(normalizeStatus("failed-validation")).toBe("failed");
  });

  it("normalizes confidence from fractions and percentages", () => {
    expect(normalizeConfidence(0.82)).toBe(0.82);
    expect(normalizeConfidence(82)).toBe(0.82);
    expect(normalizeConfidence(140)).toBe(1);
  });

  it("formats file metadata for Windows paths", () => {
    expect(fileNameFromPath("C:\\samples\\input.luau")).toBe("input.luau");
    expect(formatBytes(1536)).toBe("1.50 KB");
  });

  it("preserves derived JNKIE records, semantic statistics, and readable kind", () => {
    const result: AnalysisResult = {
      jobId: "jnkie-job",
      status: "partial",
      readableKind: "register-pseudocode",
      detection: {
        pluginId: "jnkie-luraph-14-static",
        confidence: 0.99,
      },
      artifacts: {
        readable: "prototype_1: -- conservative pseudocode",
        decodedRecords: "section 1\nsection 2\n",
      },
      diagnostics: [
        {
          severity: "warning",
          message: "A diagnostic is not a semantic instruction count.",
        },
      ],
      statistics: {
        recordSections: 2,
        prototypes: 371,
        instructions: 227_168,
        constants: 2_335,
        constantReferences: 9_270,
        stringReferences: 669,
        childReferences: 370,
        resolvedChildReferences: 370,
        decodedBytes: 2_284_527,
        unresolvedBytes: 400,
        outerRootPrototype: 302,
        nestedRootPrototype: 1,
        semanticInstructions: 120_000,
        protocolInstructions: 80_000,
        unknownInstructions: 27_168,
        semanticCoverageRatio: 0.6,
      },
    };

    const normalized = normalizeAnalysisResult(result, "C:\\samples\\jnkie.lua");
    expect(normalized.readableKind).toBe("register-pseudocode");
    expect(normalized.artifacts.decodedRecords).toContain("section 2");
    expect(normalized.statistics).toMatchObject(result.statistics ?? {});
    expect(normalized.statistics.unknownInstructions).toBe(27_168);
    expect(normalized.statistics.warnings).toBe(1);
  });

  it("defaults legacy JNKIE results to VM-loader readability", () => {
    const normalized = normalizeAnalysisResult({
      jobId: "legacy-jnkie",
      status: "partial",
      detection: { pluginId: "jnkie-luraph-14-static" },
      artifacts: { readable: "local loader = {}" },
    });

    expect(normalized.readableKind).toBe("vm-loader");
  });
});
