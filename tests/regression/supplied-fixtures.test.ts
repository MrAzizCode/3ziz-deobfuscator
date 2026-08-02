import { existsSync, readFileSync } from "node:fs";
import { join } from "node:path";

import { describe, expect, it } from "vitest";

import { analyzeBytes } from "../../src/core/analyze";
import { sha256Bytes } from "../../src/core/hash";

const fixtureRoot = process.env.THREEZIZ_FIXTURE_ROOT ?? "D:\\macos";
const moonSecPath = join(fixtureRoot, "Pasted text.txt");
const utopiaPath = join(fixtureRoot, "UtopiaSpy_deobfuscated.lua");
const luraphAuditPath = join(
  fixtureRoot,
  "Pasted text(1).deobfuscated.luau",
);
const compactPath = join(fixtureRoot, "compact.luau");

const allFixturesAvailable = [
  moonSecPath,
  utopiaPath,
  luraphAuditPath,
  compactPath,
].every(existsSync);

const describeFixtures = allFixturesAvailable ? describe : describe.skip;

describeFixtures("authorized supplied fixtures (static reads only)", () => {
  it("detects the exact MoonSec V3 wrapper without executing it", async () => {
    const bytes = readFileSync(moonSecPath);
    expect(bytes.byteLength).toBe(289_894);
    expect(sha256Bytes(bytes)).toBe(
      "d7982ef91a86da1e454db270196510d2e8f48d382f57a140d12028d117f3943d",
    );

    const result = await analyzeBytes({
      fileName: "Pasted text.txt",
      bytes,
      jobId: "fixture-moonsec",
      createdAt: "2026-07-29T00:00:00.000Z",
    });

    expect(result.report.input.classification.kind).toBe("lua-source");
    expect(result.report.selectedPlugin.id).toBe("moonsec-v3-static");
    expect(result.report.selection.rankedDetections[0]?.confidence).toBeGreaterThanOrEqual(
      0.9,
    );
    expect(result.report.status).toBe("partial");
    expect(result.report.diagnostics.some(
      (diagnostic) => diagnostic.code === "MOONSEC_EXTRACTOR_NOT_INSTALLED",
    )).toBe(true);
    expect(sha256Bytes(result.exactBytes)).toBe(result.report.input.sha256);
  });

  it("parses the UtopiaSpy gold output and inventories dangerous APIs", async () => {
    const bytes = readFileSync(utopiaPath);
    const source = bytes.toString("utf8");
    expect(bytes.byteLength).toBe(53_232);
    expect(source.replace(/\r?\n$/, "").split(/\r\n|\r|\n/)).toHaveLength(1_617);
    expect(sha256Bytes(bytes)).toBe(
      "a334cfd737252f406a95a68f50cdb18c1885baecfc3caf55da874b9380c3b5c8",
    );

    const result = await analyzeBytes({
      fileName: "UtopiaSpy_deobfuscated.lua",
      bytes,
      jobId: "fixture-utopia",
      createdAt: "2026-07-29T00:00:00.000Z",
    });

    expect(result.report.selectedPlugin.id).toBe("generic-static");
    expect(result.report.analysis.sourceFacts?.parsed).toBe(true);
    expect(
      result.report.analysis.sourceFacts?.registerIdentifierOccurrences,
    ).toBe(0);
    expect(
      result.report.analysis.behavior?.capabilities.some(
        (finding) =>
          finding.category === "dynamic-code" && finding.api === "loadstring",
      ),
    ).toBe(true);
    expect(result.readableSource).toBeDefined();
  });

  it("validates the supplied Luraph register audit as non-executable VM IR", async () => {
    const bytes = readFileSync(luraphAuditPath);
    expect(sha256Bytes(bytes)).toBe(
      "fe46362f71296988ebfef72cc3301acc45dcc4efe7eea1ac7d3e292369af159a",
    );

    const result = await analyzeBytes({
      fileName: "Pasted text(1).deobfuscated.luau",
      bytes,
      jobId: "fixture-luraph",
      createdAt: "2026-07-29T00:00:00.000Z",
    });

    expect(result.report.input.classification.kind).toBe("vm-audit-ir");
    expect(result.report.selectedPlugin.id).toBe("luraph-audit");
    expect(result.report.status).toBe("partial");
    expect(result.readableSource).toBeUndefined();

    const facts = result.report.analysis.luraphAudit;
    expect(facts).toMatchObject({
      functionCount: 36,
      decodedInstructions: 9_414,
      deterministicPatches: 667,
      ambiguousDecoderWrites: 74,
      labelDefinitions: 6_644,
      gotoReferences: 2_789,
      vmFragments: 495,
    });
    expect(
      facts?.functions.every(
        (func) =>
          func.duplicateLabels.length === 0 &&
          func.unresolvedTargets.length === 0,
      ),
    ).toBe(true);
  });

  it("labels compact Luraph output as Luau audit pseudocode, not Lua 5.1", async () => {
    const bytes = readFileSync(compactPath);
    expect(bytes.byteLength).toBe(6_501);
    expect(sha256Bytes(bytes)).toBe(
      "75f4ff5a7993c5232846e2ad01622e91cc9603c6e8301791e70e94b96d8fe460",
    );

    const result = await analyzeBytes({
      fileName: "compact.luau",
      bytes,
      jobId: "fixture-compact",
      createdAt: "2026-07-29T00:00:00.000Z",
    });

    expect(result.report.input.classification.kind).toBe("luau-source");
    // The Luau front end reads it, but it is never labelled Lua 5.1 source and
    // no readable rewrite is published from a Luau-only parse.
    expect(result.report.analysis.sourceFacts?.mode).toBe("luau-ast");
    expect(result.report.analysis.readableSource).toBeUndefined();
    expect(result.report.status).toBe("partial");
  });
});

