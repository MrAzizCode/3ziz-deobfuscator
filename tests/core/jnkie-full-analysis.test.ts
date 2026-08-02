import { describe, expect, it } from "vitest";

import {
  buildJnkieFullStaticAnalysis,
  inspectJnkieLoaderDeep,
  inspectJnkiePayloadDeep,
  renderJnkieFullAnalysisAppendix,
} from "../../src/core/analysis/jnkie-full-analysis";

describe("JNKIE full static analysis", () => {
  it("scans the complete payload while keeping reports bounded", () => {
    const prefix = Buffer.from("TextButton\0loadstring\0", "ascii");
    const bytes = new Uint8Array(150_000);
    bytes.set(prefix, 0);
    bytes.set(Buffer.from("HttpService\0", "ascii"), 149_980);
    const facts = inspectJnkiePayloadDeep(bytes);
    expect(facts.inspectedBytes).toBe(bytes.length);
    expect(facts.entropyWindows.count).toBe(3);
    expect(facts.indicators).toEqual(expect.arrayContaining(["TextButton", "loadstring", "HttpService"]));
    expect(facts.readableStrings.length).toBeLessThanOrEqual(160);
  });

  it("maps loader control flow without reading strings as code", () => {
    const loader = "return({x=function(S) while true do if S[12345] then S:readu32() else break end end return S end, fake='if while continue'}):x()";
    const facts = inspectJnkieLoaderDeep(loader);
    expect(facts.conditionalCount).toBe(1);
    expect(facts.loopCount).toBe(1);
    expect(facts.uniqueLargeNumericKeys).toBe(1);
    expect(facts.bufferApis).toContain("readu32");
  });

  it("emits a machine-readable model and an honest coverage appendix", () => {
    const analysis = buildJnkieFullStaticAnalysis(
      "return({x=function() return end}):x()",
      Buffer.from("GetAsync\0payload", "ascii"),
    );
    expect(analysis.safety.execution).toBe("not-executed");
    const report = renderJnkieFullAnalysisAppendix(analysis);
    expect(report).toContain("Whole-buffer coverage");
    expect(report).toContain("Every payload byte");
  });
});
