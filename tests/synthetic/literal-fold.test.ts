import { describe, expect, it } from "vitest";

import type { SourceClassification } from "../../src/shared/contracts";
import { runSourceCleanup } from "../../src/core/passes/source-cleanup";
import { parseLuaFacts } from "../../src/core/source/parse-facts";

const CLASSIFICATION: SourceClassification = {
  kind: "lua-source",
  dialect: "lua-5.1",
  confidence: 1,
  isText: true,
  reasons: ["synthetic test"],
};

function fold(source: string) {
  const before = parseLuaFacts(source, CLASSIFICATION);
  expect(before.parsed).toBe(true);
  return runSourceCleanup(source, CLASSIFICATION, before);
}

describe("literal-only concatenation folding", () => {
  it("folds a nested chain to a byte-safe escaped literal and reparses", () => {
    const result = fold('local value = ("A" .. "\\000") .. "\\255"\nreturn value\n');
    expect(result.source).toContain('"A\\000\\255"');
    const pass = result.passes.find(
      (candidate) => candidate.id === "literal-string-concatenation",
    );
    expect(pass?.applied).toBe(true);
    expect(pass?.edits).toHaveLength(1);
    expect(pass?.factsAfter.functionCount).toBe(pass?.factsBefore.functionCount);
    expect(pass?.factsAfter.callCount).toBe(pass?.factsBefore.callCount);
  });

  it("preserves explicit UTF-8 bytes and decimal-escaped bytes distinctly", () => {
    const result = fold('return "\\195\\169" .. "\\255"\n');
    expect(result.source).toContain('"\\195\\169\\255"');
  });

  it("does not fold long-bracket strings without byte-semantics proof", () => {
    const source = "return [[a]] .. \"b\"\n";
    expect(fold(source).source).toBe(source);
  });

  it("retains comments inside the candidate range", () => {
    const source = 'return "a" -- evidence\n  .. "b"\n';
    expect(fold(source).source).toBe(source);
  });

  it("folds only the literal child while retaining a call and its position", () => {
    const result = fold('return ("a" .. "b") .. effect()\n');
    expect(result.source).toContain('"ab"');
    expect(result.source).toContain("effect()");
  });

  it("keeps quote and backslash bytes escaped in readable output", () => {
    const result = fold('return "\\"" .. "\\\\"\n');
    expect(result.source).toContain('"\\"\\\\"');
  });

  it("keeps a numeric escape boundary unambiguous before a digit", () => {
    const result = fold('return "\\001" .. "2"\n');
    expect(result.source).toContain('"\\0012"');
  });
});
