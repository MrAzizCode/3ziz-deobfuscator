import { describe, expect, it } from "vitest";

import type { SourceClassification } from "../../src/shared/contracts";
import { parseLuaFacts } from "../../src/core/source/parse-facts";
import { runSourceCleanup } from "../../src/core/passes/source-cleanup";

const CLASSIFICATION: SourceClassification = {
  kind: "lua-source",
  dialect: "lua-5.1",
  confidence: 1,
  isText: true,
  reasons: ["synthetic test"],
};

function cleanup(source: string) {
  const facts = parseLuaFacts(source, CLASSIFICATION);
  expect(facts.parsed).toBe(true);
  return runSourceCleanup(source, CLASSIFICATION, facts);
}

describe("effect-sensitive cleanup barriers", () => {
  it.each([
    "local x = f(); return x",
    "local x = ...; return x",
    "local x = f(); sink(x)",
    "local x = proxy.value; return x",
    "local x = left + right; return x",
    "proxy.object.method(proxy.object, argument)",
    "local a, b = f(); return a, b",
    "local L1_1 = 1; do local L1_1 = 2; print(L1_1) end; return L1_1",
    "local L1_1; L1_1 = function() return L1_1 end; return L1_1",
  ])("leaves hazardous source byte-for-byte unchanged: %s", (source) => {
    const result = cleanup(source);
    expect(result.source).toBe(source);
    expect(result.passes.every((pass) => pass.edits.length === 0)).toBe(true);
  });

  it("skips name-only alpha-renaming when binding identity is not proven", () => {
    const result = cleanup("local L1_1 = input; return L1_1");
    expect(
      result.diagnostics.some(
        (diagnostic) =>
          diagnostic.code === "CLEANUP_ALPHA_RENAME_SKIPPED_SCOPE_PROOF",
      ),
    ).toBe(true);
  });
});

