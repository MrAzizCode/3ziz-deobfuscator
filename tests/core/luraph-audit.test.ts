import { describe, expect, it } from "vitest";

import { validateLuraphAudit } from "../../src/core/validation/luraph-audit";

const VALID_AUDIT = `--[[ LURAPH PAYLOAD — DEVIRTUALIZED REGISTER-LEVEL RECONSTRUCTION ]]
-- stack slots: 3; decoded instructions: 2; reachable CFG instructions: 2
-- statically applied array patches: 1; unreachable PCs omitted: 0
local function payload_main(...)
  ::L001:: JUMP goto L002
  ::L002:: RETURN_ONE return reg[1]
end
-- Summary: 1 functions, 2 decoded instructions, 1 deterministic self-modifying writes applied.
`;

describe("Luraph audit validation", () => {
  it("validates metadata and per-function label scope", () => {
    const result = validateLuraphAudit(VALID_AUDIT);
    expect(result.report.valid).toBe(true);
    expect(result.facts).toMatchObject({
      functionCount: 1,
      decodedInstructions: 2,
      reachableInstructions: 2,
      deterministicPatches: 1,
      labelDefinitions: 2,
      gotoReferences: 1,
      summaryMatchesMetadata: true,
    });
  });

  it("reports unresolved goto targets without trying to repair them", () => {
    const result = validateLuraphAudit(
      VALID_AUDIT.replace("goto L002", "goto L999"),
    );
    expect(result.report.valid).toBe(false);
    expect(
      result.report.diagnostics.some(
        (diagnostic) => diagnostic.code === "LURAPH_AUDIT_UNRESOLVED_GOTOS",
      ),
    ).toBe(true);
    expect(result.facts.functions[0]?.unresolvedTargets).toEqual(["L999"]);
  });

  it("reports duplicate labels inside one function", () => {
    const source = VALID_AUDIT.replace(
      "::L002:: RETURN_ONE",
      "::L001:: RETURN_ONE",
    );
    const result = validateLuraphAudit(source);
    expect(result.report.valid).toBe(false);
    expect(result.facts.functions[0]?.duplicateLabels).toEqual(["L001"]);
  });
});

