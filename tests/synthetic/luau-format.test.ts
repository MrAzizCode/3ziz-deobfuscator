import { describe, expect, it } from "vitest";

import { formatLuauStatically, lexLuauStatically } from "../../src/core/source/luau-format";

describe("static Luau formatter", () => {
  it("expands minified control flow without changing tokens", () => {
    const input = "local t=...;return({x=function(S,p)while true do if p==1 then p+=1;continue;else break;end;end;return'S;end'..[[x;y]];end});";
    const result = formatLuauStatically(input);
    expect(result.verifiedTokenPreservation).toBe(true);
    expect(result.lineCount).toBeGreaterThan(8);
    expect(lexLuauStatically(result.source).map((token) => token.raw)).toEqual(
      lexLuauStatically(input).map((token) => token.raw),
    );
    expect(result.source).toContain("'S;end'");
    expect(result.source).toContain("[[x;y]]");
  });

  it("preserves long comments and numeric concatenation boundaries", () => {
    const input = "--[=[ keep;end ]=]\nlocal x=1..2;repeat x=x-1;until x<=0;";
    const result = formatLuauStatically(input);
    expect(result.verifiedTokenPreservation).toBe(true);
    expect(result.source).toContain("1 .. 2");
    expect(result.source).toContain("--[=[ keep;end ]=]");
  });
});
