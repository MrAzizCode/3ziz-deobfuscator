import { describe, expect, it } from "vitest";

import { classifyInput } from "../../src/core/classification";
import { runDetectors } from "../../src/core/detectors";
import { selectPlugin } from "../../src/core/plugins";

function bytes(source: string): Uint8Array {
  return Buffer.from(source, "utf8");
}

async function detect(source: string, fileName = "sample.lua") {
  const input = bytes(source);
  const classified = classifyInput(input, fileName);
  const detections = await runDetectors({
    fileName,
    bytes: input,
    classification: classified.classification,
    ...(classified.text === undefined ? {} : { text: classified.text }),
  });
  return { classified, detections, selection: selectPlugin(detections) };
}

describe("input classification and detectors", () => {
  it("classifies ordinary Lua source and selects the generic plugin", async () => {
    const result = await detect("local value = 1\nreturn value\n");
    expect(result.classified.classification.kind).toBe("lua-source");
    expect(result.selection.pluginId).toBe("generic-static");
    expect(result.selection.ambiguous).toBe(false);
  });

  it("recognizes Luau syntax without pretending Lua 5.1 compatibility", async () => {
    const result = await detect(
      "local value: number = 1\nvalue += 2\nreturn value\n",
      "sample.luau",
    );
    expect(result.classified.classification.kind).toBe("luau-source");
    expect(result.classified.classification.reasons).toContain(
      "compound assignment",
    );
  });

  it("recognizes a Lua binary signature without decoding or executing it", () => {
    const result = classifyInput(
      Uint8Array.from([0x1b, 0x4c, 0x75, 0x61, 0x51, 0]),
      "chunk.luac",
    );
    expect(result.classification.kind).toBe("lua-bytecode");
    expect(result.text).toBeUndefined();
  });

  it("keeps a marker hidden in trivia at low confidence", async () => {
    const result = await detect('-- protected with MoonSec V3\nreturn "ok"\n');
    const moonsec = result.detections.find(
      (item) => item.pluginId === "moonsec-v3-static",
    );
    expect(moonsec?.confidence).toBeLessThan(0.7);
    expect(result.selection.pluginId).toBe("generic-static");
  });

  it("scores a structurally dense MoonSec-style wrapper above threshold", async () => {
    const hex = Array.from({ length: 130 }, (_, index) =>
      `n=(n+0x${(index + 17).toString(16)})%0x1f9;`,
    ).join("");
    const loops = Array.from(
      { length: 12 },
      () => "while n%0x19<0x10 do n=n+1;break end;",
    ).join("");
    const escaped = `"${"\\123".repeat(140)}"`;
    const padding = "local q=0;".repeat(5_000);
    const source = `([[This file was protected with MoonSec V3]]):gsub(".+",function()end);local n=0;local e=getfenv and getfenv();${hex}${loops}local s=${escaped};${padding}`;
    const result = await detect(source);
    const moonsec = result.detections.find(
      (item) => item.pluginId === "moonsec-v3-static",
    );
    expect(moonsec?.confidence).toBeGreaterThanOrEqual(0.7);
    expect(result.selection.pluginId).toBe("moonsec-v3-static");
  });

  it("recognizes recovered Luraph VM audit IR", async () => {
    const instructions = Array.from(
      { length: 10 },
      (_, index) =>
        `::L${String(index + 1).padStart(3, "0")}:: JUMP goto L${String(((index + 1) % 10) + 1).padStart(3, "0")}`,
    ).join("\n");
    const source = `--[[ LURAPH PAYLOAD — DEVIRTUALIZED REGISTER-LEVEL RECONSTRUCTION ]]\n-- source path: root\n-- stack slots: 4; decoded instructions: 10; reachable CFG instructions: 10\nlocal function payload_main(...)\n${instructions}\n::L011:: VM_FRAGMENT tmp0 = reg\nend\n`;
    const result = await detect(source, "audit.luau");
    expect(result.classified.classification.kind).toBe("vm-audit-ir");
    expect(result.selection.pluginId).toBe("luraph-audit");
  });
});

