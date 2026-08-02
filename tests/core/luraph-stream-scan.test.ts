import { describe, expect, it } from "vitest";

import {
  decodeLuraphAscii85,
  looksLikeRawLzma,
  luraphAscii85Candidates,
  scanLuraphEncodedStreams,
  unescapeLuaString,
} from "../../src/core/luraph/stream-scan";

describe("Luraph encoded stream scanning", () => {
  it("resolves the Lua escape forms the wrappers emit", () => {
    expect(unescapeLuaString("plain")).toBe("plain");
    expect(unescapeLuaString("\\60i\\56")).toBe("<i8");
    expect(unescapeLuaString("\\95_index")).toBe("__index");
    expect(unescapeLuaString("\\33")).toBe("!");
    expect(unescapeLuaString("\\x41")).toBe("A");
    expect(unescapeLuaString("a\\z   \nb")).toBe("ab");
    expect(unescapeLuaString("\\\\")).toBe("\\");
  });

  it("follows Lua 5.1 for unknown escapes and rejects impossible ones", () => {
    // Lua 5.1 yields the escaped character; wrappers hide text this way.
    expect(unescapeLuaString("r\\101\\s\\116")).toBe("rest");
    expect(() => unescapeLuaString("\\256")).toThrow(/outside the byte range/);
    expect(() => unescapeLuaString("trailing\\")).toThrow(/dangling backslash/);
  });

  it("finds markers inside long-bracket and quoted literals alike", () => {
    const source = [
      "local a = [==[LPHAAAAAA]==]",
      'local b = u("LPH!\\33\\33\\33\\33\\33", 5)',
    ].join("\n");
    const streams = scanLuraphEncodedStreams(source);
    expect(streams).toHaveLength(2);
    expect(streams[0]?.literalKind).toBe("long-bracket");
    expect(streams[0]?.text).toBe("LPHAAAAAA");
    expect(streams[0]?.declaredSubIndex).toBeNull();
    expect(streams[1]?.literalKind).toBe("quoted");
    expect(streams[1]?.text).toBe("LPH!!!!!!");
    expect(streams[1]?.declaredSubIndex).toBe(5);
  });

  it("ignores LPH text that is not the head of a literal", () => {
    expect(scanLuraphEncodedStreams("-- mentions LPH in a comment")).toEqual([]);
    expect(scanLuraphEncodedStreams('local s = "not LPH here"')).toEqual([]);
  });

  it("decodes groups in both byte orders", () => {
    expect([...decodeLuraphAscii85("!!!!!")]).toEqual([0, 0, 0, 0]);
    expect([...decodeLuraphAscii85("z")]).toEqual([0, 0, 0, 0]);
    // 85^4 == 0x0159_5E4D, so "!!!\"!" is a group with distinguishable bytes.
    const little = decodeLuraphAscii85('!!!"!', {
      headerSkip: 0,
      wordOrder: "little",
    });
    const big = decodeLuraphAscii85('!!!"!', {
      headerSkip: 0,
      wordOrder: "big",
    });
    expect([...big]).toEqual([...little].reverse());
  });

  it("sizes its output for zero-shorthand expansion", () => {
    // Five `z` shorthands expand to five whole groups from five characters,
    // which a length/5 estimate would under-allocate and silently truncate.
    expect(decodeLuraphAscii85("zzzzz").byteLength).toBe(20);
    expect([...decodeLuraphAscii85("zzzzz")].every((byte) => byte === 0)).toBe(
      true,
    );
  });

  it("refuses malformed groups instead of guessing", () => {
    expect(() => decodeLuraphAscii85("!!!!")).toThrow(/incomplete group/);
    expect(() => decodeLuraphAscii85("!!z!!")).toThrow(/inside a group/);
    expect(() => decodeLuraphAscii85("uuuuu")).toThrow(/32-bit range/);
    expect(() => decodeLuraphAscii85("!!!!!", { headerSkip: 9, wordOrder: "little" }))
      .toThrow(/exceeds the stream length/);
  });

  it("prefers the header skip the wrapper declared at the call site", () => {
    const [stream] = scanLuraphEncodedStreams('local b = u("LPHX!!!!!", 5)');
    const first = luraphAscii85Candidates(stream!).next().value;
    expect(first?.headerSkip).toBe(4);
    expect(first?.wordOrder).toBe("little");
  });

  it("rules out compression from the LZMA range-coder lead byte", () => {
    expect(looksLikeRawLzma(Uint8Array.from([0, 1, 2]))).toBe(true);
    expect(looksLikeRawLzma(Uint8Array.from([0xdf, 1, 2]))).toBe(false);
    expect(looksLikeRawLzma(new Uint8Array())).toBe(false);
  });
});
