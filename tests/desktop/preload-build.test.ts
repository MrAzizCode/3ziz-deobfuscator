import { readFile } from "node:fs/promises";
import { resolve } from "node:path";

import { describe, expect, it } from "vitest";

describe("sandboxed preload source", () => {
  it("has no sibling runtime imports that Electron's sandboxed preload cannot load", async () => {
    const source = await readFile(
      resolve("src", "desktop", "preload.ts"),
      "utf8",
    );
    expect(source).not.toMatch(/from\s+["']\.\//);
    expect(source).toContain('from "electron"');
    expect(source).toContain('contextBridge.exposeInMainWorld("deobfuscator"');
  });
});
