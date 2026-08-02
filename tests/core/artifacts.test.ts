import { mkdtemp, readFile, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";

import { afterEach, describe, expect, it } from "vitest";

import { analyzeBytes } from "../../src/core/analyze";
import {
  buildExpandedArtifactPayloads,
  writeExpandedJobBundle,
} from "../../src/core/artifacts/expanded-store";
import { sha256Bytes } from "../../src/core/hash";

const temporaryDirectories: string[] = [];

async function temporaryDirectory(): Promise<string> {
  const directory = await mkdtemp(join(tmpdir(), "3ziz-core-test-"));
  temporaryDirectories.push(directory);
  return resolve(directory);
}

afterEach(async () => {
  while (temporaryDirectories.length > 0) {
    const directory = temporaryDirectories.pop();
    if (directory && directory.startsWith(resolve(tmpdir()))) {
      await rm(directory, { recursive: true, force: true });
    }
  }
});

describe("immutable artifact bundles", () => {
  it("emits distinct original, audit, readable, behavior, validation, report, and warnings layers", async () => {
    const result = await analyzeBytes({
      fileName: "sample.lua",
      bytes: Buffer.from('local value = "a" .. "b"\nreturn value\n', "utf8"),
      jobId: "00000000-0000-4000-8000-000000000001",
      createdAt: "2026-07-29T00:00:00.000Z",
    });
    const payloads = buildExpandedArtifactPayloads(result);
    expect(payloads.map((payload) => payload.role)).toEqual([
      "original",
      "exact-audit",
      "readable",
      "behavior-report",
      "validation-report",
      "report",
      "warnings",
    ]);

    const root = await temporaryDirectory();
    const written = await writeExpandedJobBundle(root, result);
    expect(Object.isFrozen(written.manifest)).toBe(true);
    for (const artifact of written.manifest.artifacts) {
      const content = await readFile(join(written.jobDirectory, artifact.fileName));
      expect(content.byteLength).toBe(artifact.byteLength);
      expect(sha256Bytes(content)).toBe(artifact.sha256);
    }
    const original = await readFile(join(written.jobDirectory, "original.lua"));
    expect(Buffer.compare(original, result.exactBytes)).toBe(0);
    await expect(writeExpandedJobBundle(root, result)).rejects.toThrow();
  });

  it("checks the output cap before creating a job directory", async () => {
    const result = await analyzeBytes({
      fileName: "sample.lua",
      bytes: Buffer.from("return 1\n", "utf8"),
      jobId: "00000000-0000-4000-8000-000000000002",
    });
    const root = await temporaryDirectory();
    await expect(writeExpandedJobBundle(root, result, 1)).rejects.toThrow(
      /output limit/,
    );
  });
});

