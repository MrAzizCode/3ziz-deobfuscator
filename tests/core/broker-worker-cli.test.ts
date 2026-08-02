import { mkdtemp, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";

import { describe, expect, it } from "vitest";

import { analyzeFileToJob } from "../../src/core/broker";
import { handleWorkerMessage } from "../../src/core/worker/handler";
import { runCli } from "../../src/cli";

describe("broker, worker, and CLI boundaries", () => {
  it("rejects non-absolute broker paths before reading", async () => {
    await expect(
      analyzeFileToJob({
        inputPath: "relative.lua",
        jobsRoot: "jobs",
      }),
    ).rejects.toThrow(/absolute/);
  });

  it("returns a bounded error response for malformed worker messages", async () => {
    const response = await handleWorkerMessage({ type: "run-shell" });
    expect(response.type).toBe("analysis-error");
    expect(response).toMatchObject({ requestId: "unknown" });
  });

  it("uses one canonical request ID for the analysis and written job", async () => {
    const temporaryRoot = await mkdtemp(join(tmpdir(), "3ziz-worker-id-"));
    const inputPath = join(temporaryRoot, "input.lua");
    const jobsRoot = join(temporaryRoot, "jobs");
    const requestId = "70000000-0000-4000-8000-000000000007";
    try {
      await writeFile(inputPath, "return 1\n", "utf8");
      const response = await handleWorkerMessage({
        type: "analyze-file",
        requestId,
        inputPath,
        jobsRoot,
      });
      expect(response.type).toBe("analysis-complete");
      if (response.type !== "analysis-complete") return;
      expect(response.requestId).toBe(requestId);
      expect(response.result.analysis.report.jobId).toBe(requestId);
      expect(response.result.writtenJob.manifest.jobId).toBe(requestId);
      expect(Object.keys(response.result.analysis)).toEqual(["report"]);
      expect(response.result.analysis).not.toHaveProperty("exactBytes");
      expect(response.result.analysis).not.toHaveProperty("readableSource");
      expect(response.result.analysis).not.toHaveProperty("disassembly");
      expect(response.result.analysis).not.toHaveProperty("extractedArtifacts");
    } finally {
      await rm(temporaryRoot, { recursive: true, force: true });
    }
  });

  it("rejects a non-canonical broker job ID before filesystem use", async () => {
    await expect(analyzeFileToJob({
      inputPath: join(tmpdir(), "not-read.lua"),
      jobsRoot: join(tmpdir(), "not-written"),
      jobId: "../escape",
    })).rejects.toThrow(/canonical UUID/);
  });

  it("lists plugin manifests without exposing executable hooks", async () => {
    let stdout = "";
    let stderr = "";
    const code = await runCli(["plugins"], {
      stdout: (text) => {
        stdout += text;
      },
      stderr: (text) => {
        stderr += text;
      },
    });
    expect(code).toBe(0);
    expect(stderr).toBe("");
    const manifests = JSON.parse(stdout) as { id: string }[];
    expect(manifests.map((manifest) => manifest.id)).toEqual([
      "generic-static",
      "jnkie-luraph-14-static",
      "luraph-audit",
      "moonsec-v3-static",
    ]);
  });
});
