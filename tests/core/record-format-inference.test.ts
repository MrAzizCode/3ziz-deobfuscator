import { describe, expect, it } from "vitest";

import { JNKIE_RECORD_FORMAT } from "../../src/core/recovery/jnkie-record-model";
import { inferRecordFormat } from "../../src/core/recovery/record-format-inference";

/** Unsigned LEB128, matching the reader in jnkie-record-decoder. */
function uleb(value: number): number[] {
  const bytes: number[] = [];
  let remaining = value;
  do {
    const byte = remaining % 128;
    remaining = Math.floor(remaining / 128);
    bytes.push(remaining > 0 ? byte | 0x80 : byte);
  } while (remaining > 0);
  return bytes;
}

interface SyntheticBiases {
  readonly constantCountBias: number;
  readonly prototypeCountBias: number;
  readonly instructionCountBias: number;
}

/**
 * Build a minimal but complete single-section record stream so bias recovery
 * can be exercised without depending on a supplied sample.
 *
 * Two constants (negative-u8 form, tag <= 6) and two prototypes, one of which
 * references constant 1 through a mode-2 channel so the reference-coherence
 * check in the inference oracle actually has something to resolve.
 */
function buildSection(biases: SyntheticBiases): Uint8Array {
  const constantCount = 2;
  const prototypes = [
    // instruction words are [wordA, opcode, wordN, wordQ]; word % 8 is the mode
    { instructions: [[7, 136, 7, 7]], selector: 0, captures: [], maxStack: 2 },
    // 2 + 8 * 1 encodes mode 2 (constant channel) referencing constant 1
    { instructions: [[10, 9, 7, 7], [7, 84, 7, 7]], selector: 0, captures: [3], maxStack: 4 },
  ];

  const bytes: number[] = [];
  bytes.push(...uleb(constantCount + biases.constantCountBias));
  bytes.push(0); // wrappedConstants
  for (let index = 0; index < constantCount; index += 1) {
    bytes.push(1, index); // tag 1 -> negative-u8 integer
  }
  bytes.push(...uleb(prototypes.length + biases.prototypeCountBias));
  for (const prototype of prototypes) {
    bytes.push(
      ...uleb(prototype.instructions.length + biases.instructionCountBias),
    );
    for (const words of prototype.instructions) {
      for (const word of words) bytes.push(...uleb(word));
    }
    bytes.push(...uleb(prototype.selector));
    bytes.push(...uleb(prototype.captures.length));
    for (const capture of prototype.captures) bytes.push(...uleb(capture));
    bytes.push(...uleb(prototype.maxStack));
  }
  bytes.push(...uleb(1)); // rootPrototypeIndex
  return Uint8Array.from(bytes);
}

const limits = {
  maxInputBytes: 4_096,
  maxConstants: 64,
  maxConstantValueBytes: 256,
  maxPrototypes: 64,
  maxInstructionsPerPrototype: 64,
  maxInstructionsTotal: 256,
  maxCapturesPerPrototype: 16,
  maxCapturesTotal: 64,
};

const decodeOptions = {
  decodeNestedSection: false,
  rejectTrailingBytes: true,
} as const;

describe("record format inference", () => {
  it("recovers biases that no known profile supplies", () => {
    const biases = {
      constantCountBias: 4_211,
      prototypeCountBias: 907,
      instructionCountBias: 1_533,
    };
    const inference = inferRecordFormat(buildSection(biases), {
      limits,
      decodeOptions,
      maxPlausibleCount: 64,
    });

    expect(inference.status).toBe("resolved");
    if (inference.status !== "resolved") return;
    expect(inference.source).toBe("inferred");
    expect(inference.format.constantCountBias).toBe(biases.constantCountBias);
    expect(inference.format.prototypeCountBias).toBe(biases.prototypeCountBias);
    expect(inference.format.instructionCountBias).toBe(
      biases.instructionCountBias,
    );
    expect(inference.result.statistics.prototypeCount).toBe(2);
    expect(inference.result.statistics.instructionCount).toBe(3);
    expect(inference.result.statistics.unresolvedConstantReferenceCount).toBe(0);
    expect(inference.result.statistics.resolvedConstantReferenceCount).toBe(1);
  });

  it("recognizes a build that stores counts without any bias", () => {
    const inference = inferRecordFormat(
      buildSection({
        constantCountBias: 0,
        prototypeCountBias: 0,
        instructionCountBias: 0,
      }),
      { limits, decodeOptions, maxPlausibleCount: 64 },
    );

    expect(inference.status).toBe("resolved");
    if (inference.status !== "resolved") return;
    expect(inference.format.constantCountBias).toBe(0);
    expect(inference.candidatesEvaluated).toBeLessThanOrEqual(2);
  });

  it("reports unresolved rather than accepting a partial decode", () => {
    // Truncating the stream removes the root index, so no bias can complete it.
    const truncated = buildSection({
      constantCountBias: 11,
      prototypeCountBias: 3,
      instructionCountBias: 5,
    }).slice(0, 12);
    const inference = inferRecordFormat(truncated, {
      limits,
      decodeOptions,
      maxPlausibleCount: 32,
      maxCandidates: 512,
    });

    expect(inference.status).toBe("unresolved");
    expect(inference.diagnostics.length).toBeGreaterThan(0);
  });

  it("keeps the known 14.7 profile as the first candidate", () => {
    // A stream built with the shipped biases must resolve without searching,
    // so an already-supported build keeps its exact previous decode path.
    const inference = inferRecordFormat(buildSection(JNKIE_RECORD_FORMAT), {
      limits,
      decodeOptions,
    });

    expect(inference.status).toBe("resolved");
    if (inference.status !== "resolved") return;
    expect(inference.source).toBe("known-profile");
    expect(inference.candidatesEvaluated).toBe(1);
  });
});
