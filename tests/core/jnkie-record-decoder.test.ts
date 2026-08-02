import { existsSync, readdirSync, readFileSync, statSync } from "node:fs";
import { join, resolve } from "node:path";
import { gunzipSync } from "node:zlib";

import { describe, expect, it } from "vitest";

import {
  buildJnkieRecordArtifacts,
  buildJnkieRecordSummary,
  parseJnkieRecordSummary,
} from "../../src/core/recovery/jnkie-record-artifacts";
import {
  assertKnownJnkieRecordInvariants,
  decodeJnkieRecordStream,
  JnkieRecordDecodeError,
} from "../../src/core/recovery/jnkie-record-decoder";
import {
  instructionAt,
  JNKIE_RECORD_FORMAT,
  KNOWN_JNKIE_RECORD_INVARIANTS,
} from "../../src/core/recovery/jnkie-record-model";

function uleb(value: number): Buffer {
  if (!Number.isSafeInteger(value) || value < 0) throw new Error("bad fixture uleb");
  const bytes: number[] = [];
  let remaining = BigInt(value);
  do {
    let byte = Number(remaining & 0x7fn);
    remaining >>= 7n;
    if (remaining !== 0n) byte |= 0x80;
    bytes.push(byte);
  } while (remaining !== 0n);
  return Buffer.from(bytes);
}

function fixed(
  length: number,
  write: (buffer: Buffer) => void,
): Buffer {
  const buffer = Buffer.alloc(length);
  write(buffer);
  return buffer;
}

function constant(tag: number, payload: Uint8Array = new Uint8Array()): Buffer {
  return Buffer.concat([Buffer.from([tag]), Buffer.from(payload)]);
}

interface SyntheticPrototype {
  readonly words: readonly (readonly [number, number, number, number])[];
  readonly selector: number;
  readonly captures: readonly number[];
  readonly maxStack: number;
}

function sectionBytes(
  constants: readonly Uint8Array[],
  prototypes: readonly SyntheticPrototype[],
  rootPrototypeIndex: number,
  wrappedConstants = false,
): Buffer {
  const chunks: Uint8Array[] = [
    uleb(JNKIE_RECORD_FORMAT.constantCountBias + constants.length),
    Buffer.from([wrappedConstants ? 1 : 0]),
    ...constants,
    uleb(JNKIE_RECORD_FORMAT.prototypeCountBias + prototypes.length),
  ];
  for (const prototype of prototypes) {
    chunks.push(
      uleb(JNKIE_RECORD_FORMAT.instructionCountBias + prototype.words.length),
    );
    for (const words of prototype.words) {
      for (const word of words) chunks.push(uleb(word));
    }
    chunks.push(uleb(prototype.selector), uleb(prototype.captures.length));
    for (const capture of prototype.captures) chunks.push(uleb(capture));
    chunks.push(uleb(prototype.maxStack));
  }
  chunks.push(uleb(rootPrototypeIndex));
  return Buffer.concat(chunks);
}

function syntheticConstants(): readonly Buffer[] {
  return [
    constant(0, Buffer.from([7])),
    constant(
      49,
      Buffer.concat([
        fixed(4, (buffer) => buffer.writeUInt32LE(0xffff_fffe)),
        fixed(4, (buffer) => buffer.writeUInt32LE(0xffff_ffff)),
      ]),
    ),
    constant(110, Buffer.concat([uleb(2), Buffer.from([0xff, 0x41])])),
    constant(139, fixed(8, (buffer) => buffer.writeDoubleLE(1.5))),
    constant(105),
    constant(180),
    constant(220, fixed(4, (buffer) => buffer.writeFloatLE(-0))),
    constant(245, Buffer.concat([uleb(3), Buffer.from([1, 2, 3])])),
  ];
}

function syntheticPrototypes(): readonly SyntheticPrototype[] {
  return [
    {
      words: [
        [3 * 8 + 2, 71, 3 * 8 + 7, 2 * 8 + 4],
        [4 * 8 + 3, 136, 1 * 8 + 6, 9 * 8 + 1],
      ],
      selector: 0,
      captures: [5],
      maxStack: 4,
    },
    {
      words: [[1 * 8 + 2, 118, 7, 7]],
      selector: 1,
      captures: [],
      maxStack: 2,
    },
  ];
}

function syntheticSection(wrappedConstants = false): Buffer {
  return sectionBytes(
    syntheticConstants(),
    syntheticPrototypes(),
    2,
    wrappedConstants,
  );
}

function lines(bytes: Uint8Array): readonly string[] {
  return Buffer.from(bytes)
    .toString("utf8")
    .trimEnd()
    .split("\n");
}

describe("bounded JNKIE record decoder", () => {
  it("preserves exact constants, one-based indices, modes, references, and ranges", () => {
    const bytes = syntheticSection();
    const decoded = decodeJnkieRecordStream(bytes);
    expect(decoded.sections).toHaveLength(1);
    expect(decoded.semanticSection).toBe(decoded.primarySection);
    expect(decoded.statistics).toMatchObject({
      constantCount: 8,
      prototypeCount: 2,
      instructionCount: 3,
      constantReferenceCount: 2,
      stringConstantReferenceCount: 1,
      prototypeReferenceCount: 1,
      unresolvedConstantReferenceCount: 0,
      unresolvedPrototypeReferenceCount: 0,
      rootPrototypeIndex: 2,
      rootInstructionCount: 1,
    });

    const negative = decoded.constants[0]!;
    expect(negative).toMatchObject({
      index: 1,
      kind: "integer",
      encoding: "negative-u8",
      exactDecimal: "-7",
    });
    const wide = decoded.constants[1]!;
    expect(wide).toMatchObject({
      index: 2,
      kind: "integer",
      encoding: "signed-two-u32",
      exactDecimal: "-2",
    });
    const string = decoded.constants[2]!;
    expect(string.kind).toBe("string");
    if (string.kind !== "string") throw new Error("fixture string was not decoded");
    expect(string.utf8Text).toBeNull();
    expect(Buffer.from(string.valueBase64, "base64")).toEqual(Buffer.from([0xff, 0x41]));
    const negativeZero = decoded.constants[6]!;
    expect(negativeZero).toMatchObject({
      kind: "float",
      encoding: "f32",
      displayValue: "-0",
      ieee754Hex: "00000080",
    });
    for (const record of decoded.constants) {
      expect(Buffer.from(record.encodedBase64, "base64")).toEqual(
        bytes.subarray(record.byteRange.start, record.byteRange.end),
      );
    }

    const first = instructionAt(decoded.prototypes[0]!.instructions, 1);
    expect(first.pc).toBe(1);
    expect(first.channels.A).toMatchObject({
      mode: 2,
      payload: 3,
      constantIndex: 3,
    });
    expect(first.channels.Q).toMatchObject({
      mode: 4,
      payload: 2,
      childPrototypeIndex: 2,
    });
    const second = instructionAt(decoded.prototypes[0]!.instructions, 2);
    expect(second.channels.A.resolvedValue).toBe(6);
    expect(second.channels.N.resolvedValue).toBe(1);
    expect(second.channels.Q.resolvedValue).toBe(9);
    expect(second.wordByteRanges[3].end).toBe(second.byteRange.end);
    expect(() => instructionAt(decoded.prototypes[0]!.instructions, 0)).toThrow(
      RangeError,
    );
  });

  it("decodes the second section after the exact 400-byte opaque prelude", () => {
    const outer = syntheticSection();
    const nested = syntheticSection(true);
    const prelude = Buffer.alloc(400, 0xa5);
    const bytes = Buffer.concat([outer, prelude, nested]);
    const decoded = decodeJnkieRecordStream(bytes, { requireNestedSection: true });
    expect(decoded.sections.map((section) => section.kind)).toEqual([
      "outer-loader",
      "nested-payload",
    ]);
    expect(decoded.semanticSection.index).toBe(2);
    expect(decoded.wrappedConstants).toBe(true);
    expect(decoded.statistics).toMatchObject({
      sectionCount: 2,
      decodedBytes: outer.length + nested.length,
      unresolvedBytes: 400,
      trailingBytes: 0,
    });
    expect(decoded.statistics.constantCount).toBe(16);
    expect(decoded.statistics.instructionCount).toBe(6);
    expect(decoded.unresolvedRegions).toEqual([
      expect.objectContaining({
        kind: "interstitial-prelude",
        byteRange: { start: outer.length, end: outer.length + 400 },
        byteLength: 400,
      }),
    ]);
  });

  it.each([
    {
      name: "constants",
      limits: { maxConstants: 12 },
      field: "sections[2].constantCount",
      message: "Aggregate constant count 16 exceeds configured limit 12",
    },
    {
      name: "prototypes",
      limits: { maxPrototypes: 3 },
      field: "sections[2].prototypeCount",
      message: "Aggregate prototype count 4 exceeds configured limit 3",
    },
    {
      name: "instructions",
      limits: { maxInstructionsTotal: 4 },
      field: "prototypes[1].instructionCount",
      message: "Aggregate instruction count 5 exceeds configured limit 4",
    },
    {
      name: "captures",
      limits: { maxCapturesTotal: 1 },
      field: "prototypes[1].captureCount",
      message: "Aggregate capture count 2 exceeds configured limit 1",
    },
  ])("enforces the $name limit across all decoded sections", ({ limits, field, message }) => {
    const section = syntheticSection();
    const bytes = Buffer.concat([section, Buffer.alloc(400), section]);
    try {
      decodeJnkieRecordStream(bytes, { limits });
      throw new Error(`aggregate ${field} fixture unexpectedly decoded`);
    } catch (error) {
      expect(error).toBeInstanceOf(JnkieRecordDecodeError);
      expect(error).toMatchObject({ code: "COUNT_LIMIT", field });
      expect((error as Error).message).toContain(message);
    }
  });

  it("accepts a multi-section stream exactly at every aggregate boundary", () => {
    const section = syntheticSection();
    const decoded = decodeJnkieRecordStream(
      Buffer.concat([section, Buffer.alloc(400), section]),
      {
        requireNestedSection: true,
        limits: {
          maxConstants: 16,
          maxPrototypes: 4,
          maxInstructionsTotal: 6,
          maxCapturesTotal: 2,
        },
      },
    );
    expect(decoded.sections).toHaveLength(2);
    expect(decoded.statistics).toMatchObject({
      constantCount: 16,
      prototypeCount: 4,
      instructionCount: 6,
    });
    expect(
      decoded.sections.reduce(
        (total, decodedSection) => total + decodedSection.statistics.captureCount,
        0,
      ),
    ).toBe(2);
  });

  it("rejects truncation, unsafe ULEBs, limits, invalid roots, and forbidden tails", () => {
    const valid = syntheticSection();
    expect(() => decodeJnkieRecordStream(valid.subarray(0, valid.length - 1))).toThrow(
      JnkieRecordDecodeError,
    );
    try {
      decodeJnkieRecordStream(Buffer.alloc(9, 0x80));
      throw new Error("overflow fixture unexpectedly decoded");
    } catch (error) {
      expect(error).toBeInstanceOf(JnkieRecordDecodeError);
      expect((error as JnkieRecordDecodeError).code).toBe("ULEB_OVERFLOW");
    }
    expect(() =>
      decodeJnkieRecordStream(valid, { limits: { maxConstants: 1 } }),
    ).toThrow(/configured limit/);
    const badRoot = Buffer.from(valid);
    badRoot[badRoot.length - 1] = 3;
    expect(() => decodeJnkieRecordStream(badRoot)).toThrow(/Root prototype 3/);
    expect(() =>
      decodeJnkieRecordStream(Buffer.concat([valid, Buffer.from([1, 2, 3])]), {
        decodeNestedSection: false,
        rejectTrailingBytes: true,
      }),
    ).toThrow(/trailing byte/);
  });
});

describe("JNKIE record artifacts", () => {
  it("emits strict compact metadata and complete deterministic gzip JSONL", () => {
    const outer = syntheticSection();
    const nested = syntheticSection(true);
    const decoded = decodeJnkieRecordStream(
      Buffer.concat([outer, Buffer.alloc(400), nested]),
      { requireNestedSection: true },
    );
    const first = buildJnkieRecordArtifacts(decoded);
    const second = buildJnkieRecordArtifacts(decoded);
    expect(first.map((item) => item.fileName)).toEqual([
      "jnkie-record-summary.json",
      "jnkie-record-prototypes.jsonl",
      "jnkie-record-constants.jsonl.gz",
      "jnkie-record-root.jsonl.gz",
      "jnkie-record-instructions.jsonl.gz",
      "jnkie-records-readable.txt",
      "jnkie-record-report.md",
    ]);
    expect(first.map((item) => item.sha256)).toEqual(
      second.map((item) => item.sha256),
    );
    const byName = new Map(first.map((item) => [item.fileName, item]));
    const summaryBytes = byName.get("jnkie-record-summary.json")!.bytes;
    expect(parseJnkieRecordSummary(summaryBytes)).toEqual(
      buildJnkieRecordSummary(decoded),
    );
    const full = gunzipSync(byName.get("jnkie-record-instructions.jsonl.gz")!.bytes);
    expect(lines(full)).toHaveLength(decoded.statistics.instructionCount + 1);
    const roots = gunzipSync(byName.get("jnkie-record-root.jsonl.gz")!.bytes);
    expect(lines(roots)).toHaveLength(
      decoded.sections.reduce(
        (sum, section) => sum + section.rootPrototype.instructionCount,
        1,
      ),
    );
    const constants = gunzipSync(byName.get("jnkie-record-constants.jsonl.gz")!.bytes);
    expect(lines(constants)).toHaveLength(decoded.statistics.constantCount + 1);
    expect(Buffer.from(byName.get("jnkie-records-readable.txt")!.bytes).toString("utf8"))
      .toContain("Every instruction is retained without truncation");
    expect(Buffer.from(byName.get("jnkie-record-report.md")!.bytes).toString("utf8"))
      .toContain("never executes submitted Lua/Luau");
  });

  it("rejects a summary whose section totals were tampered", () => {
    const decoded = decodeJnkieRecordStream(syntheticSection());
    const summary = buildJnkieRecordSummary(decoded);
    const tampered = JSON.parse(JSON.stringify(summary)) as Record<string, unknown>;
    const totals = tampered.totals as Record<string, unknown>;
    totals.instructions = 99;
    expect(() => parseJnkieRecordSummary(JSON.stringify(tampered))).toThrow(
      /aggregate totals/,
    );
  });
});

function findKnownFixture(): string | undefined {
  const configured = process.env.JNKIE_PAYLOAD_FIXTURE;
  if (configured && existsSync(configured)) return resolve(configured);
  const exact = join(
    process.cwd(),
    "outputs",
    "jnkie_payload_results_v04_verified",
    "6b164acc-72d6-4c29-a4de-0de6c7843a8b",
    "jnkie-payload.bin",
  );
  if (existsSync(exact)) return exact;
  const outputRoot = join(process.cwd(), "outputs");
  if (!existsSync(outputRoot)) return undefined;
  const pending = [outputRoot];
  let visited = 0;
  while (pending.length !== 0 && visited < 2_000) {
    const directory = pending.pop()!;
    visited += 1;
    for (const entry of readdirSync(directory, { withFileTypes: true })) {
      const path = join(directory, entry.name);
      if (entry.isDirectory()) pending.push(path);
      else if (
        entry.name === "jnkie-payload.bin" &&
        statSync(path).size === KNOWN_JNKIE_RECORD_INVARIANTS.inputBytes
      ) {
        return path;
      }
    }
  }
  return undefined;
}

describe("known JNKIE payload fixture (optional)", () => {
  it("proves both exact sections and all 261,864 instruction records when available", () => {
    const fixture = findKnownFixture();
    if (!fixture) return;
    const decoded = decodeJnkieRecordStream(readFileSync(fixture), {
      requireNestedSection: true,
    });
    assertKnownJnkieRecordInvariants(decoded);
    expect(decoded.sections[0]!.statistics.instructionCount).toBe(34_696);
    expect(decoded.sections[1]!.statistics.instructionCount).toBe(227_168);
    expect(decoded.statistics.instructionCount).toBe(261_864);
    expect(decoded.statistics.unresolvedBytes).toBe(400);
    expect(decoded.statistics.trailingBytes).toBe(0);
    expect(decoded.sections[1]!.constants).toContainEqual(
      expect.objectContaining({ kind: "buffer", byteLength: 569_137 }),
    );
  });
});
