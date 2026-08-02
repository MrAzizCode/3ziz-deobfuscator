/**
 * Infer a Luraph record stream's per-build count biases from the bytes alone.
 *
 * The container framing (ULEB counts, tagged constants, four-word instructions)
 * is stable across builds, but each build offsets its declared counts by
 * arbitrary constants.  Rather than pin those constants per sample, this module
 * recovers them by requiring a candidate to decode the *whole* stream: a wrong
 * bias desynchronizes the reader within a few records and cannot reach the
 * final byte with self-consistent references.
 *
 * Scope: this recovers the three count biases only.  Some builds additionally
 * permute the constant *tag* table (one authorized sample tags strings `0x39`
 * where the 14.7 build uses `110`), which no amount of bias search can undo.
 * Those streams report `unresolved` here and are handled by deriving the
 * reader from the sample's own loader instead.
 *
 * Submitted code is never executed; this is a bounded byte reader run under a
 * search.
 */

import {
  JNKIE_RECORD_FORMAT,
  type JnkieRecordDecodeResult,
  type JnkieRecordFormat,
} from "./jnkie-record-model";
import {
  decodeJnkieRecordStream,
  JnkieRecordDecodeError,
  type JnkieRecordDecodeLimits,
  type JnkieRecordDecodeOptions,
} from "./jnkie-record-decoder";

/**
 * The first ULEB field of a section is the biased constant count, so its
 * decoded value bounds the search: a bias above it can never be valid, and a
 * bias far below it implies an implausible constant count.
 */
export interface RecordFormatInferenceOptions {
  /** Largest plausible decoded count for any of the three biased fields. */
  readonly maxPlausibleCount?: number;
  /** Upper bound on candidate formats evaluated before giving up. */
  readonly maxCandidates?: number;
  readonly limits?: Partial<JnkieRecordDecodeLimits>;
  readonly decodeOptions?: Omit<JnkieRecordDecodeOptions, "format" | "limits">;
}

export interface RecordFormatInferenceSuccess {
  readonly status: "resolved";
  readonly format: JnkieRecordFormat;
  readonly result: JnkieRecordDecodeResult;
  /** How the winning format was obtained, for the evidence trail. */
  readonly source: "known-profile" | "inferred";
  readonly candidatesEvaluated: number;
  readonly diagnostics: readonly string[];
}

export interface RecordFormatInferenceFailure {
  readonly status: "unresolved";
  readonly candidatesEvaluated: number;
  readonly diagnostics: readonly string[];
}

export type RecordFormatInference =
  | RecordFormatInferenceSuccess
  | RecordFormatInferenceFailure;

const DEFAULT_MAX_PLAUSIBLE_COUNT = 100_000;
const DEFAULT_MAX_CANDIDATES = 4_096;
const MAX_DIAGNOSTICS = 24;

/** Read one unsigned LEB128 value, returning null when the field is malformed. */
function readUleb(
  bytes: Uint8Array,
  offset: number,
): { value: number; end: number } | null {
  let value = 0;
  let shift = 1;
  let cursor = offset;
  for (let group = 0; group < 8; group += 1) {
    const byte = bytes[cursor];
    if (byte === undefined) return null;
    cursor += 1;
    value += (byte & 0x7f) * shift;
    if (!Number.isSafeInteger(value)) return null;
    if ((byte & 0x80) === 0) return { value, end: cursor };
    shift *= 128;
  }
  return null;
}

function withFormat(
  base: JnkieRecordFormat,
  constantCountBias: number,
  prototypeCountBias: number,
  instructionCountBias: number,
): JnkieRecordFormat {
  return {
    schemaVersion: base.schemaVersion,
    indexBase: base.indexBase,
    byteRangeConvention: base.byteRangeConvention,
    constantCountBias,
    prototypeCountBias,
    instructionCountBias,
  };
}

/**
 * A decode that reaches the end of the stream can still be coincidental, so
 * require the structural references to resolve as well.  A desynchronized
 * reader produces constant and child-prototype indices that fall outside their
 * pools; a correctly synchronized one resolves essentially all of them.
 */
function isStructurallyCoherent(result: JnkieRecordDecodeResult): boolean {
  const stats = result.statistics;
  if (stats.prototypeCount === 0 || stats.instructionCount === 0) return false;
  if (stats.unresolvedConstantReferenceCount !== 0) return false;
  if (stats.unresolvedPrototypeReferenceCount !== 0) return false;
  return stats.rootPrototypeIndex >= 1 &&
    stats.rootPrototypeIndex <= stats.prototypeCount;
}

/**
 * Try one fully specified format.  Returns the decode result when the stream
 * parses end to end with coherent references, else null.
 */
function evaluate(
  bytes: Uint8Array,
  format: JnkieRecordFormat,
  options: RecordFormatInferenceOptions,
): JnkieRecordDecodeResult | null {
  let result: JnkieRecordDecodeResult;
  try {
    result = decodeJnkieRecordStream(bytes, {
      ...options.decodeOptions,
      format,
      ...(options.limits === undefined ? {} : { limits: options.limits }),
    });
  } catch (error) {
    if (error instanceof JnkieRecordDecodeError) return null;
    throw error;
  }
  return isStructurallyCoherent(result) ? result : null;
}

/**
 * Recover the count biases for one record stream.
 *
 * The known 14.7 profile is evaluated first so an already-supported build keeps
 * its exact previous decode path and byte-for-byte artifacts.
 */
export function inferRecordFormat(
  bytes: Uint8Array,
  options: RecordFormatInferenceOptions = {},
): RecordFormatInference {
  const maxPlausibleCount =
    options.maxPlausibleCount ?? DEFAULT_MAX_PLAUSIBLE_COUNT;
  const maxCandidates = options.maxCandidates ?? DEFAULT_MAX_CANDIDATES;
  const diagnostics: string[] = [];
  let candidatesEvaluated = 0;

  const note = (message: string): void => {
    if (diagnostics.length < MAX_DIAGNOSTICS) diagnostics.push(message);
  };

  const known = evaluate(bytes, JNKIE_RECORD_FORMAT, options);
  candidatesEvaluated += 1;
  if (known !== null) {
    return {
      status: "resolved",
      format: JNKIE_RECORD_FORMAT,
      result: known,
      source: "known-profile",
      candidatesEvaluated,
      diagnostics: ["Matched the known Luraph 14.7 count biases."],
    };
  }
  note("The known Luraph 14.7 count biases did not decode this stream.");

  // The stream opens with the biased constant count, which caps its own bias.
  const constantField = readUleb(bytes, 0);
  if (constantField === null) {
    note("The leading constant-count field is not a readable ULEB value.");
    return { status: "unresolved", candidatesEvaluated, diagnostics };
  }

  // A bias of zero means counts are stored plainly; try that before searching.
  const plainFormat = withFormat(JNKIE_RECORD_FORMAT, 0, 0, 0);
  const plain = evaluate(bytes, plainFormat, options);
  candidatesEvaluated += 1;
  if (plain !== null) {
    return {
      status: "resolved",
      format: plainFormat,
      result: plain,
      source: "inferred",
      candidatesEvaluated,
      diagnostics: ["Counts are stored without a bias in this build."],
    };
  }

  /*
   * Search order matters more than search breadth.  The constant bias is
   * recoverable first because it is the only biased field read before any
   * variable-length record, so every candidate constant count is testable
   * independently.  Once the constant pool parses, the prototype and
   * instruction biases follow from the same end-to-end requirement.
   */
  const constantBiasFloor = Math.max(0, constantField.value - maxPlausibleCount);
  for (
    let constantBias = constantField.value;
    constantBias >= constantBiasFloor;
    constantBias -= 1
  ) {
    if (candidatesEvaluated >= maxCandidates) {
      note(`Stopped after ${candidatesEvaluated} candidate formats.`);
      break;
    }
    const probe = probeSectionBiases(
      bytes,
      constantBias,
      maxPlausibleCount,
      maxCandidates - candidatesEvaluated,
      options,
    );
    candidatesEvaluated += probe.evaluated;
    if (probe.format !== null && probe.result !== null) {
      return {
        status: "resolved",
        format: probe.format,
        result: probe.result,
        source: "inferred",
        candidatesEvaluated,
        diagnostics: [
          `Inferred count biases constant=${probe.format.constantCountBias}, prototype=${probe.format.prototypeCountBias}, instruction=${probe.format.instructionCountBias} by requiring a complete, reference-coherent decode.`,
        ],
      };
    }
  }

  note("No candidate bias set decoded the stream end to end.");
  return { status: "unresolved", candidatesEvaluated, diagnostics };
}

/**
 * Locate a biased count field by running the real decoder and reading the
 * offset it rejects.  A bias of zero makes every biased field decode to an
 * implausibly large count, so the decoder stops at the first one it reaches -
 * which is exactly the field whose bias is being recovered.
 */
function locateBiasedField(
  bytes: Uint8Array,
  format: JnkieRecordFormat,
  suffix: string,
  options: RecordFormatInferenceOptions,
): number | null {
  try {
    decodeJnkieRecordStream(bytes, {
      ...options.decodeOptions,
      format,
      decodeNestedSection: false,
      ...(options.limits === undefined ? {} : { limits: options.limits }),
    });
    return null;
  } catch (error) {
    if (!(error instanceof JnkieRecordDecodeError)) throw error;
    return error.field.endsWith(suffix) ? error.offset : null;
  }
}

/**
 * Given a candidate constant bias, recover the prototype and instruction
 * biases.  Each is located by letting the decoder walk up to it, then searched
 * downward from the value actually stored there - a bias can never exceed the
 * biased value it is subtracted from.
 */
function probeSectionBiases(
  bytes: Uint8Array,
  constantBias: number,
  maxPlausibleCount: number,
  maxEvaluations: number,
  options: RecordFormatInferenceOptions,
): {
  format: JnkieRecordFormat | null;
  result: JnkieRecordDecodeResult | null;
  evaluated: number;
} {
  let evaluated = 0;
  const empty = { format: null, result: null, evaluated: 0 };

  const prototypeOffset = locateBiasedField(
    bytes,
    withFormat(JNKIE_RECORD_FORMAT, constantBias, 0, 0),
    ".prototypeCount",
    options,
  );
  if (prototypeOffset === null) return empty;
  const prototypeField = readUleb(bytes, prototypeOffset);
  if (prototypeField === null) return empty;

  const prototypeFloor = Math.max(0, prototypeField.value - maxPlausibleCount);
  for (
    let prototypeBias = prototypeField.value;
    prototypeBias >= prototypeFloor;
    prototypeBias -= 1
  ) {
    if (evaluated >= maxEvaluations) break;
    const instructionOffset = locateBiasedField(
      bytes,
      withFormat(JNKIE_RECORD_FORMAT, constantBias, prototypeBias, 0),
      ".instructionCount",
      options,
    );
    evaluated += 1;
    if (instructionOffset === null) continue;
    const instructionField = readUleb(bytes, instructionOffset);
    if (instructionField === null) continue;

    const instructionFloor = Math.max(
      0,
      instructionField.value - maxPlausibleCount,
    );
    for (
      let instructionBias = instructionField.value;
      instructionBias >= instructionFloor;
      instructionBias -= 1
    ) {
      if (evaluated >= maxEvaluations) break;
      const candidate = withFormat(
        JNKIE_RECORD_FORMAT,
        constantBias,
        prototypeBias,
        instructionBias,
      );
      evaluated += 1;
      const result = evaluate(bytes, candidate, options);
      if (result !== null) return { format: candidate, result, evaluated };
    }
  }
  return { format: null, result: null, evaluated };
}
