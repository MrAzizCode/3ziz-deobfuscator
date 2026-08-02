import {
  KNOWN_JNKIE_LOADER_SHA256,
  KNOWN_JNKIE_PAYLOAD_SHA256,
} from "./jnkie-known-profile";
import {
  instructionAt,
  type JnkieDecodedConstant,
  type JnkieDecodedInstruction,
  type JnkieDecodedPrototype,
  type JnkieInstructionChannel,
  type JnkieOperandName,
  type JnkieRecordDecodeResult,
  type JnkieRecordSection,
  type JnkieRecordSectionKind,
} from "./jnkie-record-model";
import { gzipSync } from "node:zlib";

/**
 * The emitted text is deliberately not Lua or Luau.  It is an inert,
 * audit-oriented description of handler effects proven from one exact loader.
 */
export const JNKIE_SEMANTIC_SCOPE =
  "conservative-static-pseudocode-not-original-source" as const;

export const JNKIE_UI_PSEUDOCODE_MAX_BYTES = Math.floor(3.5 * 1_024 * 1_024);

const STATEFUL_MICRO_OPCODES = new Set([
  3, 7, 32, 38, 39, 52, 55, 56, 61, 109, 141, 151, 174, 175, 184,
  206, 211, 214, 223, 237, 241, 243, 246, 275, 280,
]);

/**
 * VM decoder-protocol handlers: they move the interpreter's own state rather
 * than the guest program's.  Exported so the devirtualizer can label them as
 * protocol instead of reporting them as unknown.
 */
export const PROTOCOL_OPCODES = new Set([
  39, 51, 52, 56, 81, 91, 98, 166, 203, 238, 239, 244, 247, 248, 277,
  282,
]);

const FUSION_OPCODES = [211, 3, 214, 241, 275] as const;
const FUSION_PAYLOADS = [
  { A: 124, N: 137, Q: 216 },
  { A: 14, N: 178, Q: 56 },
  { A: 134, N: 132, Q: 158 },
  { A: 58, N: 202, Q: 1_734 },
  { A: 23, N: 15, Q: 11 },
] as const;

export interface JnkieSemanticIdentity {
  readonly loaderSha256: string;
  readonly payloadSha256: string;
}

export interface JnkieSemanticCoverage {
  readonly sectionCount: number;
  readonly prototypeCount: number;
  readonly totalInstructionRecords: number;
  readonly provenSemanticInstructions: number;
  readonly decoderProtocolInstructions: number;
  readonly rawUnresolvedInstructions: number;
  /** Stateful micro-operations are a subset of rawUnresolvedInstructions. */
  readonly statefulMicroInstructions: number;
  /** Records replaced by a statically proven multi-record semantic fusion. */
  readonly fusedSemanticInstructions: number;
  readonly emittedStatements: number;
  readonly sourceSemanticCoverageRatio: number;
  readonly explainedHandlerCoverageRatio: number;
  readonly provenOpcodeCounts: Readonly<Record<string, number>>;
  readonly protocolOpcodeCounts: Readonly<Record<string, number>>;
  readonly unresolvedOpcodeCounts: Readonly<Record<string, number>>;
  readonly sections: readonly JnkieSemanticSectionCoverage[];
}

export interface JnkieSemanticSectionCoverage {
  readonly sectionIndex: number;
  readonly sectionKind: JnkieRecordSectionKind;
  readonly prototypeCount: number;
  readonly totalInstructionRecords: number;
  readonly provenSemanticInstructions: number;
  readonly decoderProtocolInstructions: number;
  readonly rawUnresolvedInstructions: number;
  readonly statefulMicroInstructions: number;
  readonly fusedSemanticInstructions: number;
  readonly emittedStatements: number;
  readonly sourceSemanticCoverageRatio: number;
  readonly explainedHandlerCoverageRatio: number;
  readonly provenOpcodeCounts: Readonly<Record<string, number>>;
  readonly protocolOpcodeCounts: Readonly<Record<string, number>>;
  readonly unresolvedOpcodeCounts: Readonly<Record<string, number>>;
}

export type JnkieSemanticEmission =
  | {
      readonly status: "not-applicable";
      readonly scope: typeof JNKIE_SEMANTIC_SCOPE;
      readonly reason: string;
    }
  | {
      readonly status: "emitted";
      readonly scope: typeof JNKIE_SEMANTIC_SCOPE;
      /** Compact UI-safe view. */
      readonly text: string;
      readonly compactText: string;
      readonly compactByteLength: number;
      readonly compactTruncated: boolean;
      readonly compactIncludedInstructionRecords: number;
      readonly compactOmittedInstructionRecords: number;
      /** Complete export-only artifact; never route these bytes into the UI. */
      readonly fullArtifact: Readonly<{
        fileName: "jnkie-semantic-pseudocode.full.txt.gz";
        mediaType: "application/gzip";
        bytes: Uint8Array;
        compressedByteLength: number;
        uncompressedByteLength: number;
        deterministicHeader: true;
      }>;
      readonly coverage: JnkieSemanticCoverage;
      readonly prototypeOrder: readonly {
        readonly sectionIndex: number;
        readonly prototypeIndices: readonly number[];
      }[];
      readonly warnings: readonly string[];
      readonly safety: Readonly<{
        submittedCodeExecution: "never";
        outputKind: "inert-pseudocode";
      }>;
    };

interface RenderedSemantic {
  readonly name: string;
  readonly text: string;
}

interface FusionMatch {
  readonly instructions: readonly JnkieDecodedInstruction[];
  readonly text: string;
}

interface RenderedInstructionBlock {
  readonly lines: readonly string[];
  readonly instructionRecords: number;
  readonly nextPc: number;
}

interface MutableCoverage {
  provenSemanticInstructions: number;
  decoderProtocolInstructions: number;
  rawUnresolvedInstructions: number;
  statefulMicroInstructions: number;
  fusedSemanticInstructions: number;
  emittedStatements: number;
  readonly provenOpcodeCounts: Record<string, number>;
  readonly protocolOpcodeCounts: Record<string, number>;
  readonly unresolvedOpcodeCounts: Record<string, number>;
}

interface OrderedSection {
  readonly section: JnkieRecordSection;
  readonly prototypes: readonly JnkieDecodedPrototype[];
  readonly coverage: JnkieSemanticSectionCoverage;
}

function normalizedHash(value: string): string {
  return value.trim().toLowerCase();
}

function numberText(value: number): string {
  if (Number.isNaN(value)) return "NaN";
  if (value === Number.POSITIVE_INFINITY) return "+Infinity";
  if (value === Number.NEGATIVE_INFINITY) return "-Infinity";
  if (Object.is(value, -0)) return "-0";
  return String(value);
}

function rangeText(start: number, end: number): string {
  return `[${start},${end})`;
}

function register(index: number): string {
  return `R[${numberText(index)}]`;
}

function prototypeName(index: number): string {
  return `P${String(index).padStart(3, "0")}`;
}

function constantName(index: number): string {
  return `C${String(index).padStart(4, "0")}`;
}

function auxiliary(channel: JnkieInstructionChannel): string {
  if (channel.constantIndex !== null) return constantName(channel.constantIndex);
  if (channel.childPrototypeIndex !== null) {
    return prototypeName(channel.childPrototypeIndex);
  }
  if (channel.resolvedValue !== null) return numberText(channel.resolvedValue);
  return numberText(channel.payload);
}

/**
 * Branch destinations honour the operand addressing mode the record decoder
 * already applied: absolute for modes 1 and 7, relative forward for mode 3,
 * relative backward for mode 6.  Reading the raw payload treats every branch as
 * absolute, which points most of them at the wrong instruction.
 *
 * The trailing increment is the dispatcher's post-increment.
 */
function jumpTarget(channel: JnkieInstructionChannel): string {
  const resolved = channel.resolvedValue ?? channel.payload;
  return `PC${String(resolved + 1).padStart(4, "0")}`;
}

function registerSlice(first: number, last: number): string {
  return `REGISTERS(${register(first)} .. ${register(last)})`;
}

function closeOpenUpvalues(): string {
  return "CLOSE_OPEN_UPVALUES(from_register=1)";
}

function genericCallArguments(base: number, encodedCount: number): string {
  if (encodedCount === 0) return `REGISTERS(${register(base + 1)} .. VM_TOP)`;
  if (encodedCount === 1) return "NO_ARGUMENTS";
  return registerSlice(base + 1, base + encodedCount - 1);
}

function genericCallResults(base: number, encodedCount: number): string {
  if (encodedCount === 0) return `ALL_RESULTS(start=${register(base)}, update=VM_TOP)`;
  if (encodedCount === 1) return `DISCARD_RESULTS(update=VM_TOP=${base - 1})`;
  return `${registerSlice(base, base + encodedCount - 2)} (count=${encodedCount - 1}, update=VM_TOP=${base + encodedCount - 1})`;
}

/**
 * Exported so `op-effects` can be checked against it: the typed effect model
 * must resolve exactly the opcodes this table proves, under the same names.
 */
export function knownSemantic(
  instruction: JnkieDecodedInstruction,
  selector: number,
): RenderedSemantic | null {
  // This handler table is proven only for selector zero. The outer stream has
  // one selector-three prototype whose raw opcode numbers mean something else.
  if (selector !== 0) return null;
  const { A, N, Q } = instruction.channels;
  const a = A.payload;
  const nRegister = N.payload;
  const q = Q.payload;
  const K = auxiliary(A);
  const M = auxiliary(N);
  const n = auxiliary(Q);

  switch (instruction.rawOpcode) {
    case 1:
      return {
        name: "NEW_TABLE_WITH_ARRAY_CAPACITY",
        text: `${register(a)} = NEW_TABLE(array_capacity=${numberText(q)})`,
      };
    case 5:
      return {
        name: "COMPARE_REG_NE_REG",
        text: `${register(q)} = (${register(a)} != ${register(nRegister)})`,
      };
    case 9:
      return { name: "SET_TABLE_CONST", text: `${register(nRegister)}[${n}] = ${K}` };
    case 10:
      return { name: "ADD_CONST_REG", text: `${register(nRegister)} = ${K} + ${register(q)}` };
    case 14:
      return {
        name: "COMPARE_REG_LE_REG",
        text: `${register(nRegister)} = (${register(a)} <= ${register(q)})`,
      };
    case 20:
      return {
        name: "CALL_ONE_ARGUMENT_NO_RESULTS",
        text: `CALL_DISCARD(${register(nRegister)}, ${register(nRegister + 1)}); VM_TOP = ${nRegister - 1}`,
      };
    case 21:
      return {
        name: "JUMP_IF_TRUTHY",
        text: `IF TRUTHY(${register(a)}) THEN GOTO ${jumpTarget(N)}`,
      };
    case 22:
      return {
        name: "COMPARE_REG_LE_CONST",
        text: `${register(q)} = (${register(nRegister)} <= ${K})`,
      };
    case 25:
      return { name: "LOAD_NIL", text: `${register(q)} = NIL` };
    case 34:
      return {
        name: "SUBTRACT_REG_REG",
        text: `${register(a)} = ${register(q)} - ${register(nRegister)}`,
      };
    case 36:
      return {
        name: "CALL_RANGE_ONE_RESULT",
        text: `${register(nRegister)} = CALL(${register(nRegister)}, ${registerSlice(nRegister + 1, nRegister + q - 1)})`,
      };
    case 41:
      return {
        name: "COMPARE_REG_EQ_CONST",
        text: `${register(nRegister)} = (${register(q)} == ${K})`,
      };
    case 50:
      return {
        name: "TAILCALL_ONE_ARGUMENT",
        text: `${closeOpenUpvalues()}; TAILCALL ${register(nRegister)}(${register(nRegister + 1)})`,
      };
    case 58:
      return {
        name: "JUMP_IF_FALSY",
        text: `IF FALSY(${register(a)}) THEN GOTO ${jumpTarget(N)}`,
      };
    case 59:
      return {
        name: "ADD_REG_CONST",
        text: `${register(q)} = ${register(nRegister)} + ${K}`,
      };
    case 62:
      return {
        name: "CALL_GENERIC",
        text: `CALL_GENERIC(function=${register(a)}, arguments=${genericCallArguments(a, nRegister)}, results=${genericCallResults(a, q)})`,
      };
    case 69:
      return {
        name: "JUMP_IF_REG_LE_CONST",
        text: `IF ${register(a)} <= ${M} THEN GOTO ${jumpTarget(Q)}`,
      };
    case 71:
      return { name: "LOAD_CONSTANT", text: `${register(nRegister)} = ${K}` };
    case 72:
      return {
        name: "MULTIPLY_CONST_CONST",
        text: `${register(nRegister)} = ${n} * ${K}`,
      };
    case 73:
      return {
        name: "NUMERIC_FOR_LOOP",
        text: `LOOP_INDEX += LOOP_STEP; IF ((LOOP_STEP > 0 AND LOOP_INDEX <= LOOP_LIMIT) OR (LOOP_STEP <= 0 AND LOOP_INDEX >= LOOP_LIMIT)) THEN ${register(q + 3)} = LOOP_INDEX; GOTO ${jumpTarget(A)}`,
      };
    case 75:
      return {
        name: "TABLE_MOVE",
        text: `TABLE_MOVE(source=REGISTERS, first=${a + 1}, last=${a + nRegister}, destination=${register(a)}, destination_first=${q + 1})`,
      };
    case 77:
      return {
        name: "COMPARE_CONST_LE_REG",
        text: `${register(a)} = (${n} <= ${register(nRegister)})`,
      };
    case 79:
      return {
        name: "RETURN_RANGE_CLOSE_UPVALUES",
        text: `${closeOpenUpvalues()}; RETURN ${registerSlice(nRegister, nRegister + q - 2)}`,
      };
    case 84:
      return {
        name: "CREATE_CLOSURE",
        text: `${register(a)} = CLOSURE(${M}, captures=DESCRIPTORS_OF(${M}))`,
      };
    case 87:
      return {
        name: "CALL_TWO_ARGUMENTS_ONE_RESULT",
        text: `${register(q)} = CALL(${register(q)}, ${register(q + 1)}, ${register(q + 2)})`,
      };
    case 97:
      return {
        name: "SELF_LOOKUP",
        text: `${register(a + 1)} = ${register(nRegister)}; ${register(a)} = ${register(nRegister)}[${n}]`,
      };
    case 105:
      return {
        name: "COMPARE_REG_GE_REG",
        text: `${register(q)} = (${register(a)} >= ${register(nRegister)})`,
      };
    case 118:
      return {
        name: "RETURN_ZERO_RESULTS_CLOSE_UPVALUES",
        text: `${closeOpenUpvalues()}; RETURN`,
      };
    case 120:
      return {
        name: "LOAD_RUNTIME_SLOT",
        text: `${register(q)} = RUNTIME_TABLE[${numberText(a)}]`,
      };
    case 123:
      return {
        name: "CALL_OPEN_ARGUMENTS_ONE_RESULT",
        text: `${register(nRegister)} = CALL(${register(nRegister)}, REGISTERS(${register(nRegister + 1)} .. VM_TOP)); VM_TOP = ${nRegister}`,
      };
    case 125:
      return {
        name: "ADD_REG_REG",
        text: `${register(nRegister)} = ${register(a)} + ${register(q)}`,
      };
    case 126:
      return {
        name: "SET_TABLE",
        text: `${register(a)}[${n}] = ${register(nRegister)}`,
      };
    case 127:
      return {
        name: "COMPARE_REG_EQ_REG",
        text: `${register(nRegister)} = (${register(a)} == ${register(q)})`,
      };
    case 129:
      return {
        name: "COPY_INCOMING_VARARGS_PREFIX",
        text: `${registerSlice(1, q)} = INCOMING_VARARGS(start=1, count=${numberText(q)})`,
      };
    case 131:
      return {
        name: "CALL_ZERO_ARGUMENTS_NO_RESULTS",
        text: `CALL_DISCARD(${register(nRegister)}); VM_TOP = ${nRegister - 1}`,
      };
    case 135:
      return { name: "ADD_CONST_CONST", text: `${register(nRegister)} = ${K} + ${n}` };
    case 136:
      return { name: "JUMP", text: `GOTO ${jumpTarget(N)}` };
    case 137:
      return {
        name: "SUBTRACT_CONST_CONST",
        text: `${register(q)} = ${M} - ${K}`,
      };
    case 138:
      return {
        name: "COMPARE_REG_GT_CONST",
        text: `${register(a)} = (${register(nRegister)} > ${n})`,
      };
    case 143:
      return {
        name: "RIGHT_SHIFT_REG_REG",
        text: `${register(nRegister)} = BIT32_RSHIFT(${register(a)}, ${register(q)})`,
      };
    case 144:
      return {
        name: "JUMP_IF_REG_NE_CONST",
        text: `IF ${register(q)} != ${K} THEN GOTO ${jumpTarget(N)}`,
      };
    case 147:
      return {
        name: "COMPARE_REG_NE_CONST",
        text: `${register(q)} = (${register(a)} != ${M})`,
      };
    case 150:
      return {
        name: "COMPARE_REG_GE_CONST",
        text: `${register(a)} = (${register(q)} >= ${M})`,
      };
    case 154:
      return {
        name: "COPY_VARARGS",
        text: `${registerSlice(q, q + a - 1)} = INCOMING_VARARGS(cursor=VARARG_CURSOR, count=${a})`,
      };
    case 155:
      return {
        name: "GET_TABLE_CONST",
        text: `${register(nRegister)} = ${register(q)}[${K}]`,
      };
    case 161:
      return {
        name: "JUMP_IF_REG_LT_REG",
        text: `IF ${register(nRegister)} < ${register(q)} THEN GOTO ${jumpTarget(A)}`,
      };
    case 162:
      return {
        name: "LENGTH",
        text: `${register(nRegister)} = LENGTH(${register(q)})`,
      };
    case 164:
      return {
        name: "RIGHT_SHIFT_REG_IMMEDIATE",
        text: `${register(a)} = BIT32_RSHIFT(${register(nRegister)}, ${n})`,
      };
    case 176:
      return {
        name: "NUMERIC_FOR_PREP",
        text: `PUSH_NUMERIC_LOOP_FRAME(index=LOOP_INDEX, limit=LOOP_LIMIT, step=LOOP_STEP); LOOP_BASE = ${q}; LOOP_STEP = NUMERIC(${register(q + 2)}); LOOP_LIMIT = NUMERIC(${register(q + 1)}); LOOP_INDEX = ${register(q)} - LOOP_STEP; GOTO ${jumpTarget(A)}`,
      };
    case 187:
      return { name: "MOVE", text: `${register(nRegister)} = ${register(a)}` };
    case 188:
      return { name: "NEW_TABLE", text: `${register(q)} = NEW_TABLE()` };
    case 192:
      return {
        name: "CLEAR_REGISTER_RANGE",
        text: `CLEAR ${registerSlice(a, q)}`,
      };
    case 193:
      return {
        name: "CALL_TWO_ARGUMENTS_NO_RESULTS",
        text: `CALL_DISCARD(${register(nRegister)}, ${register(nRegister + 1)}, ${register(nRegister + 2)}); VM_TOP = ${nRegister - 1}`,
      };
    case 198:
      return {
        name: "COMPARE_REG_LT_REG",
        text: `${register(a)} = (${register(nRegister)} < ${register(q)})`,
      };
    case 199:
      return {
        name: "JUMP_IF_REG_GE_CONST",
        text: `IF ${register(q)} >= ${K} THEN GOTO ${jumpTarget(N)}`,
      };
    case 208:
      return {
        name: "COMPARE_REG_GT_REG",
        text: `${register(a)} = (${register(nRegister)} > ${register(q)})`,
      };
    case 212:
      return {
        name: "DIVIDE_REG_CONST",
        text: `${register(q)} = ${register(nRegister)} / ${K}`,
      };
    case 215:
      return {
        name: "GET_TABLE_REG",
        text: `${register(q)} = ${register(nRegister)}[${register(a)}]`,
      };
    case 216:
      return {
        name: "JUMP_IF_REG_NE_REG",
        text: `IF ${register(q)} != ${register(a)} THEN GOTO ${jumpTarget(N)}`,
      };
    case 219:
      return {
        name: "RETURN_ONE_RESULT_CLOSE_UPVALUES",
        text: `${closeOpenUpvalues()}; RETURN ${register(q)}`,
      };
    case 230:
      return {
        name: "MODULO_REG_CONST",
        text: `${register(nRegister)} = ${register(q)} % ${K}`,
      };
    case 233:
      return {
        name: "CALL_RANGE_NO_RESULTS",
        text: `CALL_DISCARD(${register(a)}, ${registerSlice(a + 1, a + q - 1)})`,
      };
    case 250:
      return {
        name: "MULTIPLY_REG_REG",
        text: `${register(a)} = ${register(q)} * ${register(nRegister)}`,
      };
    case 251:
      return {
        name: "CALL_ONE_ARGUMENT_ONE_RESULT",
        text: `${register(a)} = CALL(${register(a)}, ${register(a + 1)})`,
      };
    case 252:
      return {
        name: "SUBTRACT_REG_CONST",
        text: `${register(a)} = ${register(q)} - ${M}`,
      };
    case 253:
      return {
        name: "SET_TABLE_REG",
        text: `${register(q)}[${register(nRegister)}] = ${register(a)}`,
      };
    case 255:
      return {
        name: "COMPARE_REG_LT_CONST",
        text: `${register(q)} = (${register(nRegister)} < ${K})`,
      };
    case 259:
      return {
        name: "CALL_ZERO_ARGUMENTS_ONE_RESULT",
        text: `${register(q)} = CALL(${register(q)}); VM_TOP = ${q}`,
      };
    case 263:
      return {
        name: "SUBTRACT_CONST_REG",
        text: `${register(nRegister)} = ${n} - ${register(a)}`,
      };
    case 266:
      return {
        name: "MULTIPLY_REG_CONST",
        text: `${register(nRegister)} = ${register(q)} * ${K}`,
      };
    case 267:
      return {
        name: "LOAD_UPVALUE",
        text: `${register(q)} = UPVALUE(${numberText(a)}).VALUE`,
      };
    case 271:
      return {
        name: "LOAD_ENVIRONMENT_KEY",
        text: `${register(q)} = ENVIRONMENT[${K}]`,
      };
    default:
      return null;
  }
}

function protocolSemantic(
  instruction: JnkieDecodedInstruction,
  selector: number,
): RenderedSemantic | null {
  if (selector !== 0) return null;
  const { A, N, Q } = instruction.channels;
  switch (instruction.rawOpcode) {
    case 39:
      return {
        name: "VM_LOAD_N_OPERAND_STREAM",
        text: `VM_PROTOCOL ${register(A.payload)} = N_OPERAND_STREAM`,
      };
    case 51:
      return {
        name: "VM_LOAD_A_STREAM",
        text: `VM_PROTOCOL_LOAD_A(destination=${register(N.payload)})`,
      };
    case 52:
      return {
        name: "VM_SET_DESTINATION_INDEX",
        text: `VM_STATE.d = ${A.payload}; VM_STATE.v = ${Q.payload}`,
      };
    case 56:
      return {
        name: "VM_INDEX_PENDING_SOURCE",
        text: "REQUIRE_VM_STATE(s,f); VM_STATE.s = VM_STATE.s[VM_STATE.f]",
      };
    case 81:
      return {
        name: "VM_SELECT_REGISTER_DESTINATION_Q",
        text: `VM_STATE.d = REGISTER_FILE; VM_STATE.v = ${Q.payload}`,
      };
    case 91:
      return {
        name: "VM_STORE_CONST_AT_PENDING_DESTINATION",
        text: `REQUIRE_VM_STATE(d,v); VM_STATE.s = ${auxiliary(A)}; VM_STATE.d[VM_STATE.v] = VM_STATE.s`,
      };
    case 98:
      return {
        name: "VM_POP_NUMERIC_LOOP_FRAME",
        text: "REQUIRE_VM_STATE(loop_frame); LOOP_INDEX = LOOP_FRAME.index; LOOP_LIMIT = LOOP_FRAME.limit; LOOP_STEP = LOOP_FRAME.step; LOOP_FRAME = LOOP_FRAME.parent",
      };
    case 166:
      return {
        name: "VM_CAPTURE_VARARG_STATE",
        text: "VM_PROTOCOL_CAPTURE_INCOMING_VARARGS()",
      };
    case 203:
      return {
        name: "VM_SELECT_REGISTER_DESTINATION_N",
        text: `VM_STATE.d = REGISTER_FILE; VM_STATE.v = ${N.payload}`,
      };
    case 238:
      return {
        name: "VM_LOAD_OPCODE_STREAM",
        text: `VM_PROTOCOL_LOAD_RAW_OPCODE(destination=${register(N.payload)})`,
      };
    case 239:
      return {
        name: "VM_STORE_CURSOR",
        text: `VM_PROTOCOL_STORE_CURSOR(${register(A.payload)})`,
      };
    case 244:
      return {
        name: "VM_LOAD_PENDING_KEY_CONST",
        text: `VM_STATE.f = ${auxiliary(A)}`,
      };
    case 247:
      return {
        name: "VM_CLEAR_SCRATCH_RANGE",
        text: "VM_PROTOCOL_CLEAR_CURRENT_SCRATCH_RANGE()",
      };
    case 248:
      return {
        name: "VM_LOAD_Q_STREAM",
        text: `VM_PROTOCOL_LOAD_Q(destination=${register(N.payload)}, encoded_Q=${Q.payload})`,
      };
    case 277:
      return {
        name: "VM_INDEX_AND_STORE_PENDING_VALUE",
        text: "REQUIRE_VM_STATE(d,v,s,f); VM_STATE.s = VM_STATE.s[VM_STATE.f]; VM_STATE.d[VM_STATE.v] = VM_STATE.s",
      };
    case 282:
      return {
        name: "VM_LOAD_CAPTURE_CELL",
        text: `${register(A.payload)} = CAPTURE_CELLS[${N.payload}] (cell_object, not_value)`,
      };
    default:
      return null;
  }
}

function wordRange(
  instruction: JnkieDecodedInstruction,
  name: JnkieOperandName,
): { readonly start: number; readonly end: number } {
  const index = name === "A" ? 0 : name === "N" ? 2 : 3;
  return instruction.wordByteRanges[index];
}

function channelDetail(
  instruction: JnkieDecodedInstruction,
  name: JnkieOperandName,
): string {
  const channel = instruction.channels[name];
  const range = wordRange(instruction, name);
  const rawWord = instruction.rawWords[name === "A" ? 0 : name === "N" ? 2 : 3];
  // Tuple fields are documented in the artifact header.  This compact form
  // keeps the complete 260k+ record export practical without dropping data.
  return `${name}=[${[
    numberText(rawWord),
    channel.mode,
    numberText(channel.payload),
    channel.resolvedValue === null ? "null" : numberText(channel.resolvedValue),
    channel.constantIndex === null ? "null" : constantName(channel.constantIndex),
    channel.childPrototypeIndex === null ? "null" : prototypeName(channel.childPrototypeIndex),
    range.start,
    range.end,
  ].join(",")}]`;
}

function rawInstructionCall(instruction: JnkieDecodedInstruction): string {
  const opcodeRange = instruction.wordByteRanges[1];
  return [
    `VM_OP_raw(op=${numberText(instruction.rawOpcode)}`,
    `opb=${opcodeRange.start}:${opcodeRange.end}`,
    `ib=${instruction.byteRange.start}:${instruction.byteRange.end}`,
    `w=[${instruction.rawWords.map(numberText).join(",")}]`,
    channelDetail(instruction, "A"),
    channelDetail(instruction, "N"),
    channelDetail(instruction, "Q"),
    ")",
  ].join(", ");
}

function provenanceSuffix(instruction: JnkieDecodedInstruction, name: string): string {
  return [
    `handler=${name}`,
    `raw_opcode=${numberText(instruction.rawOpcode)}`,
    `bytes=${rangeText(instruction.byteRange.start, instruction.byteRange.end)}`,
    `words=[${instruction.rawWords.map(numberText).join(",")}]`,
    `modes={A:${instruction.channels.A.mode},N:${instruction.channels.N.mode},Q:${instruction.channels.Q.mode}}`,
  ].join(" | ");
}

function matchesKnownFusion(
  section: JnkieRecordSection,
  identity: JnkieSemanticIdentity,
  prototype: JnkieDecodedPrototype,
  pc: number,
): FusionMatch | null {
  if (
    normalizedHash(identity.payloadSha256) !== KNOWN_JNKIE_PAYLOAD_SHA256 ||
    section.index !== 1 ||
    prototype.selector !== 0 ||
    prototype.index !== section.rootPrototypeIndex ||
    pc !== 548 ||
    prototype.instructionCount < 552
  ) {
    return null;
  }
  const instructions = FUSION_OPCODES.map((opcode, offset) => {
    const instruction = instructionAt(prototype.instructions, pc + offset);
    const expected = FUSION_PAYLOADS[offset]!;
    if (
      instruction.rawOpcode !== opcode ||
      instruction.channels.A.payload !== expected.A ||
      instruction.channels.N.payload !== expected.N ||
      instruction.channels.Q.payload !== expected.Q
    ) {
      return null;
    }
    return instruction;
  });
  if (instructions.some((instruction) => instruction === null)) return null;
  return {
    instructions: instructions as readonly JnkieDecodedInstruction[],
    text: `${register(14)}[262] = ${register(15)}`,
  };
}

function increment(target: Record<string, number>, opcode: number): void {
  const key = String(opcode);
  target[key] = (target[key] ?? 0) + 1;
}

function sortedCounts(counts: Readonly<Record<string, number>>): Readonly<Record<string, number>> {
  return Object.fromEntries(
    Object.entries(counts).sort(([left], [right]) => Number(left) - Number(right)),
  );
}

function orderedPrototypes(section: JnkieRecordSection): readonly JnkieDecodedPrototype[] {
  const byIndex = new Map<number, JnkieDecodedPrototype>();
  for (const prototype of section.prototypes) {
    if (byIndex.has(prototype.index)) {
      throw new Error(`Duplicate decoded prototype index ${prototype.index}.`);
    }
    if (prototype.instructionCount !== prototype.instructions.count) {
      throw new Error(`Prototype ${prototype.index} instruction columns are inconsistent.`);
    }
    byIndex.set(prototype.index, prototype);
  }
  const root = byIndex.get(section.rootPrototypeIndex);
  if (!root) throw new Error("Decoded root prototype is missing from the prototype list.");
  return [
    root,
    ...[...byIndex.values()]
      .filter((prototype) => prototype.index !== root.index)
      .sort((left, right) => left.index - right.index),
  ];
}

function collectSectionCoverage(
  section: JnkieRecordSection,
  identity: JnkieSemanticIdentity,
  prototypes: readonly JnkieDecodedPrototype[],
): JnkieSemanticSectionCoverage {
  const mutable: MutableCoverage = {
    provenSemanticInstructions: 0,
    decoderProtocolInstructions: 0,
    rawUnresolvedInstructions: 0,
    statefulMicroInstructions: 0,
    fusedSemanticInstructions: 0,
    emittedStatements: 0,
    provenOpcodeCounts: {},
    protocolOpcodeCounts: {},
    unresolvedOpcodeCounts: {},
  };
  let total = 0;
  for (const prototype of prototypes) {
    for (let pc = 1; pc <= prototype.instructionCount; pc += 1) {
      const fusion = matchesKnownFusion(section, identity, prototype, pc);
      if (fusion) {
        for (const instruction of fusion.instructions) {
          increment(mutable.provenOpcodeCounts, instruction.rawOpcode);
        }
        total += fusion.instructions.length;
        mutable.provenSemanticInstructions += fusion.instructions.length;
        mutable.fusedSemanticInstructions += fusion.instructions.length;
        mutable.emittedStatements += 1;
        pc += fusion.instructions.length - 1;
        continue;
      }
      const instruction = instructionAt(prototype.instructions, pc);
      total += 1;
      mutable.emittedStatements += 1;
      if (knownSemantic(instruction, prototype.selector)) {
        mutable.provenSemanticInstructions += 1;
        increment(mutable.provenOpcodeCounts, instruction.rawOpcode);
      } else if (protocolSemantic(instruction, prototype.selector)) {
        mutable.decoderProtocolInstructions += 1;
        increment(mutable.protocolOpcodeCounts, instruction.rawOpcode);
      } else {
        mutable.rawUnresolvedInstructions += 1;
        increment(mutable.unresolvedOpcodeCounts, instruction.rawOpcode);
        if (STATEFUL_MICRO_OPCODES.has(instruction.rawOpcode)) {
          mutable.statefulMicroInstructions += 1;
        }
      }
    }
  }
  if (total !== section.statistics.instructionCount) {
    throw new Error(
      `Section ${section.index} semantic traversal counted ${total} records; decoder reports ${section.statistics.instructionCount}.`,
    );
  }
  if (
    mutable.provenSemanticInstructions +
      mutable.decoderProtocolInstructions +
      mutable.rawUnresolvedInstructions !==
    total
  ) {
    throw new Error("Semantic coverage categories do not partition the decoded instructions.");
  }
  return {
    sectionIndex: section.index,
    sectionKind: section.kind,
    prototypeCount: prototypes.length,
    totalInstructionRecords: total,
    provenSemanticInstructions: mutable.provenSemanticInstructions,
    decoderProtocolInstructions: mutable.decoderProtocolInstructions,
    rawUnresolvedInstructions: mutable.rawUnresolvedInstructions,
    statefulMicroInstructions: mutable.statefulMicroInstructions,
    fusedSemanticInstructions: mutable.fusedSemanticInstructions,
    emittedStatements: mutable.emittedStatements,
    sourceSemanticCoverageRatio: mutable.provenSemanticInstructions / Math.max(1, total),
    explainedHandlerCoverageRatio:
      (mutable.provenSemanticInstructions + mutable.decoderProtocolInstructions) /
      Math.max(1, total),
    provenOpcodeCounts: sortedCounts(mutable.provenOpcodeCounts),
    protocolOpcodeCounts: sortedCounts(mutable.protocolOpcodeCounts),
    unresolvedOpcodeCounts: sortedCounts(mutable.unresolvedOpcodeCounts),
  };
}

function mergeCounts(
  coverages: readonly JnkieSemanticSectionCoverage[],
  field: "provenOpcodeCounts" | "protocolOpcodeCounts" | "unresolvedOpcodeCounts",
): Readonly<Record<string, number>> {
  const merged: Record<string, number> = {};
  for (const coverage of coverages) {
    for (const [opcode, count] of Object.entries(coverage[field])) {
      merged[opcode] = (merged[opcode] ?? 0) + count;
    }
  }
  return sortedCounts(merged);
}

function aggregateCoverage(
  result: JnkieRecordDecodeResult,
  sections: readonly JnkieSemanticSectionCoverage[],
): JnkieSemanticCoverage {
  const sum = (field: keyof Pick<
    JnkieSemanticSectionCoverage,
    | "prototypeCount"
    | "totalInstructionRecords"
    | "provenSemanticInstructions"
    | "decoderProtocolInstructions"
    | "rawUnresolvedInstructions"
    | "statefulMicroInstructions"
    | "fusedSemanticInstructions"
    | "emittedStatements"
  >): number => sections.reduce((total, section) => total + section[field], 0);
  const total = sum("totalInstructionRecords");
  if (total !== result.statistics.instructionCount) {
    throw new Error(
      `Aggregate semantic traversal counted ${total} records; decoder reports ${result.statistics.instructionCount}.`,
    );
  }
  const proven = sum("provenSemanticInstructions");
  const protocol = sum("decoderProtocolInstructions");
  return {
    sectionCount: sections.length,
    prototypeCount: sum("prototypeCount"),
    totalInstructionRecords: total,
    provenSemanticInstructions: proven,
    decoderProtocolInstructions: protocol,
    rawUnresolvedInstructions: sum("rawUnresolvedInstructions"),
    statefulMicroInstructions: sum("statefulMicroInstructions"),
    fusedSemanticInstructions: sum("fusedSemanticInstructions"),
    emittedStatements: sum("emittedStatements"),
    sourceSemanticCoverageRatio: proven / Math.max(1, total),
    explainedHandlerCoverageRatio: (proven + protocol) / Math.max(1, total),
    provenOpcodeCounts: mergeCounts(sections, "provenOpcodeCounts"),
    protocolOpcodeCounts: mergeCounts(sections, "protocolOpcodeCounts"),
    unresolvedOpcodeCounts: mergeCounts(sections, "unresolvedOpcodeCounts"),
    sections,
  };
}

function constantDisplay(constant: JnkieDecodedConstant): string {
  switch (constant.kind) {
    case "integer":
      return `INTEGER(${constant.exactDecimal}, encoding=${constant.encoding})`;
    case "float":
      return `FLOAT(${constant.displayValue}, encoding=${constant.encoding}, ieee754=0x${constant.ieee754Hex})`;
    case "boolean":
      return constant.value ? "TRUE" : "FALSE";
    case "string":
      return constant.utf8Text === null
        ? `STRING_BYTES(base64=${JSON.stringify(constant.valueBase64)}, latin1=${JSON.stringify(constant.latin1Text)}, bytes=${constant.byteLength})`
        : `UTF8_STRING(${JSON.stringify(constant.utf8Text)}, raw_base64=${JSON.stringify(constant.valueBase64)}, bytes=${constant.byteLength})`;
    case "buffer":
      return `BUFFER_BYTES(base64=${JSON.stringify(constant.valueBase64)}, bytes=${constant.byteLength})`;
  }
}

function captureDisplay(prototype: JnkieDecodedPrototype): string {
  if (prototype.captures.length === 0) return "[]";
  return `[${prototype.captures
    .map((capture) => {
      const source = capture.kind === 0
        ? `OPEN_REGISTER_CELL(${capture.sourceIndex})`
        : capture.kind === 1
          ? `REGISTER_VALUE(${capture.sourceIndex})`
          : `PARENT_UPVALUE(${capture.sourceIndex})`;
      return `slot${capture.index}:${source}@${rangeText(capture.byteRange.start, capture.byteRange.end)}`;
    })
    .join(", ")}]`;
}

function coverageLines(
  coverage: JnkieSemanticCoverage | JnkieSemanticSectionCoverage,
): readonly string[] {
  const percentage = (value: number): string => `${(value * 100).toFixed(2)}%`;
  return [
    `decoded_prototypes: ${coverage.prototypeCount}`,
    `decoded_instruction_records: ${coverage.totalInstructionRecords}`,
    `proven_source_semantic_records: ${coverage.provenSemanticInstructions}`,
    `decoder_protocol_records: ${coverage.decoderProtocolInstructions}`,
    `raw_unresolved_records: ${coverage.rawUnresolvedInstructions}`,
    `stateful_micro_records_within_unresolved: ${coverage.statefulMicroInstructions}`,
    `records_in_exact_proven_fusions: ${coverage.fusedSemanticInstructions}`,
    `emitted_statements: ${coverage.emittedStatements}`,
    `source_semantic_coverage: ${percentage(coverage.sourceSemanticCoverageRatio)}`,
    `explained_handler_coverage_including_protocol: ${percentage(coverage.explainedHandlerCoverageRatio)}`,
    `partition_check: ${coverage.provenSemanticInstructions} + ${coverage.decoderProtocolInstructions} + ${coverage.rawUnresolvedInstructions} = ${coverage.totalInstructionRecords}`,
    `proven_opcode_counts: ${JSON.stringify(coverage.provenOpcodeCounts)}`,
    `protocol_opcode_counts: ${JSON.stringify(coverage.protocolOpcodeCounts)}`,
    `unresolved_opcode_counts: ${JSON.stringify(coverage.unresolvedOpcodeCounts)}`,
  ];
}

function renderPrototype(
  section: JnkieRecordSection,
  identity: JnkieSemanticIdentity,
  prototype: JnkieDecodedPrototype,
): readonly string[] {
  const root = prototype.index === section.rootPrototypeIndex;
  const lines = [
    "",
    `PROTOTYPE ${prototypeName(prototype.index)}${root ? " [ROOT]" : ""}`,
    `  stream_bytes: ${rangeText(prototype.byteRange.start, prototype.byteRange.end)}`,
    `  selector: ${prototype.selector}`,
    `  max_stack: ${prototype.maxStack}`,
    `  instruction_records: ${prototype.instructionCount}`,
    `  captures: ${captureDisplay(prototype)}`,
    "  BEGIN_INSTRUCTIONS",
  ];
  for (let pc = 1; pc <= prototype.instructionCount; pc += 1) {
    const block = renderInstructionBlock(section, identity, prototype, pc);
    lines.push(...block.lines);
    pc = block.nextPc - 1;
  }
  lines.push("  END_INSTRUCTIONS");
  return lines;
}

function renderInstructionBlock(
  section: JnkieRecordSection,
  identity: JnkieSemanticIdentity,
  prototype: JnkieDecodedPrototype,
  pc: number,
): RenderedInstructionBlock {
  const fusion = matchesKnownFusion(section, identity, prototype, pc);
  if (fusion) {
    const first = fusion.instructions[0]!;
    const last = fusion.instructions[fusion.instructions.length - 1]!;
    return {
      lines: [
        `    PC${String(pc).padStart(4, "0")}..PC${String(pc + fusion.instructions.length - 1).padStart(4, "0")}: ${fusion.text}  // VERIFIED_FUSION | bytes=${rangeText(first.byteRange.start, last.byteRange.end)}`,
        ...fusion.instructions.map(
          (instruction) =>
            `      EVIDENCE PC${String(instruction.pc).padStart(4, "0")}: ${rawInstructionCall(instruction)}`,
        ),
      ],
      instructionRecords: fusion.instructions.length,
      nextPc: pc + fusion.instructions.length,
    };
  }
  const instruction = instructionAt(prototype.instructions, pc);
  const semantic = knownSemantic(instruction, prototype.selector);
  const protocol = semantic ? null : protocolSemantic(instruction, prototype.selector);
  const label = `PC${String(pc).padStart(4, "0")}`;
  if (semantic) {
    return {
      lines: [`    ${label}: ${semantic.text}  // ${provenanceSuffix(instruction, semantic.name)}`],
      instructionRecords: 1,
      nextPc: pc + 1,
    };
  }
  if (protocol) {
    return {
      lines: [`    ${label}: ${protocol.text}  // ${provenanceSuffix(instruction, protocol.name)}`],
      instructionRecords: 1,
      nextPc: pc + 1,
    };
  }
  const micro = STATEFUL_MICRO_OPCODES.has(instruction.rawOpcode)
    ? "stateful_micro_op=true, "
    : "";
  return {
    lines: [`    ${label}: ${rawInstructionCall(instruction)}  // ${micro}semantic_effect=unresolved`],
    instructionRecords: 1,
    nextPc: pc + 1,
  };
}

function renderSection(
  section: JnkieRecordSection,
  identity: JnkieSemanticIdentity,
  prototypes: readonly JnkieDecodedPrototype[],
  coverage: JnkieSemanticSectionCoverage,
): readonly string[] {
  const sectionLabel = `S${String(section.index).padStart(2, "0")}`;
  const lines: string[] = [
    "",
    `SECTION ${sectionLabel} [${section.kind}]`,
    `  stream_bytes: ${rangeText(section.byteRange.start, section.byteRange.end)}`,
    `  wrapped_constants: ${section.wrappedConstants}`,
    `  constants: ${section.constants.length}`,
    `  prototypes: ${section.prototypes.length}`,
    `  root_prototype: ${sectionLabel}.${prototypeName(section.rootPrototypeIndex)}`,
    "  prototype_order: section root first, then remaining prototypes in numeric stream order",
    "",
    `  ${sectionLabel}_COVERAGE`,
    ...coverageLines(coverage).map((line) => `  ${line}`),
    "",
    `  ${sectionLabel}_PROTOTYPES`,
  ];
  for (const prototype of prototypes) {
    appendLines(lines, renderPrototype(section, identity, prototype));
  }
  lines.push("", `  ${sectionLabel}_CONSTANT_POOL`);
  for (const constant of section.constants) {
    lines.push(
      `  ${constantName(constant.index)} = ${constantDisplay(constant)}  // tag=${constant.tag} | bytes=${rangeText(constant.byteRange.start, constant.byteRange.end)}`,
    );
  }
  lines.push(`END_SECTION ${sectionLabel}`);
  return lines;
}

function linesByteLength(lines: readonly string[]): number {
  return lines.reduce((total, line) => total + Buffer.byteLength(`${line}\n`, "utf8"), 0);
}

function appendLines(target: string[], source: readonly string[]): void {
  for (const line of source) target.push(line);
}

function importantPrototypeOrder(entry: OrderedSection): readonly JnkieDecodedPrototype[] {
  const root = entry.prototypes[0]!;
  return [
    root,
    ...entry.prototypes
      .slice(1)
      .sort(
        (left, right) =>
          right.instructionCount - left.instructionCount || left.index - right.index,
      )
      .slice(0, 12),
  ];
}

function makeCompactView(
  prefixLines: readonly string[],
  ordered: readonly OrderedSection[],
  identity: JnkieSemanticIdentity,
  coverage: JnkieSemanticCoverage,
  fullUncompressedByteLength: number,
): {
  readonly text: string;
  readonly byteLength: number;
  readonly truncated: boolean;
  readonly includedInstructionRecords: number;
  readonly omittedInstructionRecords: number;
} {
  const bodyBudget = JNKIE_UI_PSEUDOCODE_MAX_BYTES - 256 * 1_024;
  const body: string[] = [];
  let bodyBytes = 0;
  let includedInstructionRecords = 0;
  const append = (candidate: readonly string[]): boolean => {
    const candidateBytes = linesByteLength(candidate);
    if (bodyBytes + candidateBytes > bodyBudget) return false;
    body.push(...candidate);
    bodyBytes += candidateBytes;
    return true;
  };

  for (const entry of ordered) {
    const sectionLabel = `S${String(entry.section.index).padStart(2, "0")}`;
    append([
      "",
      `COMPACT_SECTION ${sectionLabel} [${entry.section.kind}]`,
      `stream_bytes: ${rangeText(entry.section.byteRange.start, entry.section.byteRange.end)}`,
      `root_prototype: ${sectionLabel}.${prototypeName(entry.section.rootPrototypeIndex)}`,
      `section_instruction_records: ${entry.coverage.totalInstructionRecords}`,
    ]);
    for (const prototype of importantPrototypeOrder(entry)) {
      const root = prototype.index === entry.section.rootPrototypeIndex;
      const limit = root
        ? Math.min(prototype.instructionCount, entry.section.kind === "nested-payload" ? 8_000 : 4_000)
        : Math.min(prototype.instructionCount, 300);
      if (!append([
        "",
        `PROTOTYPE_EXCERPT ${sectionLabel}.${prototypeName(prototype.index)}${root ? " [ROOT]" : " [IMPORTANT_BY_INSTRUCTION_COUNT]"}`,
        `  total_instruction_records: ${prototype.instructionCount}`,
        `  excerpt_target_records: ${limit}`,
        `  stream_bytes: ${rangeText(prototype.byteRange.start, prototype.byteRange.end)}`,
        "  BEGIN_EXCERPT",
      ])) break;
      let emittedForPrototype = 0;
      for (let pc = 1; pc <= limit; ) {
        const block = renderInstructionBlock(entry.section, identity, prototype, pc);
        if (pc + block.instructionRecords - 1 > limit || !append(block.lines)) break;
        includedInstructionRecords += block.instructionRecords;
        emittedForPrototype += block.instructionRecords;
        pc = block.nextPc;
      }
      append([
        `  END_EXCERPT included=${emittedForPrototype} omitted_from_this_prototype=${prototype.instructionCount - emittedForPrototype}`,
      ]);
    }
    append([
      `${sectionLabel}_COMPACT_CONSTANTS: omitted (${entry.section.constants.length} exact constants remain in the full gzip artifact)`,
    ]);
  }
  const omittedInstructionRecords =
    coverage.totalInstructionRecords - includedInstructionRecords;
  const compactHeader = [
    ...prefixLines,
    "",
    "COMPACT_UI_VIEW",
    "selection_policy: each section root first, followed by up to 12 largest prototypes; each prototype is a source-order prefix",
    `included_instruction_records: ${includedInstructionRecords}`,
    `omitted_instruction_records: ${omittedInstructionRecords}`,
    `partition_check: ${includedInstructionRecords} + ${omittedInstructionRecords} = ${coverage.totalInstructionRecords}`,
    `full_uncompressed_pseudocode_bytes: ${fullUncompressedByteLength}`,
    "full_export: jnkie-semantic-pseudocode.full.txt.gz (export-only; not loaded into the code viewer)",
    "Every omitted record remains counted in the complete coverage block and present in the deterministic full gzip artifact.",
  ];
  const footer = [
    "",
    "END_COMPACT_UI_VIEW",
    `included_instruction_records: ${includedInstructionRecords}`,
    `omitted_instruction_records: ${omittedInstructionRecords}`,
    "",
  ];
  const text = [...compactHeader, ...body, ...footer].join("\n");
  const byteLength = Buffer.byteLength(text, "utf8");
  if (byteLength > JNKIE_UI_PSEUDOCODE_MAX_BYTES) {
    throw new Error("Compact pseudocode exceeded its byte budget.");
  }
  return {
    text,
    byteLength,
    truncated: omittedInstructionRecords > 0 || byteLength !== fullUncompressedByteLength,
    includedInstructionRecords,
    omittedInstructionRecords,
  };
}

function deterministicGzip(text: string): Uint8Array {
  const bytes = Uint8Array.from(gzipSync(Buffer.from(text, "utf8"), { level: 9 }));
  if (bytes.length >= 10) {
    // Normalize mtime and OS header fields.  They are not covered by the
    // payload CRC and otherwise vary across runtimes/platforms.
    bytes[4] = 0;
    bytes[5] = 0;
    bytes[6] = 0;
    bytes[7] = 0;
    bytes[9] = 255;
  }
  return bytes;
}

export function emitKnownJnkieSemanticPseudocode(
  result: JnkieRecordDecodeResult,
  identity: JnkieSemanticIdentity,
): JnkieSemanticEmission {
  if (normalizedHash(identity.loaderSha256) !== KNOWN_JNKIE_LOADER_SHA256) {
    return {
      status: "not-applicable",
      scope: JNKIE_SEMANTIC_SCOPE,
      reason: "The proven handler map is gated to the exact known JNKIE loader SHA-256.",
    };
  }
  if (result.safety.submittedCodeExecution !== "never") {
    throw new Error("Semantic emission requires a decoder result produced without execution.");
  }
  if (result.sections.length === 0) {
    throw new Error("Semantic emission requires at least one decoded record section.");
  }
  const ordered: readonly OrderedSection[] = [...result.sections]
    .sort((left, right) => left.index - right.index)
    .map((section) => {
      const prototypes = orderedPrototypes(section);
      return {
        section,
        prototypes,
        coverage: collectSectionCoverage(section, identity, prototypes),
      };
    });
  const coverage = aggregateCoverage(
    result,
    ordered.map((entry) => entry.coverage),
  );
  const warnings = [
    "This artifact is conservative inert pseudocode, not recovered original Lua/Luau source.",
    "Names, comments, source layout, and unproven opcode effects are not invented.",
    `${result.statistics.decodedBytes} bytes belong to decoded record sections; ${result.statistics.unresolvedBytes} bytes remain explicitly unresolved between or after sections.`,
    "Wrapped constants remain indexed, typed byte records; unknown values are never guessed.",
    "VM_OP_raw records preserve every operand channel and byte range for later semantic upgrades.",
  ] as const;
  const prefixLines: string[] = [
    "3ZIZ JNKIE CONSERVATIVE SEMANTIC PSEUDOCODE",
    "================================================",
    `scope: ${JNKIE_SEMANTIC_SCOPE}`,
    "output_language: inert audit pseudocode (not Lua, not Luau)",
    "original_source_claim: none",
    "submitted_code_execution: never",
    `loader_sha256: ${normalizedHash(identity.loaderSha256)}`,
    `payload_sha256: ${normalizedHash(identity.payloadSha256)}`,
    `record_stream_bytes: ${result.statistics.inputBytes}`,
    `decoded_section_bytes: ${result.statistics.decodedBytes}`,
    `unresolved_bytes: ${result.statistics.unresolvedBytes}`,
    `sections: ${result.sections.length}`,
    `semantic_section: S${String(result.semanticSection.index).padStart(2, "0")}.${prototypeName(result.semanticSection.rootPrototypeIndex)}`,
    `unresolved_regions: ${JSON.stringify(result.unresolvedRegions)}`,
    "section_order: numeric stream order; each section emits its root first",
    "jump_rule: encoded target T resumes at PC(T + 1), matching the known dispatcher footer",
    "VM_OP_raw channel tuple: [raw_word, mode, payload, resolved_value, constant_id, child_prototype_id, byte_start, byte_end]",
    "",
    "WARNINGS",
    ...warnings.map((warning) => `- ${warning}`),
    "",
    "COVERAGE",
    ...coverageLines(coverage),
  ];
  const lines: string[] = [...prefixLines];
  for (const entry of ordered) {
    appendLines(lines, renderSection(entry.section, identity, entry.prototypes, entry.coverage));
  }
  lines.push("", "END_OF_CONSERVATIVE_PSEUDOCODE", "");
  const fullText = lines.join("\n");
  const uncompressedByteLength = Buffer.byteLength(fullText, "utf8");
  const fullGzip = deterministicGzip(fullText);
  const compact = makeCompactView(
    prefixLines,
    ordered,
    identity,
    coverage,
    uncompressedByteLength,
  );
  return {
    status: "emitted",
    scope: JNKIE_SEMANTIC_SCOPE,
    text: compact.text,
    compactText: compact.text,
    compactByteLength: compact.byteLength,
    compactTruncated: compact.truncated,
    compactIncludedInstructionRecords: compact.includedInstructionRecords,
    compactOmittedInstructionRecords: compact.omittedInstructionRecords,
    fullArtifact: {
      fileName: "jnkie-semantic-pseudocode.full.txt.gz",
      mediaType: "application/gzip",
      bytes: fullGzip,
      compressedByteLength: fullGzip.byteLength,
      uncompressedByteLength,
      deterministicHeader: true,
    },
    coverage,
    prototypeOrder: ordered.map((entry) => ({
      sectionIndex: entry.section.index,
      prototypeIndices: entry.prototypes.map((prototype) => prototype.index),
    })),
    warnings,
    safety: {
      submittedCodeExecution: "never",
      outputKind: "inert-pseudocode",
    },
  };
}

export const JNKIE_PROVEN_SEMANTIC_OPCODES = Object.freeze([
  1, 5, 9, 10, 14, 20, 21, 22, 25, 34, 36, 41, 50, 58, 59, 62, 69, 71,
  72, 73, 75, 77, 79, 84, 87, 97, 105, 118, 120, 123, 125, 126, 127, 129,
  131, 135, 136, 137, 138, 143, 144, 147, 150, 154, 155, 161, 162, 164,
  176, 187, 188, 192, 193, 198, 199, 208, 212, 215, 216, 219, 230, 233,
  250,
  251, 252, 253, 255, 259, 263, 266, 267, 271,
] as const);

export const JNKIE_PROTOCOL_OPCODES = Object.freeze([...PROTOCOL_OPCODES].sort((a, b) => a - b));
