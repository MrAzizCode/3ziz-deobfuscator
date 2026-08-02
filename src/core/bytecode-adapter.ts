import type {
  BytecodeAnalysisSummary,
  Diagnostic,
} from "../shared/contracts";

export interface BytecodeAdapterResult {
  readonly summary: BytecodeAnalysisSummary;
  readonly diagnostics: readonly Diagnostic[];
}

function asRecord(value: unknown): Record<string, unknown> | null {
  return value !== null && typeof value === "object"
    ? (value as Record<string, unknown>)
    : null;
}

function numberField(
  record: Record<string, unknown> | null,
  names: readonly string[],
): number | undefined {
  for (const name of names) {
    const value = record?.[name];
    if (typeof value === "number" && Number.isFinite(value)) return value;
  }
  return undefined;
}

/**
 * Keeps the core independent of the bytecode implementation's internal types.
 * The bounded parser is loaded only for inputs already classified as bytecode.
 */
export async function inspectBytecodeSafely(
  bytes: Uint8Array,
): Promise<BytecodeAdapterResult> {
  try {
    const modulePath = "./bytecode/lua51";
    const loaded: unknown = await import(modulePath);
    const moduleRecord = asRecord(loaded);
    const inspect = moduleRecord?.inspectLua51Bytecode;
    if (typeof inspect !== "function") {
      return {
        summary: { valid: false },
        diagnostics: [
          {
            code: "BYTECODE_ADAPTER_UNAVAILABLE",
            severity: "warning",
            stage: "bytecode",
            message:
              "The bounded Lua 5.1 bytecode inspector is not available in this build.",
          },
        ],
      };
    }

    const inspection: unknown = await Reflect.apply(inspect, undefined, [bytes]);
    const inspectionRecord = asRecord(inspection);
    const chunkRecord = asRecord(inspectionRecord?.chunk);
    const headerRecord = asRecord(chunkRecord?.header);
    const statsRecord = asRecord(chunkRecord?.stats);
    const valid = inspectionRecord?.ok === true;
    const disassembly =
      typeof inspectionRecord?.auditText === "string"
        ? inspectionRecord.auditText
        : undefined;

    const summary: BytecodeAnalysisSummary = {
      valid,
      ...(() => {
        const version = numberField(headerRecord, ["version"]);
        return version === undefined ? {} : { version };
      })(),
      ...(() => {
        const format = numberField(headerRecord, ["format"]);
        return format === undefined ? {} : { format };
      })(),
      ...(() => {
        const instructionCount = numberField(statsRecord, [
          "instructionCount",
          "instructions",
        ]);
        return instructionCount === undefined ? {} : { instructionCount };
      })(),
      ...(() => {
        const prototypeCount = numberField(statsRecord, [
          "prototypeCount",
          "prototypes",
        ]);
        return prototypeCount === undefined ? {} : { prototypeCount };
      })(),
      ...(disassembly === undefined ? {} : { disassembly }),
    };

    const diagnostics: Diagnostic[] = [];
    const rawDiagnostics = Array.isArray(inspectionRecord?.diagnostics)
      ? inspectionRecord.diagnostics
      : [];
    for (const raw of rawDiagnostics) {
      const record = asRecord(raw);
      diagnostics.push({
        code:
          typeof record?.code === "string"
            ? record.code
            : "BYTECODE_INSPECTOR_DIAGNOSTIC",
        severity:
          record?.severity === "error" || record?.severity === "warning"
            ? record.severity
            : "info",
        stage: "bytecode",
        message:
          typeof record?.message === "string"
            ? record.message
            : "The bytecode inspector reported a structural finding.",
      });
    }

    return { summary, diagnostics };
  } catch (error) {
    return {
      summary: { valid: false },
      diagnostics: [
        {
          code: "BYTECODE_ADAPTER_FAILURE",
          severity: "error",
          stage: "bytecode",
          message:
            error instanceof Error
              ? `Bytecode inspection failed safely: ${error.message}`
              : "Bytecode inspection failed safely.",
        },
      ],
    };
  }
}
