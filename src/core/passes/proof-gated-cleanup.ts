import type {
  Diagnostic,
  LuaParseFacts,
  SourcePassRecord,
} from "../../shared/contracts";
import { scanLuaLexically } from "../source/lexical";

export interface CleanupResult {
  readonly source: string;
  readonly passes: readonly SourcePassRecord[];
  readonly diagnostics: readonly Diagnostic[];
}

interface HazardProbe {
  readonly id: string;
  readonly description: string;
  readonly expression: RegExp;
}

const HAZARD_PROBES: readonly HazardProbe[] = [
  {
    id: "stored-call",
    description:
      "stored call results require scalarization and effect-order proof before substitution",
    expression: /=\s*[A-Za-z_(][^\n;=]*\([^;\n]*\)/g,
  },
  {
    id: "stored-vararg",
    description: "stored varargs must not be expanded at a later use site",
    expression: /=\s*\.\.\./g,
  },
  {
    id: "member-index",
    description:
      "member and index reads may invoke metamethods or raise and are not pure",
    expression: /=\s*[A-Za-z_(][^\n;]*(?:\.|\[)[^\n;]*/g,
  },
  {
    id: "arithmetic",
    description: "arithmetic and length operations may invoke metamethods or raise",
    expression: /=\s*[^\n;]+(?:\+|-|\*|\/|%|#)[^\n;]*/g,
  },
  {
    id: "closure",
    description: "closure creation and capture require lexical binding identity",
    expression: /\bfunction\b/g,
  },
  {
    id: "dot-self-call",
    description:
      "dot-call to colon-call rewriting can change receiver evaluation count",
    expression:
      /\b([A-Za-z_]\w*(?:\s*\.\s*[A-Za-z_]\w*)*)\s*\.\s*[A-Za-z_]\w*\s*\(\s*\1\b/g,
  },
  {
    id: "multiple-assignment",
    description: "simultaneous assignment and nil-hole behavior must be preserved",
    expression: /\b[A-Za-z_]\w*\s*,\s*[A-Za-z_]\w*\s*=/g,
  },
] as const;

function collectHazards(code: string): readonly string[] {
  const hazards: string[] = [];
  for (const probe of HAZARD_PROBES) {
    const matches = [...code.matchAll(probe.expression)].length;
    if (matches > 0) {
      hazards.push(`${probe.id}: ${probe.description} (${matches} marker(s))`);
    }
  }
  return hazards;
}

export function runProofGatedCleanup(
  source: string,
  facts: LuaParseFacts,
): CleanupResult {
  const diagnostics: Diagnostic[] = [];
  const code = scanLuaLexically(source).code;
  const hazards = collectHazards(code);

  if (facts.uniqueRegisterIdentifiers > 0) {
    diagnostics.push({
      code: "CLEANUP_ALPHA_RENAME_SKIPPED_SCOPE_PROOF",
      severity: "warning",
      stage: "source-cleanup",
      message:
        "Register-style names were retained because this release does not have binding-identity proof strong enough for authoritative alpha-renaming.",
      evidence: [
        `${facts.uniqueRegisterIdentifiers} unique register-style identifiers`,
        `${facts.registerIdentifierOccurrences} identifier occurrences`,
      ],
      suggestedAction:
        "Review a proposed rename profile manually; do not apply name-only substitutions.",
    });
  }

  if (hazards.length > 0) {
    diagnostics.push({
      code: "CLEANUP_EFFECT_SENSITIVE_REGIONS_RETAINED",
      severity: "info",
      stage: "source-cleanup",
      message:
        "Effect-sensitive expressions were left unchanged because their evaluation count, order, result arity, or binding could not be proven equivalent.",
      evidence: hazards,
    });
  }

  diagnostics.push({
    code: "CLEANUP_NO_AUTHORITATIVE_EDITS",
    severity: "info",
    stage: "source-cleanup",
    message:
      "Readable output is an exact source copy; no speculative inlining, purity folding, call-style conversion, or cross-scope renaming was applied.",
  });

  const pass: SourcePassRecord = {
    id: "proof-gated-source-cleanup",
    version: "1.0.0",
    applied: false,
    confidence: 1,
    edits: [],
    factsBefore: facts,
    factsAfter: facts,
    diagnostics,
  };

  return {
    source,
    passes: [pass],
    diagnostics,
  };
}
