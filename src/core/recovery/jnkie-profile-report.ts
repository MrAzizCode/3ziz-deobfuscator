import type { KnownJnkieProfileManifest } from "./jnkie-known-profile";

export function renderKnownJnkieProfileReport(
  manifest: KnownJnkieProfileManifest,
): string {
  const lines = [
    "## Exact-stream static evidence profile",
    "",
    `- Profile: \`${manifest.profileId}\``,
    `- Status: **${manifest.status}**`,
    `- Loader SHA-256: \`${manifest.match.loaderSha256}\``,
    `- Payload SHA-256: \`${manifest.match.payloadSha256}\``,
    "- Match rule: both recovered stream hashes must match; a wrapper filename is never sufficient.",
    "- Submitted loader/payload execution: **never executed**",
    "",
  ];

  if (manifest.status === "loaded" && manifest.currentStreamMetrics) {
    const current = manifest.currentStreamMetrics;
    const reference = manifest.unverifiedReferenceMetrics;
    lines.push(
      "### Current-stream profile evidence",
      "",
      `- Prototype summary records: ${current.prototypeSummaryRecords.toLocaleString("en-US")}`,
      `- Aggregate declared instruction count across those summaries: ${current.aggregateDeclaredInstructionCount.toLocaleString("en-US")}`,
      `- Top-prototype raw IR rows: ${current.topPrototypeRawIrRows.toLocaleString("en-US")}`,
      `- Constants: ${current.constants.toLocaleString("en-US")} (${current.stringConstants.toLocaleString("en-US")} string constants)`,
      "- Scope: inventory and raw IR evidence only; these facts do not prove opcode meanings, a complete CFG, or high-level payload source.",
      "",
      "### Quarantined earlier-sample references",
      "",
      ...(reference === undefined
        ? ["- No earlier-sample reference metadata was attached."]
        : [
            `- Source sample size: ${reference.sourceSampleInputBytes.toLocaleString("en-US")} bytes (different from the current JNKIE input)`,
            `- Internal reference inventory: ${reference.compactReferenceLines} compact lines; ${reference.auditFunctions} audit functions / ${reference.auditInstructions.toLocaleString("en-US")} audit instructions`,
            "- Trust: unverified reference only; never used as current readable output, exact audit, CFG evidence, or behavior proof.",
          ]),
      "",
      "### Provenance boundary",
      "",
      "Both recovered stream SHA-256 values select the current-stream inventory profile. The compact and VM-audit text files came from a separate earlier sample and are exported only as warning-prefixed, plain-text research references.",
      "",
    );
  } else if (manifest.status === "not-matched") {
    lines.push(
      "No packaged knowledge profile matched this loader/payload pair. The app retained only generic, evidence-backed extraction and whole-buffer measurements.",
      "",
    );
  } else {
    lines.push(
      `The matching profile was rejected atomically: ${manifest.rejectionReason ?? "integrity or metric validation failed"}. No current-stream profile evidence or earlier-sample references were attached.`,
      "",
    );
  }

  return lines.join("\n");
}
