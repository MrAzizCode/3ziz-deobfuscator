import { existsSync, readFileSync } from "node:fs";
import { join } from "node:path";

import type { ExtractedArtifact } from "../../shared/contracts";
import { sha256Bytes } from "../hash";
import { validateLuraphAudit } from "../validation/luraph-audit";

export const KNOWN_JNKIE_PROFILE_ID = "jnkie-75107ad9-a76a6929";
export const KNOWN_JNKIE_LOADER_SHA256 =
  "75107ad9c4ac66af5fe302f0099a2a7fb9b632b6abdba0adf20ddf7265391392";
export const KNOWN_JNKIE_PAYLOAD_SHA256 =
  "a76a692983229924d32257c921a4de981950dcba6a5aa257e09dda1c786a1f92";
export const KNOWN_JNKIE_REFERENCE_READABLE_ARTIFACT =
  "jnkie-unverified-earlier-sample-readable-reference.txt";
export const KNOWN_JNKIE_REFERENCE_AUDIT_ARTIFACT =
  "jnkie-unverified-earlier-sample-vm-audit-reference.txt";
/** @deprecated This is an unverified earlier-sample reference, not current readable output. */
export const KNOWN_JNKIE_READABLE_ARTIFACT =
  KNOWN_JNKIE_REFERENCE_READABLE_ARTIFACT;
/** @deprecated This is an unverified earlier-sample reference, not a current exact audit. */
export const KNOWN_JNKIE_AUDIT_ARTIFACT =
  KNOWN_JNKIE_REFERENCE_AUDIT_ARTIFACT;
export const KNOWN_JNKIE_PROFILE_ARTIFACT = "jnkie-known-profile.json";

const PROFILE_DIRECTORY = "75107ad9-a76a6929";
const MAX_PROFILE_ASSET_BYTES = 2 * 1_024 * 1_024;

interface KnownAssetSpec {
  readonly sourceFile: string;
  readonly artifactFile: string;
  readonly mediaType: string;
  readonly byteLength: number;
  readonly sha256: string;
  readonly trustClass:
    | "current-stream-evidence"
    | "unverified-earlier-sample-reference";
}

interface LoadedKnownAsset {
  readonly spec: KnownAssetSpec;
  readonly sourceBytes: Uint8Array;
  readonly artifact: ExtractedArtifact;
}

const KNOWN_ASSET_SPECS: readonly KnownAssetSpec[] = [
  {
    sourceFile: "readable.compact.luau",
    artifactFile: KNOWN_JNKIE_REFERENCE_READABLE_ARTIFACT,
    mediaType: "text/plain; charset=utf-8",
    byteLength: 6_501,
    sha256: "75f4ff5a7993c5232846e2ad01622e91cc9603c6e8301791e70e94b96d8fe460",
    trustClass: "unverified-earlier-sample-reference",
  },
  {
    sourceFile: "exact-vm-audit.luau",
    artifactFile: KNOWN_JNKIE_REFERENCE_AUDIT_ARTIFACT,
    mediaType: "text/plain; charset=utf-8",
    byteLength: 494_202,
    sha256: "fe46362f71296988ebfef72cc3301acc45dcc4efe7eea1ac7d3e292369af159a",
    trustClass: "unverified-earlier-sample-reference",
  },
  {
    sourceFile: "prototypes.json",
    artifactFile: "jnkie-known-prototypes.json",
    mediaType: "application/json",
    byteLength: 241_900,
    sha256: "b2da9c8a8f70d015b2098c8e33996c8b40b9df732e12e778f89ac1bff7912dbe",
    trustClass: "current-stream-evidence",
  },
  {
    sourceFile: "top-ir.json",
    artifactFile: "jnkie-known-top-ir.json",
    mediaType: "application/json",
    byteLength: 223_110,
    sha256: "de5de60573a25388d154c0c24c8090a31a5bd6346a3c69771d6dbe7eb4dbf5a8",
    trustClass: "current-stream-evidence",
  },
  {
    sourceFile: "all-strings.tsv",
    artifactFile: "jnkie-known-all-strings.tsv",
    mediaType: "text/tab-separated-values; charset=utf-8",
    byteLength: 62_042,
    sha256: "0f56aacad8802af65908f7bd7aa6962991a8dd68249f089a66970fa8677656c1",
    trustClass: "current-stream-evidence",
  },
  {
    sourceFile: "constants.txt",
    artifactFile: "jnkie-known-constants.txt",
    mediaType: "text/plain; charset=utf-8",
    byteLength: 6_663,
    sha256: "a3c10fb20d8bb48929ca10f1c46d753e990584cc8905b99cc427fee173ad9bc5",
    trustClass: "current-stream-evidence",
  },
  {
    sourceFile: "prototypes-report.txt",
    artifactFile: "jnkie-known-prototypes-report.txt",
    mediaType: "text/plain; charset=utf-8",
    byteLength: 11_276,
    sha256: "06aa1df7846f88ea18b1beef16c0e0606c4bf9205baf44020b755ea2d007a2c5",
    trustClass: "current-stream-evidence",
  },
  {
    sourceFile: "ir-report.txt",
    artifactFile: "jnkie-known-ir-report.txt",
    mediaType: "text/plain; charset=utf-8",
    byteLength: 1_152,
    sha256: "42bd032f77d143299da83e07db9de105fa1841ffa44c0c069bd42878190f07e8",
    trustClass: "current-stream-evidence",
  },
  {
    sourceFile: "prototype-0.rough.lua",
    artifactFile: "jnkie-known-prototype-0-rough.lua",
    mediaType: "text/x-lua; charset=utf-8",
    byteLength: 3_272,
    sha256: "c8fd0ea8f538ac8e5cb6e29bc03dd9fcf21d2c66c9ad660c36cca8bdbd57297e",
    trustClass: "current-stream-evidence",
  },
  {
    sourceFile: "prototype-0.min.lua",
    artifactFile: "jnkie-known-prototype-0-min.lua",
    mediaType: "text/x-lua; charset=utf-8",
    byteLength: 3_100,
    sha256: "05682f9496667c707f995bec35528b644df44f8604801dca19e081b74c92acad",
    trustClass: "current-stream-evidence",
  },
  {
    sourceFile: "prototype-3.rough.lua",
    artifactFile: "jnkie-known-prototype-3-rough.lua",
    mediaType: "text/x-lua; charset=utf-8",
    byteLength: 77_217,
    sha256: "b905b8f572f78e8b4cc72274448017c1939d264e881aaad9396447765850ea33",
    trustClass: "current-stream-evidence",
  },
  {
    sourceFile: "prototype-3.min.lua",
    artifactFile: "jnkie-known-prototype-3-min.lua",
    mediaType: "text/x-lua; charset=utf-8",
    byteLength: 73_506,
    sha256: "c923d6ef9af4071de0ab2db9829c4db34deb3d2719cbdfefdc7a5ee8d352dc72",
    trustClass: "current-stream-evidence",
  },
] as const;

export interface KnownJnkieProfileManifest {
  readonly schemaVersion: 2;
  readonly profileId: string;
  readonly status: "loaded" | "not-matched" | "rejected";
  readonly match: {
    readonly loaderSha256: string;
    readonly payloadSha256: string;
    readonly requiresBothHashes: true;
  };
  readonly provenance: {
    readonly kind: "user-supplied-dual-hash-static-evidence-profile";
    readonly currentStreamEvidenceAssociation:
      | "exact-dual-stream-sha256-profile"
      | "not-matched";
    readonly unverifiedReferenceAssociation:
      "earlier-324503-byte-sample-not-current-evidence";
    readonly submittedCodeExecuted: false;
  };
  readonly currentStreamMetrics?: {
    readonly prototypeSummaryRecords: 371;
    readonly aggregateDeclaredInstructionCount: 34_696;
    readonly topPrototypeRawIrRows: 1_409;
    readonly constants: 9_270;
    readonly stringConstants: 669;
    readonly scope: "inventory-and-raw-ir-not-opcode-cfg-or-source-recovery";
  };
  readonly unverifiedReferenceMetrics?: {
    readonly sourceSampleInputBytes: 324_503;
    readonly compactReferenceLines: 201;
    readonly auditFunctions: 36;
    readonly auditInstructions: 9_414;
    readonly currentStreamEvidence: false;
  };
  readonly assets?: readonly {
    readonly fileName: string;
    readonly byteLength: number;
    readonly sha256: string;
    readonly trustClass:
      | "current-stream-evidence"
      | "unverified-earlier-sample-reference";
  }[];
  readonly rejectionReason?: string;
}

export type KnownJnkieProfileResolution =
  | {
      readonly status: "not-matched";
      readonly manifest: KnownJnkieProfileManifest;
      readonly artifacts: readonly ExtractedArtifact[];
    }
  | {
      readonly status: "rejected";
      readonly manifest: KnownJnkieProfileManifest;
      readonly artifacts: readonly ExtractedArtifact[];
    }
  | {
      readonly status: "loaded";
      readonly manifest: KnownJnkieProfileManifest;
      readonly artifacts: readonly ExtractedArtifact[];
    };

function profileRootCandidates(): readonly string[] {
  const suffix = join("assets", "jnkie", PROFILE_DIRECTORY);
  return [
    join(__dirname, "..", "..", "..", suffix),
    join(__dirname, "..", "..", "..", "..", suffix),
    join(process.cwd(), suffix),
  ];
}

function resolveProfileRoot(): string {
  const root = profileRootCandidates().find((candidate) =>
    KNOWN_ASSET_SPECS.every((spec) => existsSync(join(candidate, spec.sourceFile))),
  );
  if (!root) throw new Error("The packaged JNKIE knowledge pack is unavailable.");
  return root;
}

function wrapUnverifiedReference(
  spec: KnownAssetSpec,
  sourceBytes: Uint8Array,
): Uint8Array {
  const warning = [
    "3ziz Deobfuscator - UNVERIFIED EARLIER-SAMPLE REFERENCE",
    "",
    "This plain-text file came from a separate 324,503-byte Luraph sample.",
    "It is not readable output, an exact audit, or control-flow evidence for the current JNKIE input.",
    "It is exported only as a quarantined research reference and was never executed by this app.",
    `Original packaged reference: ${spec.sourceFile}`,
    `Original packaged reference SHA-256: ${spec.sha256}`,
    "",
    "----- BEGIN UNVERIFIED EARLIER-SAMPLE REFERENCE -----",
    "",
  ].join("\n");
  return Buffer.concat([Buffer.from(warning, "utf8"), Buffer.from(sourceBytes)]);
}

function readAndVerifyAssets(): readonly LoadedKnownAsset[] {
  const root = resolveProfileRoot();
  const assets: LoadedKnownAsset[] = [];
  let totalBytes = 0;
  for (const spec of KNOWN_ASSET_SPECS) {
    const sourceBytes = Uint8Array.from(readFileSync(join(root, spec.sourceFile)));
    totalBytes += sourceBytes.byteLength;
    if (
      sourceBytes.byteLength !== spec.byteLength ||
      sha256Bytes(sourceBytes) !== spec.sha256
    ) {
      throw new Error(`Knowledge-pack integrity failed for ${spec.sourceFile}.`);
    }
    if (totalBytes > MAX_PROFILE_ASSET_BYTES) {
      throw new Error("The JNKIE knowledge pack exceeds its static read limit.");
    }
    const bytes = spec.trustClass === "unverified-earlier-sample-reference"
      ? wrapUnverifiedReference(spec, sourceBytes)
      : sourceBytes;
    const artifact: ExtractedArtifact = {
      fileName: spec.artifactFile,
      mediaType: spec.mediaType,
      bytes,
      sha256: sha256Bytes(bytes),
    };
    assets.push({ spec, sourceBytes, artifact });
  }
  return assets;
}

function sourceAssetText(assets: readonly LoadedKnownAsset[], sourceFile: string): string {
  const asset = assets.find((candidate) => candidate.spec.sourceFile === sourceFile);
  if (!asset) throw new Error(`Knowledge-pack source asset ${sourceFile} is missing.`);
  return new TextDecoder("utf-8", { fatal: true }).decode(asset.sourceBytes);
}

function numberField(value: unknown, field: string): number {
  if (typeof value !== "object" || value === null) throw new Error(`Invalid ${field} record.`);
  const candidate = (value as Record<string, unknown>)[field];
  if (typeof candidate !== "number" || !Number.isFinite(candidate)) {
    throw new Error(`Invalid numeric field ${field}.`);
  }
  return candidate;
}

function validatePrototypeInventory(source: string): void {
  const records: unknown = JSON.parse(source);
  if (!Array.isArray(records) || records.length !== 371) {
    throw new Error("Prototype inventory does not contain 371 records.");
  }
  const tids = new Set<number>();
  let instructions = 0;
  let constants = 0;
  let strings = 0;
  let children = 0;
  let minimumStack = Number.POSITIVE_INFINITY;
  let maximumStack = Number.NEGATIVE_INFINITY;
  const parameterCounts = new Map<number, number>();
  for (const record of records) {
    const tid = numberField(record, "tid");
    tids.add(tid);
    instructions += numberField(record, "instructions");
    constants += numberField(record, "constant_count");
    strings += numberField(record, "string_constant_count");
    children += numberField(record, "child_refs");
    const stack = numberField(record, "maxstack");
    minimumStack = Math.min(minimumStack, stack);
    maximumStack = Math.max(maximumStack, stack);
    const parameters = numberField(record, "numparams");
    parameterCounts.set(parameters, (parameterCounts.get(parameters) ?? 0) + 1);
  }
  if (
    tids.size !== 371 ||
    instructions !== 34_696 ||
    constants !== 9_270 ||
    strings !== 669 ||
    children !== 370 ||
    minimumStack !== 2 ||
    maximumStack !== 99 ||
    parameterCounts.get(0) !== 370 ||
    parameterCounts.get(3) !== 1
  ) {
    throw new Error("Prototype inventory metrics do not match the known profile.");
  }
}

function validateTopIr(source: string): void {
  const parsed: unknown = JSON.parse(source);
  if (typeof parsed !== "object" || parsed === null) throw new Error("Top IR is not an object.");
  const record = parsed as Record<string, unknown>;
  if (!Array.isArray(record.rows) || record.rows.length !== 1_409) {
    throw new Error("Top IR does not contain 1,409 rows.");
  }
  const opcodes = new Set<number>();
  let constantRows = 0;
  let childRows = 0;
  const children = new Set<string | number>();
  record.rows.forEach((row, index) => {
    if (numberField(row, "pc") !== index + 1) throw new Error("Top IR PCs are not contiguous.");
    const opcode = numberField(row, "op");
    if (!Number.isInteger(opcode) || opcode < 3 || opcode > 280) {
      throw new Error("Top IR contains an out-of-range opcode.");
    }
    opcodes.add(opcode);
    const rowRecord = row as Record<string, unknown>;
    if (rowRecord.const !== null) constantRows += 1;
    if (rowRecord.child !== null) {
      if (typeof rowRecord.child !== "string" && typeof rowRecord.child !== "number") {
        throw new Error("Top IR child reference is invalid.");
      }
      childRows += 1;
      children.add(rowRecord.child);
    }
  });
  if (
    numberField(record, "maxstack") !== 40 ||
    numberField(record, "numparams") !== 0 ||
    opcodes.size !== 61 ||
    constantRows !== 283 ||
    childRows !== 334 ||
    children.size !== 334
  ) {
    throw new Error("Top IR metrics do not match the known profile.");
  }
}

function validateKnownContent(assets: readonly LoadedKnownAsset[]): void {
  const readableReference = sourceAssetText(assets, "readable.compact.luau");
  const auditReference = sourceAssetText(assets, "exact-vm-audit.luau");
  if (
    readableReference.split(/\r?\n/).length - Number(readableReference.endsWith("\n")) !== 201 ||
    !readableReference.includes("COMPACT READABLE DEOBFUSCATION") ||
    readableReference.trimStart().startsWith("return({xm")
  ) {
    throw new Error("Earlier-sample readable reference failed its internal consistency gates.");
  }

  const audit = validateLuraphAudit(auditReference);
  const facts = audit.facts;
  if (
    !audit.report.valid ||
    facts.functionCount !== 36 ||
    facts.decodedInstructions !== 9_414 ||
    facts.reachableInstructions !== 6_644 ||
    facts.omittedInstructions !== 2_770 ||
    facts.deterministicPatches !== 667 ||
    facts.ambiguousDecoderWrites !== 74 ||
    facts.labelDefinitions !== 6_644 ||
    facts.gotoReferences !== 2_789 ||
    facts.vmFragments !== 495 ||
    !facts.summaryMatchesMetadata
  ) {
    throw new Error("Earlier-sample VM audit reference failed its internal consistency gates.");
  }

  validatePrototypeInventory(sourceAssetText(assets, "prototypes.json"));
  validateTopIr(sourceAssetText(assets, "top-ir.json"));
}

function makeManifest(
  status: KnownJnkieProfileManifest["status"],
  loaderSha256: string,
  payloadSha256: string,
  assets?: readonly LoadedKnownAsset[],
  rejectionReason?: string,
): KnownJnkieProfileManifest {
  return {
    schemaVersion: 2,
    profileId: KNOWN_JNKIE_PROFILE_ID,
    status,
    match: {
      loaderSha256,
      payloadSha256,
      requiresBothHashes: true,
    },
    provenance: {
      kind: "user-supplied-dual-hash-static-evidence-profile",
      currentStreamEvidenceAssociation: status === "not-matched"
        ? "not-matched"
        : "exact-dual-stream-sha256-profile",
      unverifiedReferenceAssociation: "earlier-324503-byte-sample-not-current-evidence",
      submittedCodeExecuted: false,
    },
    ...(status === "loaded"
      ? {
          currentStreamMetrics: {
            prototypeSummaryRecords: 371,
            aggregateDeclaredInstructionCount: 34_696,
            topPrototypeRawIrRows: 1_409,
            constants: 9_270,
            stringConstants: 669,
            scope: "inventory-and-raw-ir-not-opcode-cfg-or-source-recovery",
          } as const,
          unverifiedReferenceMetrics: {
            sourceSampleInputBytes: 324_503,
            compactReferenceLines: 201,
            auditFunctions: 36,
            auditInstructions: 9_414,
            currentStreamEvidence: false,
          } as const,
        }
      : {}),
    ...(assets === undefined
      ? {}
      : {
          assets: assets.map((asset) => ({
            fileName: asset.artifact.fileName,
            byteLength: asset.artifact.bytes.byteLength,
            sha256: asset.artifact.sha256,
            trustClass: asset.spec.trustClass,
          })),
        }),
    ...(rejectionReason === undefined ? {} : { rejectionReason }),
  };
}

export function resolveKnownJnkieProfile(
  loader: Uint8Array,
  payload: Uint8Array,
): KnownJnkieProfileResolution {
  const loaderSha256 = sha256Bytes(loader);
  const payloadSha256 = sha256Bytes(payload);
  if (
    loaderSha256 !== KNOWN_JNKIE_LOADER_SHA256 ||
    payloadSha256 !== KNOWN_JNKIE_PAYLOAD_SHA256
  ) {
    return {
      status: "not-matched",
      manifest: makeManifest("not-matched", loaderSha256, payloadSha256),
      artifacts: [],
    };
  }

  try {
    const assets = readAndVerifyAssets();
    validateKnownContent(assets);
    return {
      status: "loaded",
      manifest: makeManifest("loaded", loaderSha256, payloadSha256, assets),
      artifacts: assets.map((asset) => asset.artifact),
    };
  } catch (error) {
    return {
      status: "rejected",
      manifest: makeManifest(
        "rejected",
        loaderSha256,
        payloadSha256,
        undefined,
        error instanceof Error ? error.message.slice(0, 512) : "Knowledge-pack validation failed.",
      ),
      artifacts: [],
    };
  }
}

export function knownProfileManifestArtifact(
  manifest: KnownJnkieProfileManifest,
): ExtractedArtifact {
  const bytes = Buffer.from(`${JSON.stringify(manifest, null, 2)}\n`, "utf8");
  return {
    fileName: KNOWN_JNKIE_PROFILE_ARTIFACT,
    mediaType: "application/json",
    bytes,
    sha256: sha256Bytes(bytes),
  };
}
