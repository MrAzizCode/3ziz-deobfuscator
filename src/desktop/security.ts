import {
  basename,
  extname,
  isAbsolute,
  relative,
  resolve,
  sep,
} from "node:path";

export const APP_BUNDLE_ORIGIN = "app://bundle";
export const APP_INDEX_URL = `${APP_BUNDLE_ORIGIN}/index.html`;
export const DEV_RENDERER_URL = "http://127.0.0.1:4317/";

export const ALLOWED_INPUT_EXTENSIONS = Object.freeze([
  ".lua",
  ".luau",
  ".luac",
  ".txt",
] as const);

const ALLOWED_INPUT_EXTENSION_SET = new Set<string>(
  ALLOWED_INPUT_EXTENSIONS,
);

const MIME_TYPES = new Map<string, string>([
  [".css", "text/css; charset=utf-8"],
  [".gif", "image/gif"],
  [".html", "text/html; charset=utf-8"],
  [".ico", "image/x-icon"],
  [".jpeg", "image/jpeg"],
  [".jpg", "image/jpeg"],
  [".js", "text/javascript; charset=utf-8"],
  [".json", "application/json; charset=utf-8"],
  [".map", "application/json; charset=utf-8"],
  [".mjs", "text/javascript; charset=utf-8"],
  [".png", "image/png"],
  [".svg", "image/svg+xml"],
  [".ttf", "font/ttf"],
  [".txt", "text/plain; charset=utf-8"],
  [".wasm", "application/wasm"],
  [".webp", "image/webp"],
  [".woff", "font/woff"],
  [".woff2", "font/woff2"],
]);

export interface BundleAssetResolution {
  readonly filePath: string;
  readonly mimeType: string;
  readonly relativePath: string;
}

export interface ValidatedInputPath {
  readonly path: string;
  readonly extension: (typeof ALLOWED_INPUT_EXTENSIONS)[number];
}

/**
 * Maps a custom protocol request to a path below the trusted renderer bundle.
 * The raw path is checked before URL normalization so encoded dot segments and
 * encoded separators cannot be hidden by the WHATWG URL parser.
 */
export function resolveBundleAssetUrl(
  requestUrl: string,
  bundleRoot: string,
): BundleAssetResolution | null {
  if (
    typeof requestUrl !== "string" ||
    requestUrl.length > 16_384 ||
    requestUrl.includes("\0") ||
    !isAbsolute(bundleRoot)
  ) {
    return null;
  }

  const schemeSeparator = requestUrl.indexOf("://");
  if (schemeSeparator < 0) {
    return null;
  }
  const pathStart = requestUrl.indexOf("/", schemeSeparator + 3);
  const rawPathAndSuffix =
    pathStart < 0 ? "/" : requestUrl.slice(pathStart);
  const suffixStart = rawPathAndSuffix.search(/[?#]/);
  const rawPath =
    suffixStart < 0
      ? rawPathAndSuffix
      : rawPathAndSuffix.slice(0, suffixStart);

  if (rawPath.includes("\\") || /%2f|%5c|%00/i.test(rawPath)) {
    return null;
  }

  const decodedRawSegments: string[] = [];
  for (const rawSegment of rawPath.split("/")) {
    if (rawSegment.length === 0) {
      continue;
    }
    let decoded: string;
    try {
      decoded = decodeURIComponent(rawSegment);
    } catch {
      return null;
    }
    if (
      decoded === "." ||
      decoded === ".." ||
      decoded.includes("/") ||
      decoded.includes("\\") ||
      decoded.includes("\0")
    ) {
      return null;
    }
    decodedRawSegments.push(decoded);
  }

  let parsed: URL;
  try {
    parsed = new URL(requestUrl);
  } catch {
    return null;
  }
  if (
    parsed.protocol !== "app:" ||
    parsed.hostname !== "bundle" ||
    parsed.username !== "" ||
    parsed.password !== "" ||
    parsed.port !== "" ||
    parsed.search !== ""
  ) {
    return null;
  }

  const segments =
    decodedRawSegments.length === 0
      ? ["index.html"]
      : decodedRawSegments;
  const root = resolve(bundleRoot);
  const candidate = resolve(root, ...segments);
  if (!isPathWithin(root, candidate)) {
    return null;
  }
  const relativePath = relative(root, candidate);
  return {
    filePath: candidate,
    mimeType:
      MIME_TYPES.get(extname(candidate).toLowerCase()) ??
      "application/octet-stream",
    relativePath,
  };
}

export function isPathWithin(rootPath: string, candidatePath: string): boolean {
  const root = resolve(rootPath);
  const candidate = resolve(candidatePath);
  const childPath = relative(root, candidate);
  return (
    childPath !== "" &&
    childPath !== ".." &&
    !childPath.startsWith(`..${sep}`) &&
    !isAbsolute(childPath)
  );
}

export function resolveArtifactFilePath(
  jobDirectory: string,
  fileName: string,
): string | null {
  if (
    !isAbsolute(jobDirectory) ||
    !isSafeSingleFileName(fileName)
  ) {
    return null;
  }
  const root = resolve(jobDirectory);
  const candidate = resolve(root, fileName);
  return isPathWithin(root, candidate) ? candidate : null;
}

export function isSafeSingleFileName(fileName: string): boolean {
  return (
    typeof fileName === "string" &&
    fileName.length > 0 &&
    fileName.length <= 255 &&
    fileName !== "." &&
    fileName !== ".." &&
    !fileName.includes("\0") &&
    !fileName.includes("/") &&
    !fileName.includes("\\") &&
    basename(fileName) === fileName
  );
}

export function validateInputPath(value: unknown): ValidatedInputPath {
  if (
    typeof value !== "string" ||
    value.length === 0 ||
    value.length > 32_767 ||
    value.includes("\0") ||
    !isAbsolute(value)
  ) {
    throw new Error("Input path must be a bounded absolute local path.");
  }
  const extension = extname(value).toLowerCase();
  if (!ALLOWED_INPUT_EXTENSION_SET.has(extension)) {
    throw new Error(
      `Unsupported input extension "${extension || "(none)"}"; choose a .lua, .luau, .luac, or .txt file.`,
    );
  }
  return {
    path: resolve(value),
    extension: extension as ValidatedInputPath["extension"],
  };
}

export function validateJobId(value: unknown): string {
  if (
    typeof value !== "string" ||
    !/^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i.test(
      value,
    )
  ) {
    throw new Error("Job ID must be a UUID.");
  }
  return value.toLowerCase();
}

export function expectNoArguments(args: readonly unknown[]): void {
  if (args.length !== 0) {
    throw new Error("This desktop operation does not accept arguments.");
  }
}

export function expectOneStringArgument(
  args: readonly unknown[],
  label: string,
  maxLength: number,
): string {
  if (
    args.length !== 1 ||
    typeof args[0] !== "string" ||
    args[0].length === 0 ||
    args[0].length > maxLength ||
    args[0].includes("\0")
  ) {
    throw new Error(`${label} must be one bounded string argument.`);
  }
  return args[0];
}

export function isAllowedIpcSenderUrl(
  senderUrl: string,
  isPackaged: boolean,
): boolean {
  if (typeof senderUrl !== "string" || senderUrl.length > 4_096) {
    return false;
  }
  let parsed: URL;
  try {
    parsed = new URL(senderUrl);
  } catch {
    return false;
  }
  if (
    parsed.username !== "" ||
    parsed.password !== "" ||
    parsed.search !== "" ||
    parsed.hash !== ""
  ) {
    return false;
  }
  if (isPackaged) {
    return (
      parsed.protocol === "app:" &&
      parsed.hostname === "bundle" &&
      parsed.port === "" &&
      parsed.pathname === "/index.html"
    );
  }
  return (
    parsed.protocol === "http:" &&
    parsed.hostname === "127.0.0.1" &&
    parsed.port === "4317" &&
    parsed.pathname === "/"
  );
}

export function isAllowedRendererRequestUrl(
  requestUrl: string,
  isPackaged: boolean,
): boolean {
  let parsed: URL;
  try {
    parsed = new URL(requestUrl);
  } catch {
    return false;
  }
  if (parsed.protocol === "data:" || parsed.protocol === "blob:") {
    return true;
  }
  if (isPackaged) {
    return (
      parsed.protocol === "app:" &&
      parsed.hostname === "bundle" &&
      parsed.username === "" &&
      parsed.password === "" &&
      parsed.port === ""
    );
  }
  return (
    (parsed.protocol === "http:" || parsed.protocol === "ws:") &&
    parsed.hostname === "127.0.0.1" &&
    parsed.port === "4317" &&
    parsed.username === "" &&
    parsed.password === ""
  );
}

export function makeExportDirectoryBaseName(
  inputFileName: string,
  jobId: string,
): string {
  const base = basename(inputFileName, extname(inputFileName))
    .normalize("NFKD")
    .replace(/[^a-zA-Z0-9._-]+/g, "-")
    .replace(/^-+|-+$/g, "")
    .slice(0, 48);
  const safeBase = base.length === 0 ? "analysis" : base;
  const idSuffix = validateJobId(jobId).slice(0, 8);
  return `3ziz-${safeBase}-${idSuffix}`;
}

/**
 * Builds an explicit environment allowlist for an analysis utility process.
 * Credential, cloud, proxy, shell-history, and application variables are not
 * copied through.
 */
export function buildMinimalWorkerEnvironment(
  source: NodeJS.ProcessEnv,
  tempDirectory: string,
  nodeEnvironment: "development" | "production",
): Record<string, string> {
  const result: Record<string, string> = {
    NODE_ENV: nodeEnvironment,
    TEMP: tempDirectory,
    TMP: tempDirectory,
  };
  const allowedNames = [
    "SystemRoot",
    "WINDIR",
    "LANG",
    "LC_ALL",
    "TZ",
  ] as const;
  const entries = Object.entries(source);
  for (const allowedName of allowedNames) {
    const entry = entries.find(
      ([name, value]) =>
        name.toLowerCase() === allowedName.toLowerCase() &&
        typeof value === "string" &&
        value.length > 0,
    );
    if (entry !== undefined) {
      result[allowedName] = entry[1] ?? "";
    }
  }
  return result;
}
