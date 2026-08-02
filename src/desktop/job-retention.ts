import {
  lstat,
  mkdir,
  readdir,
  rm,
} from "node:fs/promises";
import {
  isAbsolute,
  relative,
  resolve,
  sep,
} from "node:path";

const UUID =
  /^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;

export function managedJobStoragePath(
  jobsRoot: string,
  requestId: string,
): string {
  if (!isAbsolute(jobsRoot) || !UUID.test(requestId)) {
    throw new Error("Managed job storage requires an absolute root and UUID.");
  }
  return resolve(jobsRoot, "pending", requestId.toLowerCase());
}

export function isManagedJobStoragePath(
  jobsRoot: string,
  candidatePath: string,
): boolean {
  if (!isAbsolute(jobsRoot) || !isAbsolute(candidatePath)) {
    return false;
  }
  const relativePath = relative(
    resolve(jobsRoot),
    resolve(candidatePath),
  );
  const segments = relativePath.split(sep);
  return (
    segments.length === 2 &&
    segments[0] === "pending" &&
    segments[1] !== undefined &&
    UUID.test(segments[1])
  );
}

export async function createManagedJobStorage(
  jobsRoot: string,
  requestId: string,
): Promise<string> {
  const pendingRoot = resolve(jobsRoot, "pending");
  const storagePath = managedJobStoragePath(jobsRoot, requestId);
  await mkdir(pendingRoot, { recursive: true });
  await mkdir(storagePath, { recursive: false });
  return storagePath;
}

export async function removeManagedJobStorage(
  jobsRoot: string,
  storagePath: string,
): Promise<void> {
  if (!isManagedJobStoragePath(jobsRoot, storagePath)) {
    throw new Error("Refused to remove a path outside managed job storage.");
  }
  try {
    const metadata = await lstat(storagePath);
    if (metadata.isSymbolicLink() || !metadata.isDirectory()) {
      throw new Error("Managed job storage is not a regular directory.");
    }
  } catch (error) {
    if (hasErrorCode(error, "ENOENT")) {
      return;
    }
    throw error;
  }
  await rm(storagePath, {
    recursive: true,
    force: false,
    maxRetries: 2,
    retryDelay: 50,
  });
}

/**
 * Clears only UUID-named app-managed job directories. Unrecognized entries and
 * symlinks are left untouched.
 */
export async function cleanupStaleJobStorage(
  jobsRoot: string,
): Promise<void> {
  if (!isAbsolute(jobsRoot)) {
    throw new Error("Jobs root must be absolute.");
  }
  const pendingRoot = resolve(jobsRoot, "pending");
  await mkdir(pendingRoot, { recursive: true });
  const pendingEntries = await readdir(pendingRoot, {
    withFileTypes: true,
  });
  for (const entry of pendingEntries) {
    if (!entry.isDirectory() || entry.isSymbolicLink() || !UUID.test(entry.name)) {
      continue;
    }
    await removeManagedJobStorage(
      jobsRoot,
      resolve(pendingRoot, entry.name),
    );
  }

  // Remove UUID directories created by the foundation broker before request
  // isolation was introduced. Files and unknown directory names are retained.
  const rootEntries = await readdir(jobsRoot, { withFileTypes: true });
  for (const entry of rootEntries) {
    if (!entry.isDirectory() || entry.isSymbolicLink() || !UUID.test(entry.name)) {
      continue;
    }
    const legacyPath = resolve(jobsRoot, entry.name);
    const relativePath = relative(resolve(jobsRoot), legacyPath);
    if (
      relativePath === entry.name &&
      !relativePath.includes(sep)
    ) {
      await rm(legacyPath, {
        recursive: true,
        force: false,
        maxRetries: 2,
        retryDelay: 50,
      });
    }
  }
}

function hasErrorCode(error: unknown, code: string): boolean {
  return (
    error !== null &&
    typeof error === "object" &&
    "code" in error &&
    error.code === code
  );
}
