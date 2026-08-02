import { randomUUID } from "node:crypto";
import {
  mkdir,
  open,
  readFile,
  realpath,
  rm,
  stat,
  writeFile,
} from "node:fs/promises";
import {
  basename,
  join,
  resolve,
} from "node:path";

import {
  app,
  BrowserWindow,
  dialog,
  ipcMain,
  protocol,
  session,
  utilityProcess,
  type IpcMainEvent,
  type IpcMainInvokeEvent,
  type Session,
} from "electron";

import type { PersistedBrokerAnalysisResult } from "../core/broker";
import type { AnalyzeWorkerResponse } from "../core/worker/handler";
import {
  DESKTOP_IPC,
  type DesktopProgressEvent,
} from "./channels";
import { verifyArtifactSha256 } from "./artifact-integrity";
import {
  cleanupStaleJobStorage,
  createManagedJobStorage,
  removeManagedJobStorage,
} from "./job-retention";
import {
  adaptBrokerAnalysisResult,
  readCappedFile,
  type RendererAnalysisResult,
} from "./result-adapter";
import { presentVerifiedStages } from "./progress-presentation";
import {
  selectRendererTarget,
  type RendererTarget,
} from "./runtime-policy";
import {
  ALLOWED_INPUT_EXTENSIONS,
  buildMinimalWorkerEnvironment,
  expectNoArguments,
  expectOneStringArgument,
  isAllowedIpcSenderUrl,
  isAllowedRendererRequestUrl,
  isPathWithin,
  isSafeSingleFileName,
  makeExportDirectoryBaseName,
  resolveArtifactFilePath,
  resolveBundleAssetUrl,
  validateInputPath,
  validateJobId,
} from "./security";

app.enableSandbox();

const ownsSingleInstanceLock = app.requestSingleInstanceLock();
if (!ownsSingleInstanceLock) {
  app.quit();
}

protocol.registerSchemesAsPrivileged([
  {
    scheme: "app",
    privileges: {
      standard: true,
      secure: true,
      supportFetchAPI: true,
      corsEnabled: false,
      allowServiceWorkers: false,
      bypassCSP: false,
    },
  },
]);

const ANALYSIS_TIMEOUT_MS = 60_000;
// The exact JNKIE fixture expands into 261,864 typed instruction records plus
// deterministic validation artifacts. Keep the worker bounded, but leave
// enough headroom for that evidence-backed analysis to complete.
const ANALYSIS_MEMORY_LIMIT_MIB = 768;
const ANALYSIS_MEMORY_LIMIT_BYTES =
  ANALYSIS_MEMORY_LIMIT_MIB * 1024 * 1024;
const ANALYSIS_OLD_SPACE_LIMIT_MIB = 512;
const MAX_ACTIVE_JOBS = 4;
const MAX_COMPLETED_JOBS = 8;
const MAX_EXPORT_BYTES = 48 * 1024 * 1024;
const MAX_BUNDLE_ASSET_BYTES = 64 * 1024 * 1024;
const MAX_AUTHORIZED_INPUTS = 256;
const CONTENT_SECURITY_POLICY = [
  "default-src 'self'",
  "script-src 'self'",
  "style-src 'self' 'unsafe-inline'",
  "font-src 'self' data:",
  "img-src 'self' data:",
  "worker-src 'self' blob:",
  "connect-src 'none'",
  "object-src 'none'",
  "frame-src 'none'",
  "base-uri 'none'",
  "form-action 'none'",
].join("; ");

interface ActiveJob {
  readonly id: string;
  readonly inputPath: string;
  cancel(reason: string): void;
}

interface CompletedJob {
  readonly id: string;
  readonly inputName: string;
  readonly result: PersistedBrokerAnalysisResult["writtenJob"];
  readonly storageRoot: string;
}

let mainWindow: BrowserWindow | null = null;
let rendererSession: Session | null = null;
let rendererTarget: RendererTarget = selectRendererTarget(app.isPackaged, undefined);
let ipcRegistered = false;
const activeJobs = new Map<string, ActiveJob>();
const completedJobs = new Map<string, CompletedJob>();
const authorizedInputs = new Set<string>();

app.on("web-contents-created", (_event, contents) => {
  contents.setWindowOpenHandler(() => ({ action: "deny" }));
  contents.on("will-attach-webview", (event) => {
    event.preventDefault();
  });
  contents.on("will-navigate", (event) => {
    event.preventDefault();
  });
  contents.on("will-frame-navigate", (event) => {
    event.preventDefault();
  });
  contents.on("will-redirect", (event) => {
    event.preventDefault();
  });
});

app.on("before-quit", () => {
  for (const job of [...activeJobs.values()]) {
    job.cancel("Application is closing.");
  }
});

app.on("window-all-closed", () => {
  app.quit();
});

app.on("activate", () => {
  if (BrowserWindow.getAllWindows().length === 0 && rendererSession !== null) {
    void createMainWindow(rendererSession);
  }
});

app.on("second-instance", () => {
  const window = mainWindow;
  if (window !== null && !window.isDestroyed()) {
    if (window.isMinimized()) {
      window.restore();
    }
    window.focus();
  }
});

if (ownsSingleInstanceLock) {
void app
  .whenReady()
  .then(async () => {
    const jobsRoot = join(app.getPath("userData"), "jobs");
    const workerTemp = join(app.getPath("temp"), "3ziz-deobfuscator-worker");
    await mkdir(jobsRoot, { recursive: true });
    await cleanupStaleJobStorage(jobsRoot);
    await mkdir(workerTemp, { recursive: true });

    rendererTarget = selectRendererTarget(
      app.isPackaged,
      process.env.ZIZ_DEV_RENDERER_URL,
    );
    rendererSession = session.fromPartition("3ziz-renderer", {
      cache: false,
    });
    configureRendererSession(
      rendererSession,
      rendererTarget.kind === "bundle",
    );
    if (rendererTarget.kind === "bundle") {
      await registerBundleProtocol(rendererSession);
    }
    registerIpcHandlers(jobsRoot, workerTemp);
    await createMainWindow(rendererSession);
  })
  .catch((error: unknown) => {
    dialog.showErrorBox(
      "3ziz Deobfuscator could not start",
      error instanceof Error ? error.message : "Desktop initialization failed.",
    );
    app.quit();
  });
}

function configureRendererSession(
  targetSession: Session,
  useBundle: boolean,
): void {
  targetSession.setPermissionRequestHandler(
    (_webContents, _permission, callback) => {
      callback(false);
    },
  );
  targetSession.setPermissionCheckHandler(() => false);
  targetSession.setDevicePermissionHandler(() => false);
  targetSession.on("will-download", (event) => {
    event.preventDefault();
  });
  targetSession.webRequest.onBeforeRequest((details, callback) => {
    callback({
      cancel: !isAllowedRendererRequestUrl(details.url, useBundle),
    });
  });
}

async function registerBundleProtocol(targetSession: Session): Promise<void> {
  const bundleRoot = join(app.getAppPath(), "dist", "renderer");
  const realBundleRoot = await realpath(bundleRoot);
  await targetSession.protocol.handle("app", async (request) => {
    if (request.method !== "GET" && request.method !== "HEAD") {
      return textResponse(405, "Method Not Allowed");
    }
    const resolution = resolveBundleAssetUrl(request.url, realBundleRoot);
    if (resolution === null) {
      return textResponse(404, "Not Found");
    }
    try {
      const realAssetPath = await realpath(resolution.filePath);
      if (!isPathWithin(realBundleRoot, realAssetPath)) {
        return textResponse(404, "Not Found");
      }
      const metadata = await stat(realAssetPath);
      if (
        !metadata.isFile() ||
        metadata.size > MAX_BUNDLE_ASSET_BYTES
      ) {
        return textResponse(404, "Not Found");
      }
      const headers = localAssetHeaders(
        resolution.mimeType,
        metadata.size,
      );
      if (request.method === "HEAD") {
        return new Response(null, { status: 200, headers });
      }
      const bytes = await readFile(realAssetPath);
      if (bytes.byteLength !== metadata.size) {
        return textResponse(409, "Asset changed while being read");
      }
      return new Response(Uint8Array.from(bytes), {
        status: 200,
        headers,
      });
    } catch {
      return textResponse(404, "Not Found");
    }
  });
}

function localAssetHeaders(
  mimeType: string,
  byteLength: number,
): Record<string, string> {
  return {
    "cache-control": "no-store",
    "content-length": String(byteLength),
    "content-security-policy": CONTENT_SECURITY_POLICY,
    "content-type": mimeType,
    "cross-origin-resource-policy": "same-origin",
    "referrer-policy": "no-referrer",
    "x-content-type-options": "nosniff",
  };
}

function textResponse(status: number, body: string): Response {
  return new Response(body, {
    status,
    headers: {
      "cache-control": "no-store",
      "content-security-policy": CONTENT_SECURITY_POLICY,
      "content-type": "text/plain; charset=utf-8",
      "x-content-type-options": "nosniff",
    },
  });
}

async function createMainWindow(targetSession: Session): Promise<void> {
  if (mainWindow !== null && !mainWindow.isDestroyed()) {
    mainWindow.focus();
    return;
  }

  const window = new BrowserWindow({
    width: 1440,
    height: 920,
    minWidth: 1040,
    minHeight: 700,
    show: false,
    autoHideMenuBar: true,
    backgroundColor: "#07111f",
    webPreferences: {
      preload: join(__dirname, "preload.js"),
      session: targetSession,
      nodeIntegration: false,
      nodeIntegrationInWorker: false,
      contextIsolation: true,
      sandbox: true,
      webSecurity: true,
      webviewTag: false,
      allowRunningInsecureContent: false,
      experimentalFeatures: false,
      navigateOnDragDrop: false,
      safeDialogs: true,
      spellcheck: false,
      devTools: rendererTarget.kind === "dev-server",
    },
  });
  mainWindow = window;
  window.setMenuBarVisibility(false);
  window.webContents.setWindowOpenHandler(() => ({ action: "deny" }));
  window.once("ready-to-show", () => {
    if (!window.isDestroyed()) {
      window.show();
    }
  });
  window.on("closed", () => {
    if (mainWindow === window) {
      mainWindow = null;
    }
    for (const job of [...activeJobs.values()]) {
      job.cancel("Desktop window closed.");
    }
    authorizedInputs.clear();
  });

  await window.loadURL(rendererTarget.url);
}

function registerIpcHandlers(
  jobsRoot: string,
  workerTemp: string,
): void {
  if (ipcRegistered) {
    return;
  }
  ipcRegistered = true;

  ipcMain.handle(
    DESKTOP_IPC.chooseFile,
    secureInvoke(async (_event, args) => {
      expectNoArguments(args);
      const window = requireMainWindow();
      const chosen = await dialog.showOpenDialog(window, {
        title: "Choose Lua or Luau input",
        properties: ["openFile"],
        filters: [
          {
            name: "Lua and Luau",
            extensions: ALLOWED_INPUT_EXTENSIONS.map((extension) =>
              extension.slice(1),
            ),
          },
        ],
      });
      if (chosen.canceled || chosen.filePaths.length !== 1) {
        return null;
      }
      const validated = validateInputPath(chosen.filePaths[0]);
      authorizeInput(validated.path);
      return {
        path: validated.path,
        name: basename(validated.path),
      };
    }),
  );

  ipcMain.on(
    DESKTOP_IPC.authorizeDroppedFile,
    (event, ...args: unknown[]) => {
      try {
        assertTrustedSender(event);
        const path = expectOneStringArgument(
          args,
          "Dropped file path",
          32_767,
        );
        const validated = validateInputPath(path);
        authorizeInput(validated.path);
      } catch {
        // An invalid asynchronous authorization is intentionally ignored.
      }
    },
  );

  ipcMain.handle(
    DESKTOP_IPC.analyzeFile,
    secureInvoke(async (_event, args): Promise<RendererAnalysisResult> => {
      const path = expectOneStringArgument(
        args,
        "Input path",
        32_767,
      );
      const validated = validateInputPath(path);
      if (!authorizedInputs.has(authorizationKey(validated.path))) {
        throw new Error(
          "The input path was not authorized by the file picker or a local file drop.",
        );
      }
      if (activeJobs.size >= MAX_ACTIVE_JOBS) {
        throw new Error(
          `At most ${MAX_ACTIVE_JOBS} analyses may run at once.`,
        );
      }

      const requestId = randomUUID();
      const startedAt = Date.now();
      let storageRoot: string | null = null;
      let retained = false;
      const lifecycle = new AbortController();
      activeJobs.set(requestId, {
        id: requestId,
        inputPath: validated.path,
        cancel: (reason) => {
          if (!lifecycle.signal.aborted) {
            lifecycle.abort(new Error(reason));
          }
        },
      });
      sendProgress({
        jobId: requestId,
        stage: "ingesting",
        status: "active",
        percent: 5,
        message: "Starting a restricted static analysis worker…",
        inputPath: validated.path,
      });

      try {
        storageRoot = await createManagedJobStorage(jobsRoot, requestId);
        const brokerResult = await runAnalysisWorker({
          requestId,
          inputPath: validated.path,
          jobsRoot: storageRoot,
          workerTemp,
          signal: lifecycle.signal,
        });
        throwIfAnalysisAborted(lifecycle.signal);
        assertBrokerResultInvariant(brokerResult, storageRoot, requestId);
        const rendererResult = await adaptBrokerAnalysisResult(
          brokerResult,
          validated.path,
          Date.now() - startedAt,
        );
        throwIfAnalysisAborted(lifecycle.signal);
        await presentVerifiedStages({
          jobId: requestId,
          inputPath: validated.path,
          startedAt,
          stages: rendererResult.stages,
          signal: lifecycle.signal,
          emit: sendProgress,
        });
        throwIfAnalysisAborted(lifecycle.signal);
        const completedJob: CompletedJob = {
          id: rendererResult.jobId,
          inputName: brokerResult.analysis.report.input.fileName,
          result: brokerResult.writtenJob,
          storageRoot,
        };
        throwIfAnalysisAborted(lifecycle.signal);
        await rememberCompletedJob(completedJob, jobsRoot);
        retained = true;
        if (lifecycle.signal.aborted) {
          const remembered = completedJobs.get(completedJob.id);
          if (remembered?.storageRoot === completedJob.storageRoot) {
            completedJobs.delete(completedJob.id);
          }
          retained = false;
          throwIfAnalysisAborted(lifecycle.signal);
        }
        sendProgress({
          jobId: requestId,
          stage: "emitting",
          status: "complete",
          percent: 100,
          message: "Static analysis and artifact validation completed.",
          inputPath: validated.path,
        });
        return rendererResult;
      } catch (error) {
        if (!lifecycle.signal.aborted) {
          sendProgress({
            jobId: requestId,
            stage: "validating",
            status: "error",
            percent: 100,
            message:
              error instanceof Error
                ? error.message.slice(0, 2_048)
                : "Analysis failed safely.",
            inputPath: validated.path,
          });
        }
        throw error;
      } finally {
        activeJobs.delete(requestId);
        if (!retained && storageRoot !== null) {
          await removeManagedJobStorage(
            jobsRoot,
            storageRoot,
          ).catch(() => undefined);
        }
      }
    }),
  );

  ipcMain.handle(
    DESKTOP_IPC.cancelJob,
    secureInvoke(async (_event, args) => {
      const rawJobId = expectOneStringArgument(args, "Job ID", 64);
      const jobId = validateJobId(rawJobId);
      const active = activeJobs.get(jobId);
      if (active !== undefined) {
        sendProgress({
          jobId,
          message: "Analysis cancelled by the user.",
          inputPath: active.inputPath,
        });
        active.cancel("Analysis cancelled by the user.");
        return { outcome: "cancelled" } as const;
      }
      if (completedJobs.has(jobId)) {
        return { outcome: "already-complete" } as const;
      }
      throw new Error("No active analysis exists for that job ID.");
    }),
  );

  ipcMain.handle(
    DESKTOP_IPC.exportJob,
    secureInvoke(async (_event, args) => {
      const rawJobId = expectOneStringArgument(args, "Job ID", 64);
      const jobId = validateJobId(rawJobId);
      const completed = completedJobs.get(jobId);
      if (completed === undefined) {
        throw new Error("The requested completed job is not available.");
      }
      const window = requireMainWindow();
      const selected = await dialog.showOpenDialog(window, {
        title: "Choose an export destination",
        properties: ["openDirectory", "createDirectory"],
      });
      const selectedPath = selected.filePaths[0];
      if (selected.canceled || selectedPath === undefined || selected.filePaths.length !== 1) {
        return { cancelled: true };
      }
      const destinationRoot = resolve(selectedPath);
      const metadata = await stat(destinationRoot);
      if (!metadata.isDirectory()) {
        throw new Error("Export destination must be a directory.");
      }
      const realDestinationRoot = await realpath(destinationRoot);
      const baseName = makeExportDirectoryBaseName(
        completed.inputName,
        completed.id,
      );
      const exportDirectory = await createUniqueExportDirectory(
        realDestinationRoot,
        baseName,
      );
      try {
        await copyCompletedJob(completed, exportDirectory);
        return { path: exportDirectory, cancelled: false };
      } catch (error) {
        if (isPathWithin(realDestinationRoot, exportDirectory)) {
          await rm(exportDirectory, {
            recursive: true,
            force: true,
          }).catch(() => undefined);
        }
        throw error;
      }
    }),
  );
}

function secureInvoke<T>(
  handler: (
    event: IpcMainInvokeEvent,
    args: readonly unknown[],
  ) => Promise<T> | T,
): (
  event: IpcMainInvokeEvent,
  ...args: unknown[]
) => Promise<T> {
  return async (event, ...args) => {
    assertTrustedSender(event);
    return handler(event, args);
  };
}

function assertTrustedSender(
  event: IpcMainInvokeEvent | IpcMainEvent,
): void {
  const window = requireMainWindow();
  const senderFrame = event.senderFrame;
  if (
    event.sender !== window.webContents ||
    senderFrame === null ||
    senderFrame !== event.sender.mainFrame ||
    !isAllowedIpcSenderUrl(senderFrame.url, rendererTarget.kind === "bundle")
  ) {
    throw new Error("Rejected IPC from an untrusted renderer frame.");
  }
}

function requireMainWindow(): BrowserWindow {
  if (mainWindow === null || mainWindow.isDestroyed()) {
    throw new Error("The desktop window is unavailable.");
  }
  return mainWindow;
}

function authorizeInput(path: string): void {
  const key = authorizationKey(path);
  authorizedInputs.delete(key);
  authorizedInputs.add(key);
  while (authorizedInputs.size > MAX_AUTHORIZED_INPUTS) {
    const oldest = authorizedInputs.values().next().value as
      | string
      | undefined;
    if (oldest === undefined) {
      break;
    }
    authorizedInputs.delete(oldest);
  }
}

function authorizationKey(path: string): string {
  const normalized = resolve(path);
  return process.platform === "win32"
    ? normalized.toLocaleLowerCase("en-US")
    : normalized;
}

function sendProgress(event: DesktopProgressEvent): void {
  const window = mainWindow;
  if (
    window === null ||
    window.isDestroyed() ||
    window.webContents.isDestroyed()
  ) {
    return;
  }
  window.webContents.send(DESKTOP_IPC.progress, event);
}

function throwIfAnalysisAborted(signal: AbortSignal): void {
  if (!signal.aborted) {
    return;
  }
  throw signal.reason instanceof Error
    ? signal.reason
    : new Error(
        typeof signal.reason === "string"
          ? signal.reason
          : "Analysis cancelled.",
      );
}

interface RunWorkerOptions {
  readonly requestId: string;
  readonly inputPath: string;
  readonly jobsRoot: string;
  readonly workerTemp: string;
  readonly signal: AbortSignal;
}

function runAnalysisWorker(
  options: RunWorkerOptions,
): Promise<PersistedBrokerAnalysisResult> {
  return new Promise((resolvePromise, rejectPromise) => {
    const workerPath = join(__dirname, "worker-entry.js");
    const child = utilityProcess.fork(workerPath, [], {
      cwd: options.workerTemp,
      env: buildMinimalWorkerEnvironment(
        process.env,
        options.workerTemp,
        app.isPackaged ? "production" : "development",
      ),
      execArgv: [
        `--max-old-space-size=${ANALYSIS_OLD_SPACE_LIMIT_MIB}`,
      ],
      stdio: ["ignore", "ignore", "ignore"],
      serviceName: "3ziz Static Analysis Worker",
      allowLoadingUnsignedLibraries: false,
      respondToAuthRequestsFromMainProcess: false,
    });
    let settled = false;

    const timeout = setTimeout(() => {
      finish(
        new Error(
          `Static analysis exceeded the ${ANALYSIS_TIMEOUT_MS / 1_000}-second limit.`,
        ),
      );
    }, ANALYSIS_TIMEOUT_MS);
    timeout.unref();

    const memoryMonitor = setInterval(() => {
      const pid = child.pid;
      if (pid === undefined) {
        return;
      }
      const metric = app
        .getAppMetrics()
        .find((candidate) => candidate.pid === pid);
      const workingSetBytes =
        (metric?.memory.workingSetSize ?? 0) * 1024;
      if (workingSetBytes > ANALYSIS_MEMORY_LIMIT_BYTES) {
        finish(
          new Error(
            `Static analysis exceeded the ${ANALYSIS_MEMORY_LIMIT_MIB} MiB worker memory limit.`,
          ),
        );
      }
    }, 250);
    memoryMonitor.unref();

    const finish = (
      error: Error | null,
      result?: PersistedBrokerAnalysisResult,
    ): void => {
      if (settled) {
        return;
      }
      settled = true;
      clearTimeout(timeout);
      clearInterval(memoryMonitor);
      options.signal.removeEventListener("abort", onAbort);
      child.kill();
      if (error !== null) {
        rejectPromise(error);
      } else if (result !== undefined) {
        resolvePromise(result);
      } else {
        rejectPromise(new Error("Static analysis returned no result."));
      }
    };

    const onAbort = (): void => {
      finish(
        options.signal.reason instanceof Error
          ? options.signal.reason
          : new Error("Analysis cancelled."),
      );
    };
    options.signal.addEventListener("abort", onAbort, { once: true });
    if (options.signal.aborted) onAbort();

    child.once("spawn", () => {
      if (settled) return;
      sendProgress({
        jobId: options.requestId,
        stage: "fingerprinting",
        status: "active",
        percent: 18,
        message: "Classifying input and selecting a static plugin…",
        inputPath: options.inputPath,
      });
      child.postMessage({
        type: "analyze-file",
        requestId: options.requestId,
        inputPath: options.inputPath,
        jobsRoot: options.jobsRoot,
      });
    });
    child.on("message", (message: unknown) => {
      let response: AnalyzeWorkerResponse;
      try {
        response = validateWorkerResponse(
          message,
          options.requestId,
        );
      } catch (error) {
        finish(
          error instanceof Error
            ? error
            : new Error("Static worker returned malformed data."),
        );
        return;
      }
      if (response.type === "analysis-error") {
        finish(new Error(response.error));
      } else {
        finish(null, response.result);
      }
    });
    child.once("exit", (code) => {
      if (!settled) {
        finish(
          new Error(
            `Static analysis worker exited before responding (code ${code}).`,
          ),
        );
      }
    });
    child.once("error", (type, location) => {
      finish(
        new Error(
          `Static analysis worker failed (${type} at ${location}).`,
        ),
      );
    });
  });
}

function validateWorkerResponse(
  value: unknown,
  expectedRequestId: string,
): AnalyzeWorkerResponse {
  const record = asRecord(value);
  if (
    record === null ||
    record.requestId !== expectedRequestId ||
    (record.type !== "analysis-complete" &&
      record.type !== "analysis-error")
  ) {
    throw new Error("Static worker returned a malformed response.");
  }
  if (record.type === "analysis-error") {
    if (
      typeof record.error !== "string" ||
      record.error.length === 0 ||
      record.error.length > 4_096
    ) {
      throw new Error("Static worker returned a malformed error.");
    }
    return {
      type: "analysis-error",
      requestId: expectedRequestId,
      error: record.error,
    };
  }
  const result = asRecord(record.result);
  const analysis = asRecord(result?.analysis);
  if (
    result === null ||
    analysis === null ||
    asRecord(analysis.report) === null ||
    asRecord(result.writtenJob) === null
  ) {
    throw new Error("Static worker returned a malformed analysis result.");
  }
  return {
    type: "analysis-complete",
    requestId: expectedRequestId,
    result: record.result as PersistedBrokerAnalysisResult,
  };
}

function assertBrokerResultInvariant(
  result: PersistedBrokerAnalysisResult,
  jobsRoot: string,
  expectedJobId: string,
): void {
  const jobId = validateJobId(result.analysis.report.jobId);
  if (
    jobId !== expectedJobId ||
    result.writtenJob.manifest.jobId !== expectedJobId ||
    result.writtenJob.manifest.input.sha256 !==
      result.analysis.report.input.sha256 ||
    !isPathWithin(jobsRoot, result.writtenJob.jobDirectory) ||
    !isPathWithin(
      result.writtenJob.jobDirectory,
      result.writtenJob.manifestPath,
    ) ||
    result.writtenJob.manifest.artifacts.length > 64
  ) {
    throw new Error("Static worker returned inconsistent job metadata.");
  }
  let totalBytes = 0;
  const fileNames = new Set<string>(["manifest.json"]);
  for (const artifact of result.writtenJob.manifest.artifacts) {
    if (
      !isSafeSingleFileName(artifact.fileName) ||
      !Number.isSafeInteger(artifact.byteLength) ||
      artifact.byteLength < 0 ||
      !/^[0-9a-f]{64}$/i.test(artifact.sha256) ||
      fileNames.has(artifact.fileName)
    ) {
      throw new Error("Static worker returned an invalid artifact manifest.");
    }
    fileNames.add(artifact.fileName);
    totalBytes += artifact.byteLength;
    if (totalBytes > MAX_EXPORT_BYTES) {
      throw new Error("Static worker artifact manifest exceeds output limits.");
    }
  }
}

async function rememberCompletedJob(
  job: CompletedJob,
  jobsRoot: string,
): Promise<void> {
  const evicted: CompletedJob[] = [];
  const replaced = completedJobs.get(job.id);
  if (
    replaced !== undefined &&
    replaced.storageRoot !== job.storageRoot
  ) {
    evicted.push(replaced);
  }
  completedJobs.delete(job.id);
  completedJobs.set(job.id, job);
  while (completedJobs.size > MAX_COMPLETED_JOBS) {
    const oldestId = completedJobs.keys().next().value as
      | string
      | undefined;
    if (oldestId === undefined) {
      break;
    }
    const oldest = completedJobs.get(oldestId);
    completedJobs.delete(oldestId);
    if (oldest !== undefined) {
      evicted.push(oldest);
    }
  }
  for (const stale of evicted) {
    await removeManagedJobStorage(
      jobsRoot,
      stale.storageRoot,
    ).catch(() => undefined);
  }
}

async function createUniqueExportDirectory(
  root: string,
  baseName: string,
): Promise<string> {
  for (let suffix = 1; suffix <= 100; suffix += 1) {
    const name = suffix === 1 ? baseName : `${baseName}-${suffix}`;
    const candidate = resolve(root, name);
    if (!isPathWithin(root, candidate)) {
      throw new Error("Generated export directory escaped its selected root.");
    }
    try {
      await mkdir(candidate, { recursive: false });
      return candidate;
    } catch (error) {
      if (
        error !== null &&
        typeof error === "object" &&
        "code" in error &&
        error.code === "EEXIST"
      ) {
        continue;
      }
      throw error;
    }
  }
  throw new Error("Could not reserve a unique non-overwriting export directory.");
}

async function copyCompletedJob(
  completed: CompletedJob,
  exportDirectory: string,
): Promise<void> {
  const sourceRoot = await realpath(completed.result.jobDirectory);
  const realStorageRoot = await realpath(completed.storageRoot);
  if (!isPathWithin(realStorageRoot, sourceRoot)) {
    throw new Error(
      "Completed job resolves outside its managed storage directory.",
    );
  }
  let totalBytes = 0;
  const fileNames = new Set<string>(["manifest.json"]);
  for (const artifact of completed.result.manifest.artifacts) {
    if (fileNames.has(artifact.fileName)) {
      throw new Error("Artifact manifest contains a duplicate output name.");
    }
    fileNames.add(artifact.fileName);
    const source = resolveArtifactFilePath(
      completed.result.jobDirectory,
      artifact.fileName,
    );
    if (source === null) {
      throw new Error("Artifact manifest contains an unsafe source path.");
    }
    const realSource = await realpath(source);
    if (!isPathWithin(sourceRoot, realSource)) {
      throw new Error("Artifact source resolves outside its job directory.");
    }
    const metadata = await stat(realSource);
    if (
      !metadata.isFile() ||
      metadata.size !== artifact.byteLength
    ) {
      throw new Error("Artifact changed after job completion.");
    }
    totalBytes += metadata.size;
    if (totalBytes > MAX_EXPORT_BYTES) {
      throw new Error("Export exceeds the bounded artifact size limit.");
    }
    const bytes = await readCappedFile(
      realSource,
      artifact.byteLength,
      MAX_EXPORT_BYTES,
    );
    if (!verifyArtifactSha256(bytes, artifact.sha256)) {
      throw new Error(
        `Artifact ${artifact.fileName} failed SHA-256 verification.`,
      );
    }
    await writeFile(join(exportDirectory, artifact.fileName), bytes, {
      flag: "wx",
    });
  }

  const realManifest = await realpath(completed.result.manifestPath);
  if (!isPathWithin(sourceRoot, realManifest)) {
    throw new Error("Job manifest resolves outside its job directory.");
  }
  const manifestMetadata = await stat(realManifest);
  if (!manifestMetadata.isFile() || manifestMetadata.size > 1024 * 1024) {
    throw new Error("Job manifest is not a bounded regular file.");
  }
  const manifestBytes = await readCappedFile(
    realManifest,
    manifestMetadata.size,
    1024 * 1024,
  );
  const canonicalManifest = Buffer.from(
    `${JSON.stringify(completed.result.manifest, null, 2)}\n`,
    "utf8",
  );
  if (!Buffer.from(manifestBytes).equals(canonicalManifest)) {
    throw new Error(
      "Job manifest bytes do not match the validated in-memory manifest.",
    );
  }
  await writeFile(join(exportDirectory, "manifest.json"), manifestBytes, {
    flag: "wx",
  });
}

function asRecord(value: unknown): Record<string, unknown> | null {
  return value !== null && typeof value === "object"
    ? (value as Record<string, unknown>)
    : null;
}
