import {
  contextBridge,
  ipcRenderer,
  webUtils,
} from "electron";

// Sandboxed Electron preloads cannot load sibling CommonJS modules. Keep this
// file's runtime dependency graph limited to Electron's built-in preload API.
const DESKTOP_IPC = Object.freeze({
  chooseFile: "3ziz:choose-file",
  authorizeDroppedFile: "3ziz:authorize-dropped-file",
  analyzeFile: "3ziz:analyze-file",
  exportJob: "3ziz:export-job",
  cancelJob: "3ziz:cancel-job",
  progress: "3ziz:analysis-progress",
} as const);

interface DesktopProgressEvent {
  readonly jobId?: string;
  readonly stage?: string;
  readonly status?: string;
  readonly percent?: number;
  readonly message?: string;
  readonly inputPath?: string;
}

type CancelJobOutcome =
  | { readonly outcome: "cancelled" }
  | { readonly outcome: "already-complete" };

type LocalFile = Parameters<typeof webUtils.getPathForFile>[0];

interface DesktopBridge {
  chooseFile(): Promise<unknown>;
  getPathForFile(file: LocalFile): string;
  analyzeFile(path: string): Promise<unknown>;
  exportJob(jobId: string): Promise<unknown>;
  cancelJob(jobId: string): Promise<CancelJobOutcome>;
  onProgress(
    callback: (event: DesktopProgressEvent) => void,
  ): () => void;
}

function sanitizeProgressEvent(value: unknown): DesktopProgressEvent | null {
  if (value === null || typeof value !== "object") {
    return null;
  }
  const record = value as Record<string, unknown>;
  const event: {
    jobId?: string;
    stage?: string;
    status?: string;
    percent?: number;
    message?: string;
    inputPath?: string;
  } = {};
  if (typeof record.jobId === "string") event.jobId = record.jobId;
  if (typeof record.stage === "string") event.stage = record.stage;
  if (typeof record.status === "string") event.status = record.status;
  if (
    typeof record.percent === "number" &&
    Number.isFinite(record.percent)
  ) {
    event.percent = Math.min(100, Math.max(0, record.percent));
  }
  if (typeof record.message === "string") {
    event.message = record.message.slice(0, 2_048);
  }
  if (typeof record.inputPath === "string") {
    event.inputPath = record.inputPath.slice(0, 32_767);
  }
  return event;
}

function sanitizeCancelJobOutcome(value: unknown): CancelJobOutcome {
  if (value === null || typeof value !== "object") {
    throw new Error("Desktop returned an invalid cancellation outcome.");
  }
  const outcome = (value as Record<string, unknown>).outcome;
  if (outcome === "cancelled" || outcome === "already-complete") {
    return { outcome };
  }
  throw new Error("Desktop returned an invalid cancellation outcome.");
}

const bridge: DesktopBridge = Object.freeze({
  chooseFile: () => ipcRenderer.invoke(DESKTOP_IPC.chooseFile),
  getPathForFile: (file: LocalFile) => {
    const path = webUtils.getPathForFile(file);
    if (path.length > 0) {
      ipcRenderer.send(DESKTOP_IPC.authorizeDroppedFile, path);
    }
    return path;
  },
  analyzeFile: (path: string) =>
    ipcRenderer.invoke(DESKTOP_IPC.analyzeFile, path),
  exportJob: (jobId: string) =>
    ipcRenderer.invoke(DESKTOP_IPC.exportJob, jobId),
  cancelJob: async (jobId: string) =>
    sanitizeCancelJobOutcome(
      await ipcRenderer.invoke(DESKTOP_IPC.cancelJob, jobId),
    ),
  onProgress: (
    callback: (event: DesktopProgressEvent) => void,
  ) => {
    if (typeof callback !== "function") {
      throw new TypeError("Progress callback must be a function.");
    }
    const listener = (_event: Electron.IpcRendererEvent, payload: unknown) => {
      const progress = sanitizeProgressEvent(payload);
      if (progress !== null) {
        callback(progress);
      }
    };
    ipcRenderer.on(DESKTOP_IPC.progress, listener);
    return () => {
      ipcRenderer.removeListener(DESKTOP_IPC.progress, listener);
    };
  },
});

contextBridge.exposeInMainWorld("deobfuscator", bridge);
