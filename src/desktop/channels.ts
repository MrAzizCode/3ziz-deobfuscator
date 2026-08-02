export const DESKTOP_IPC = Object.freeze({
  chooseFile: "3ziz:choose-file",
  authorizeDroppedFile: "3ziz:authorize-dropped-file",
  analyzeFile: "3ziz:analyze-file",
  exportJob: "3ziz:export-job",
  cancelJob: "3ziz:cancel-job",
  progress: "3ziz:analysis-progress",
} as const);

export interface DesktopProgressEvent {
  readonly jobId?: string;
  readonly stage?: string;
  readonly status?: string;
  readonly percent?: number;
  readonly message?: string;
  readonly inputPath?: string;
}
