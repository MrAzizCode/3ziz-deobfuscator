import { useEffect, useMemo, useRef, useState } from "react";

import type {
  AnalysisProgressEvent,
  AnalysisStage,
  Diagnostic,
  DiagnosticSeverity,
  ExportResult,
  ValidationCheck,
} from "./api";
import {
  cancellationAllowsCompletedResult,
  shouldAcceptProgressEvent,
  type CancelJobOutcome,
} from "./api";
import { CodeSurface, DiffSurface, EmptyArtifact } from "./components/CodeSurface";
import { Icon, type IconName } from "./components/Icon";
import {
  STAGE_DEFINITIONS,
  createSampleJob,
  fileNameFromPath,
  formatBytes,
  formatDuration,
  normalizeAnalysisResult,
  type JobViewModel,
  type ViewStatus,
} from "./model";
import { canAutoCompletePriorStage } from "./progress";

type AppPhase = "idle" | "analyzing" | "result" | "error" | "cancelled";
type TabId =
  | "original"
  | "readable"
  | "records"
  | "audit"
  | "behavior"
  | "payload"
  | "validation"
  | "warnings";

interface ProgressState {
  jobId?: string | undefined;
  filePath?: string | undefined;
  percent: number;
  message: string;
  stages: AnalysisStage[];
}

interface PendingCancellation {
  readonly generation: number;
  readonly promise: Promise<CancelJobOutcome>;
}

interface TabDefinition {
  id: TabId;
  label: string;
  icon: IconName;
  description: string;
}

const TABS: TabDefinition[] = [
  {
    id: "original",
    label: "Original",
    icon: "file",
    description: "Immutable input source",
  },
  {
    id: "readable",
    label: "Readable",
    icon: "code",
    description: "Conservative structured reconstruction",
  },
  {
    id: "records",
    label: "Decoded Records",
    icon: "terminal",
    description: "Bounded instruction records with structural provenance",
  },
  {
    id: "audit",
    label: "Exact Audit",
    icon: "terminal",
    description: "Evidence-first control flow and provenance",
  },
  {
    id: "behavior",
    label: "Behavior Report",
    icon: "report",
    description: "Capabilities, reachability, and unknowns",
  },
  {
    id: "payload",
    label: "Payload Map",
    icon: "terminal",
    description: "Inert binary structure, entropy, and recoverable strings",
  },
  {
    id: "validation",
    label: "Validation",
    icon: "validation",
    description: "Structural and preservation checks",
  },
  {
    id: "warnings",
    label: "Warnings",
    icon: "warning",
    description: "Unresolved and low-confidence findings",
  },
];

const STATUS_META: Record<
  ViewStatus,
  {
    label: string;
    tone: "success" | "warning" | "danger" | "neutral" | "sample";
    title: string;
    description: string;
  }
> = {
  verified: {
    label: "Verified",
    tone: "success",
    title: "Static analysis verified",
    description:
      "The emitted artifacts passed the available static structural, integrity, and preservation checks.",
  },
  partial: {
    label: "Partial analysis",
    tone: "warning",
    title: "Analysis completed with warnings",
    description:
      "Useful evidence was produced, but unsupported, unresolved, or low-confidence areas remain.",
  },
  unsupported: {
    label: "Unsupported",
    tone: "neutral",
    title: "No supported recovery path",
    description:
      "The app preserved the input and diagnostics without inventing a reconstruction.",
  },
  failed: {
    label: "Failed validation",
    tone: "danger",
    title: "Validation did not pass",
    description:
      "Partial evidence may be available, but the readable output is not presented as verified.",
  },
  cancelled: {
    label: "Cancelled",
    tone: "neutral",
    title: "Analysis cancelled",
    description: "Worker activity was stopped and no success claim was made.",
  },
  sample: {
    label: "Sample workspace",
    tone: "sample",
    title: "Built-in preview",
    description:
      "This synthetic example demonstrates the interface. No local file was analyzed.",
  },
};

function canonicalStageId(value?: string): string | undefined {
  if (!value) {
    return undefined;
  }

  const stage = value.toLowerCase().replace(/[\s_-]+/g, "");

  if (
    stage.includes("queue") ||
    stage.includes("import") ||
    stage.includes("ingest") ||
    stage.includes("hash")
  ) {
    return "ingesting";
  }

  if (
    stage.includes("finger") ||
    stage.includes("detect") ||
    stage.includes("parse")
  ) {
    return "fingerprinting";
  }

  if (
    stage.includes("extract") ||
    stage.includes("bytecode") ||
    stage.includes("normalize")
  ) {
    return "extracting";
  }

  if (
    stage.includes("lift") ||
    stage.includes("decomp") ||
    stage.includes("reconstruct") ||
    stage.includes("ir")
  ) {
    return "reconstructing";
  }

  if (
    stage.includes("simpl") ||
    stage.includes("clean") ||
    stage.includes("transform") ||
    stage.includes("name")
  ) {
    return "simplifying";
  }

  if (stage.includes("valid") || stage.includes("verify")) {
    return "validating";
  }

  if (
    stage.includes("emit") ||
    stage.includes("report") ||
    stage.includes("complete")
  ) {
    return "emitting";
  }

  return value;
}

function initialStages(): AnalysisStage[] {
  return STAGE_DEFINITIONS.map((stage, index) => ({
    id: stage.id,
    label: stage.label,
    status: index === 0 ? "active" : "queued",
  }));
}

function progressStageStatus(
  value?: string,
): NonNullable<AnalysisStage["status"]> {
  const status = value?.toLowerCase();

  if (
    status === "completed" ||
    status === "complete" ||
    status === "success" ||
    status === "verified"
  ) {
    return "complete";
  }

  if (status === "warning" || status === "partial") {
    return "warning";
  }

  if (status === "failed" || status === "error") {
    return "error";
  }

  if (status === "skipped" || status === "unsupported") {
    return "skipped";
  }

  return "active";
}

function applyProgressToStages(
  current: AnalysisStage[],
  event: AnalysisProgressEvent,
): AnalysisStage[] {
  const id = canonicalStageId(event.stage);
  if (!id) {
    return current;
  }

  const targetIndex = STAGE_DEFINITIONS.findIndex((stage) => stage.id === id);
  if (targetIndex < 0) {
    return current;
  }

  const targetStatus = progressStageStatus(event.status);

  return current.map((stage, index) => {
    if (
      index < targetIndex &&
      canAutoCompletePriorStage(stage.status)
    ) {
      return { ...stage, status: "complete" };
    }

    if (index === targetIndex) {
      return {
        ...stage,
        status: targetStatus,
        ...(event.message ? { detail: event.message } : {}),
      };
    }

    return stage;
  });
}

function countLines(value?: string): number | undefined {
  if (!value) {
    return undefined;
  }

  return value.split(/\r?\n/).length;
}

function formatCount(value?: number): string {
  return value === undefined || !Number.isFinite(value)
    ? "—"
    : new Intl.NumberFormat().format(value);
}

function formatCoverageRatio(value: number): string {
  const percent = Math.min(100, Math.max(0, value <= 1 ? value * 100 : value));
  return `${percent.toFixed(percent >= 99.95 || Number.isInteger(percent) ? 0 : 1)}% mapped`;
}

function getExportPath(result: ExportResult): string | undefined {
  if (typeof result === "string") {
    return result;
  }

  return result?.path;
}

function Header({
  phase,
  canExport,
  isSample,
  exportBusy,
  pickerBusy,
  onChoose,
  onExport,
}: {
  phase: AppPhase;
  canExport: boolean;
  isSample: boolean;
  exportBusy: boolean;
  pickerBusy: boolean;
  onChoose: () => void;
  onExport: () => void;
}) {
  return (
    <header className="app-header">
      <div className="brand" aria-label="3ziz Deobfuscator">
        <span className="brand__mark" aria-hidden="true">
          <span>3</span>
          <span>Z</span>
        </span>
        <span className="brand__copy">
          <strong>3ziz Deobfuscator</strong>
          <small>Static Lua recovery</small>
        </span>
      </div>

      <div className="header__actions">
        <span className="safety-badge">
          <Icon name="shield" size={15} />
          Static analysis only
        </span>

        {phase !== "idle" && (
          <button
            className="button button--quiet header__compact-action"
            disabled={pickerBusy || phase === "analyzing"}
            onClick={onChoose}
            type="button"
          >
            <Icon name="folder" size={16} />
            {pickerBusy ? "Opening…" : "Choose another"}
          </button>
        )}

        {(phase === "result" || canExport) && (
          <button
            className="button button--primary"
            disabled={!canExport || exportBusy || isSample}
            onClick={onExport}
            title={
              isSample ? "Sample results cannot be exported" : "Export result bundle"
            }
            type="button"
          >
            <Icon name="download" size={16} />
            {exportBusy ? "Exporting…" : "Export bundle"}
          </button>
        )}
      </div>
    </header>
  );
}

function AuthorizedUseNote({ compact = false }: { compact?: boolean }) {
  return (
    <div className={compact ? "authorized-note authorized-note--compact" : "authorized-note"}>
      <span className="authorized-note__icon">
        <Icon name="lock" size={compact ? 15 : 18} />
      </span>
      <p>
        <strong>Authorized analysis only.</strong>{" "}
        {compact
          ? "Use this app only with code you own or may inspect."
          : "Continue only with scripts you own or are explicitly authorized to inspect. Original files are never overwritten."}
      </p>
    </div>
  );
}

function EmptyState({
  dropActive,
  pickerBusy,
  bridgeAvailable,
  notice,
  onChoose,
  onSample,
  onDragEnter,
  onDragLeave,
  onDragOver,
  onDrop,
}: {
  dropActive: boolean;
  pickerBusy: boolean;
  bridgeAvailable: boolean;
  notice?: string | undefined;
  onChoose: () => void;
  onSample: () => void;
  onDragEnter: React.DragEventHandler<HTMLDivElement>;
  onDragLeave: React.DragEventHandler<HTMLDivElement>;
  onDragOver: React.DragEventHandler<HTMLDivElement>;
  onDrop: React.DragEventHandler<HTMLDivElement>;
}) {
  const handleKeyboard = (event: React.KeyboardEvent<HTMLDivElement>) => {
    if (event.key === "Enter" || event.key === " ") {
      event.preventDefault();
      onChoose();
    }
  };

  return (
    <main className="empty-page">
      <section className="empty-hero">
        <h1>3ziz Deobfuscator</h1>
        <p className="empty-hero__intro">
          Local, static Lua and Luau analysis. Nothing you submit is executed.
        </p>

        <div
          aria-label="Drop a Lua or Luau file, or press Enter to choose one"
          className={`drop-zone${dropActive ? " drop-zone--active" : ""}`}
          onDragEnter={onDragEnter}
          onDragLeave={onDragLeave}
          onDragOver={onDragOver}
          onDrop={onDrop}
          onKeyDown={handleKeyboard}
          role="button"
          tabIndex={0}
        >
          <span className="drop-zone__icon">
            <Icon name="upload" size={24} />
          </span>
          <div className="drop-zone__copy">
            <h2>{dropActive ? "Release to analyze" : "Drop a file"}</h2>
            <p>.lua, .luau, .luac, .txt — up to 10 MiB</p>
          </div>
          <button
            className="button button--primary button--large"
            disabled={pickerBusy}
            onClick={(event) => {
              event.stopPropagation();
              onChoose();
            }}
            type="button"
          >
            <Icon name="folder" size={18} />
            {pickerBusy ? "Opening picker…" : "Choose a file"}
          </button>
        </div>

        {notice && (
          <div className="inline-notice inline-notice--warning" role="status">
            <Icon name="warning" size={17} />
            <span>{notice}</span>
          </div>
        )}

        {!bridgeAvailable && !notice && (
          <div className="inline-notice" role="status">
            <Icon name="info" size={17} />
            <span>
              Desktop controls are unavailable in this browser preview. You can
              still open the sample workspace.
            </span>
          </div>
        )}

        <AuthorizedUseNote />

        <button className="sample-link" onClick={onSample} type="button">
          Open a sample result
          <Icon name="arrow-right" size={15} />
        </button>
      </section>
    </main>
  );
}

function StageTimeline({
  stages,
  compact = false,
}: {
  stages: AnalysisStage[];
  compact?: boolean;
}) {
  const normalizedStages = STAGE_DEFINITIONS.map((definition) => {
    const incoming = stages.find(
      (stage) => canonicalStageId(stage.id) === definition.id,
    );

    return {
      ...definition,
      ...incoming,
      label: incoming?.label ?? definition.label,
      status: incoming?.status ?? "queued",
    };
  });

  return (
    <ol className={`stage-timeline${compact ? " stage-timeline--compact" : ""}`}>
      {normalizedStages.map((stage) => (
        <li
          className={`stage stage--${stage.status ?? "queued"}`}
          key={stage.id}
        >
          <span className="stage__rail" aria-hidden="true">
            <span className="stage__dot">
              {stage.status === "complete" && <Icon name="check" size={11} />}
              {stage.status === "error" && <span>!</span>}
              {stage.status === "warning" && <span>!</span>}
            </span>
          </span>
          <div className="stage__copy">
            <strong>{stage.label}</strong>
            {!compact && (
              <small>{stage.detail ?? stage.description}</small>
            )}
          </div>
          {stage.status === "active" && (
            <span className="stage__working">Working</span>
          )}
          {stage.status === "skipped" && (
            <span className="stage__skipped">Skipped</span>
          )}
        </li>
      ))}
    </ol>
  );
}

function AnalysisLoading({
  progress,
  canCancel,
  cancelling,
  onCancel,
}: {
  progress: ProgressState;
  canCancel: boolean;
  cancelling: boolean;
  onCancel: () => void;
}) {
  return (
    <main className="loading-page">
      <section className="loading-card" aria-live="polite">
        <div className="loading-card__top">
          <div>
            <h1>{fileNameFromPath(progress.filePath)}</h1>
            <p>{progress.message}</p>
          </div>
        </div>

        <div
          aria-label={`Analysis ${Math.round(progress.percent)} percent complete`}
          aria-valuemax={100}
          aria-valuemin={0}
          aria-valuenow={Math.round(progress.percent)}
          className="progress-track"
          role="progressbar"
        >
          <span style={{ width: `${progress.percent}%` }} />
        </div>

        <div className="loading-card__content">
          <StageTimeline stages={progress.stages} />
          <aside className="loading-safety">
            <span className="loading-safety__icon">
              <Icon name="shield" size={21} />
            </span>
            <div>
              <strong>Static-only policy is active</strong>
              <p>
                Only the app's restricted analysis worker runs. Submitted Lua is
                treated as untrusted data and is never launched.
              </p>
            </div>
          </aside>
        </div>

        <div className="loading-card__footer">
          <span>Cancellation stays available until the job completes.</span>
          <button
            className="button button--danger-quiet"
            disabled={!canCancel || cancelling}
            onClick={onCancel}
            type="button"
          >
            <Icon name="cancel" size={16} />
            {cancelling
              ? "Cancelling…"
              : canCancel
                ? "Cancel analysis"
                : "Preparing worker…"}
          </button>
        </div>
      </section>
    </main>
  );
}

function FailureState({
  cancelled = false,
  message,
  onChoose,
  onReset,
}: {
  cancelled?: boolean;
  message?: string | undefined;
  onChoose: () => void;
  onReset: () => void;
}) {
  return (
    <main className="failure-page">
      <section className={`failure-card${cancelled ? " failure-card--cancelled" : ""}`}>
        <span className="failure-card__icon">
          <Icon name={cancelled ? "cancel" : "alert"} size={26} />
        </span>
        <span className="section-kicker">
          {cancelled ? "Stopped safely" : "Analysis could not continue"}
        </span>
        <h1>{cancelled ? "The job was cancelled" : "No result was claimed"}</h1>
        <p>
          {message ??
            (cancelled
              ? "The analysis worker was asked to stop. Choose another file whenever you are ready."
              : "The app preserved the failure as a diagnostic and did not fabricate readable source.")}
        </p>
        <div className="failure-card__actions">
          <button className="button button--primary" onClick={onChoose} type="button">
            <Icon name="folder" size={17} />
            Choose another file
          </button>
          <button className="button button--quiet" onClick={onReset} type="button">
            Return home
          </button>
        </div>
        <AuthorizedUseNote compact />
      </section>
    </main>
  );
}

function StatusPill({ status }: { status: ViewStatus }) {
  const meta = STATUS_META[status];
  return (
    <span className={`status-pill status-pill--${meta.tone}`}>
      <span />
      {meta.label}
    </span>
  );
}

function SummaryCard({
  icon,
  label,
  value,
  detail,
  title,
  tone,
}: {
  icon: IconName;
  label: string;
  value: string;
  detail: string;
  title?: string | undefined;
  tone?: "accent" | "success" | "warning" | undefined;
}) {
  return (
    <article
      className={`summary-card${tone ? ` summary-card--${tone}` : ""}`}
      title={title}
    >
      <span className="summary-card__icon">
        <Icon name={icon} size={18} />
      </span>
      <div>
        <span>{label}</span>
        <strong>{value}</strong>
        <small>{detail}</small>
      </div>
    </article>
  );
}

function DetectionPanel({ job }: { job: JobViewModel }) {
  const confidence = job.detection.confidence;
  const evidence = job.detection.evidence ?? [];
  const plugin =
    job.detection.pluginName ??
    job.detection.pluginId ??
    (job.status === "unsupported" ? "No plugin selected" : "Detection unavailable");

  return (
    <section className="side-card detection-card">
      <div className="side-card__heading">
        <div>
          <span className="section-kicker">Detection</span>
          <h2>{plugin}</h2>
        </div>
        <span className="confidence-value">
          {confidence === undefined ? "Not scored" : `${Math.round(confidence * 100)}%`}
        </span>
      </div>

      <div
        aria-label={
          confidence === undefined
            ? "Detection confidence unavailable"
            : `Detection confidence ${Math.round(confidence * 100)} percent`
        }
        aria-valuemax={100}
        aria-valuemin={0}
        aria-valuenow={
          confidence === undefined ? undefined : Math.round(confidence * 100)
        }
        className="confidence-track"
        role="meter"
      >
        <span style={{ width: `${(confidence ?? 0) * 100}%` }} />
      </div>

      <div className="evidence-list">
        {evidence.length > 0 ? (
          evidence.map((item, index) => (
            <div className="evidence-item" key={`${item.rule ?? item.label}-${index}`}>
              <span
                className={`evidence-item__state${
                  item.matched === false ? " evidence-item__state--miss" : ""
                }`}
              >
                <Icon
                  name={item.matched === false ? "cancel" : "check"}
                  size={12}
                />
              </span>
              <div>
                <strong>{item.label ?? item.rule ?? "Detection signal"}</strong>
                {item.detail && <p>{item.detail}</p>}
              </div>
              {item.weight !== undefined && (
                <span className="evidence-item__weight">
                  +{Math.round(item.weight * (item.weight <= 1 ? 100 : 1))}
                </span>
              )}
            </div>
          ))
        ) : (
          <div className="evidence-empty">
            <Icon name="info" size={16} />
            <span>No detection evidence was returned for this job.</span>
          </div>
        )}
      </div>
    </section>
  );
}

function JobTimelinePanel({ stages }: { stages: AnalysisStage[] }) {
  return (
    <section className="side-card timeline-card">
      <div className="side-card__heading">
        <div>
          <span className="section-kicker">Pipeline</span>
          <h2>Job stages</h2>
        </div>
      </div>
      <StageTimeline compact stages={stages} />
    </section>
  );
}

function ValidationView({
  checks,
  report,
}: {
  checks: ValidationCheck[];
  report?: string | undefined;
}) {
  if (checks.length === 0 && !report) {
    return (
      <EmptyArtifact
        title="Validation was not completed"
        detail="No validation checks or report were emitted for this job."
      />
    );
  }

  return (
    <div className="validation-view">
      {checks.length > 0 && (
        <div className="validation-grid">
          {checks.map((check, index) => (
            <article
              className={`validation-check validation-check--${check.status}`}
              key={check.id ?? `${check.label}-${index}`}
            >
              <span className="validation-check__icon">
                <Icon
                  name={
                    check.status === "passed"
                      ? "check"
                      : check.status === "failed"
                        ? "cancel"
                        : check.status === "warning"
                          ? "warning"
                          : "info"
                  }
                  size={17}
                />
              </span>
              <div>
                <strong>{check.label}</strong>
                <p>{check.detail ?? "No additional detail was emitted."}</p>
              </div>
              <span className="validation-check__status">
                {check.status.replace("-", " ")}
              </span>
            </article>
          ))}
        </div>
      )}

      {report && (
        <section className="validation-report">
          <div className="validation-report__heading">
            <Icon name="terminal" size={16} />
            Machine-readable stage summary
          </div>
          <pre>{report}</pre>
        </section>
      )}
    </div>
  );
}

function DiagnosticItem({ diagnostic }: { diagnostic: Diagnostic }) {
  const severity: DiagnosticSeverity = diagnostic.severity ?? "info";
  return (
    <article className={`diagnostic diagnostic--${severity}`}>
      <span className="diagnostic__icon">
        <Icon
          name={
            severity === "error"
              ? "alert"
              : severity === "warning"
                ? "warning"
                : "info"
          }
          size={17}
        />
      </span>
      <div className="diagnostic__body">
        <div className="diagnostic__meta">
          <code>{diagnostic.code ?? severity.toUpperCase()}</code>
          {diagnostic.stage && <span>{diagnostic.stage}</span>}
          {diagnostic.location && <span>{diagnostic.location}</span>}
        </div>
        <p>{diagnostic.message}</p>
        {diagnostic.evidence && diagnostic.evidence.length > 0 && (
          <ul>
            {diagnostic.evidence.map((evidence, index) => (
              <li key={`${evidence}-${index}`}>{evidence}</li>
            ))}
          </ul>
        )}
        {diagnostic.suggestedAction && (
          <small>
            <strong>Suggested action:</strong> {diagnostic.suggestedAction}
          </small>
        )}
      </div>
    </article>
  );
}

function WarningsView({
  diagnostics,
  warningsText,
}: {
  diagnostics: Diagnostic[];
  warningsText?: string | undefined;
}) {
  const warnings = diagnostics.filter(
    (diagnostic) =>
      diagnostic.severity === "warning" || diagnostic.severity === "error",
  );

  if (warnings.length === 0 && !warningsText?.trim()) {
    return (
      <div className="warnings-clear">
        <span>
          <Icon name="check" size={23} />
        </span>
        <div>
          <h3>No warnings were emitted</h3>
          <p>
            Review the Validation tab before relying on a reconstructed result.
          </p>
        </div>
      </div>
    );
  }

  return (
    <div className="warnings-view">
      <div className="diagnostic-list">
        {warnings.map((diagnostic, index) => (
          <DiagnosticItem
            diagnostic={diagnostic}
            key={`${diagnostic.code}-${index}`}
          />
        ))}
      </div>
      {warningsText?.trim() && (
        <section className="warnings-raw">
          <div>
            <Icon name="report" size={16} />
            warnings.md
          </div>
          <pre>{warningsText}</pre>
        </section>
      )}
    </div>
  );
}

function DiagnosticsPanel({ diagnostics }: { diagnostics: Diagnostic[] }) {
  const [expanded, setExpanded] = useState(false);
  const errors = diagnostics.filter(
    (diagnostic) => diagnostic.severity === "error",
  ).length;
  const warnings = diagnostics.filter(
    (diagnostic) => diagnostic.severity === "warning",
  ).length;

  return (
    <section className={`diagnostics-panel${expanded ? " diagnostics-panel--open" : ""}`}>
      <button
        aria-expanded={expanded}
        className="diagnostics-panel__toggle"
        onClick={() => setExpanded((current) => !current)}
        type="button"
      >
        <span className="diagnostics-panel__lead">
          <Icon name="terminal" size={17} />
          <strong>Diagnostics</strong>
          <span>{diagnostics.length}</span>
        </span>
        <span className="diagnostics-panel__counts">
          {errors > 0 && <span className="count count--error">{errors} errors</span>}
          {warnings > 0 && (
            <span className="count count--warning">{warnings} warnings</span>
          )}
          {errors === 0 && warnings === 0 && (
            <span className="count count--clear">No blocking findings</span>
          )}
          <Icon className="diagnostics-panel__chevron" name="chevron" size={16} />
        </span>
      </button>

      {expanded && (
        <div className="diagnostics-panel__content">
          {diagnostics.length > 0 ? (
            diagnostics.map((diagnostic, index) => (
              <DiagnosticItem
                diagnostic={diagnostic}
                key={`${diagnostic.code}-${index}`}
              />
            ))
          ) : (
            <div className="diagnostics-empty">
              No diagnostics were emitted by this analysis.
            </div>
          )}
        </div>
      )}
    </section>
  );
}

function ResultViewer({
  job,
  activeTab,
  readableMode,
  onTabChange,
  onReadableModeChange,
  onCopy,
}: {
  job: JobViewModel;
  activeTab: TabId;
  readableMode: "compare" | "clean";
  onTabChange: (tab: TabId) => void;
  onReadableModeChange: (mode: "compare" | "clean") => void;
  onCopy: (value: string, label: string) => void;
}) {
  const isJnkieLoader = job.detection.pluginId === "jnkie-luraph-14-static";
  const isRegisterPseudocode =
    isJnkieLoader && job.readableKind === "register-pseudocode";
  const displayedTabs = useMemo(
    () =>
      TABS.map((tab) => {
        if (tab.id === "readable" && isRegisterPseudocode) {
          return {
            ...tab,
            label: "Readable IR",
            description:
              "Conservative register-level pseudocode with provenance; not original source",
          };
        }
        if (tab.id === "readable" && isJnkieLoader) {
          return {
            ...tab,
            label: "VM Loader",
            description:
              "Token-verified current loader; high-level payload source remains unknown",
          };
        }
        if (
          tab.id === "records" &&
          job.statistics.instructions !== undefined
        ) {
          return {
            ...tab,
            description: `${formatCount(job.statistics.instructions)} bounded instruction records with structural provenance`,
          };
        }
        return tab;
      }),
    [isJnkieLoader, isRegisterPseudocode, job.statistics.instructions],
  );
  const activeDefinition =
    displayedTabs.find((tab) => tab.id === activeTab) ?? displayedTabs[1]!;
  const warnings = job.diagnostics.filter(
    (diagnostic) =>
      diagnostic.severity === "warning" || diagnostic.severity === "error",
  ).length;

  const textForActiveTab = useMemo(() => {
    switch (activeTab) {
      case "original":
        return job.artifacts.original;
      case "readable":
        return job.artifacts.readable;
      case "records":
        return job.artifacts.decodedRecords;
      case "audit":
        return job.artifacts.exactAudit;
      case "behavior":
        return job.artifacts.behaviorReport;
      case "payload":
        return job.artifacts.payloadReport;
      case "validation":
        return job.artifacts.validationReport;
      case "warnings":
        return job.artifacts.warnings;
    }
  }, [activeTab, job.artifacts]);

  const lineCount = countLines(textForActiveTab);

  return (
    <section className="result-viewer">
      <nav aria-label="Analysis artifacts" className="artifact-tabs" role="tablist">
        {displayedTabs.map((tab) => {
          const active = tab.id === activeTab;
          const unavailable =
            (tab.id === "readable" && !job.artifacts.readable) ||
            (tab.id === "records" && !job.artifacts.decodedRecords) ||
            (tab.id === "audit" && !job.artifacts.exactAudit) ||
            (tab.id === "behavior" && !job.artifacts.behaviorReport) ||
            (tab.id === "payload" && !job.artifacts.payloadReport);

          return (
            <button
              aria-selected={active}
              className={`${active ? "artifact-tab artifact-tab--active" : "artifact-tab"}${
                unavailable ? " artifact-tab--muted" : ""
              }`}
              key={tab.id}
              onClick={() => onTabChange(tab.id)}
              role="tab"
              type="button"
            >
              <Icon name={tab.icon} size={15} />
              <span>{tab.label}</span>
              {tab.id === "warnings" && warnings > 0 && (
                <span className="artifact-tab__count">{warnings}</span>
              )}
            </button>
          );
        })}
      </nav>

      <div className="artifact-toolbar">
        <div>
          <strong>{activeDefinition.label}</strong>
          <span>{activeDefinition.description}</span>
        </div>
        <div className="artifact-toolbar__actions">
          {lineCount !== undefined && (
            <span className="line-count">{formatCount(lineCount)} lines</span>
          )}
          {activeTab === "readable" &&
            job.artifacts.readable &&
            job.readableKind === "source-code" && (
              <div className="segmented-control" aria-label="Readable code view">
                <button
                  aria-pressed={readableMode === "compare"}
                  className={readableMode === "compare" ? "is-active" : ""}
                  onClick={() => onReadableModeChange("compare")}
                  type="button"
                >
                  <Icon name="compare" size={14} />
                  Compare
                </button>
                <button
                  aria-pressed={readableMode === "clean"}
                  className={readableMode === "clean" ? "is-active" : ""}
                  onClick={() => onReadableModeChange("clean")}
                  type="button"
                >
                  <Icon name="code" size={14} />
                  Clean
                </button>
              </div>
            )}
          {textForActiveTab && (
            <button
              className="icon-button"
              onClick={() =>
                onCopy(textForActiveTab, `${activeDefinition.label} copied`)
              }
              title={`Copy ${activeDefinition.label.toLowerCase()}`}
              type="button"
            >
              <Icon name="copy" size={15} />
              <span className="sr-only">Copy {activeDefinition.label}</span>
            </button>
          )}
        </div>
      </div>

      <div className="artifact-content" role="tabpanel">
        {activeTab === "original" && (
          <CodeSurface
            ariaLabel="Original source code"
            emptyDetail="The original source text was not included in the renderer result."
            emptyTitle="Original text unavailable"
            value={job.artifacts.original}
          />
        )}
        {activeTab === "readable" &&
          (readableMode === "compare" &&
            job.readableKind === "source-code" ? (
            <DiffSurface
              modified={job.artifacts.readable}
              original={job.artifacts.original}
            />
          ) : (
            <CodeSurface
              ariaLabel={
                job.readableKind === "register-pseudocode"
                  ? "Readable register-level pseudocode"
                  : job.readableKind === "devirtualized-lua"
                    ? "Lua devirtualized from VM records"
                    : job.readableKind === "vm-loader"
                      ? "Readable VM loader"
                      : "Readable reconstructed source code"
              }
              emptyDetail={
                job.status === "unsupported"
                  ? "No supported plugin produced a readable reconstruction. Nothing was guessed."
                  : "The analysis stopped before a readable artifact could be validated."
              }
              emptyTitle="Readable reconstruction unavailable"
              language={
                job.readableKind === "register-pseudocode"
                  ? "plaintext"
                  : "lua"
              }
              value={job.artifacts.readable}
            />
          ))}
        {activeTab === "records" && (
          <CodeSurface
            ariaLabel="Decoded JNKIE instruction records"
            emptyDetail="This analysis did not emit a bounded human-readable record report. Full machine records may still be present in the exported bundle."
            emptyTitle="Decoded records unavailable"
            language="plaintext"
            value={job.artifacts.decodedRecords}
          />
        )}
        {activeTab === "audit" && (
          <CodeSurface
            ariaLabel="Exact audit source"
            emptyDetail="No evidence-first audit source was emitted for this recovery path."
            emptyTitle="Exact audit unavailable"
            value={job.artifacts.exactAudit}
          />
        )}
        {activeTab === "behavior" && (
          <CodeSurface
            ariaLabel="Behavior report"
            emptyDetail="The analysis did not recover enough validated behavior to emit a report."
            emptyTitle="Behavior report unavailable"
            language="markdown"
            value={job.artifacts.behaviorReport}
          />
        )}
        {activeTab === "payload" && (
          <CodeSurface
            ariaLabel="JNKIE payload structure report"
            emptyDetail="This analysis did not produce a bounded binary payload report."
            emptyTitle="Payload map unavailable"
            language="markdown"
            value={job.artifacts.payloadReport}
          />
        )}
        {activeTab === "validation" && (
          <ValidationView
            checks={job.validationChecks}
            report={job.artifacts.validationReport}
          />
        )}
        {activeTab === "warnings" && (
          <WarningsView
            diagnostics={job.diagnostics}
            warningsText={job.artifacts.warnings}
          />
        )}
      </div>
    </section>
  );
}

function JobWorkspace({
  job,
  activeTab,
  readableMode,
  onTabChange,
  onReadableModeChange,
  onCopy,
}: {
  job: JobViewModel;
  activeTab: TabId;
  readableMode: "compare" | "clean";
  onTabChange: (tab: TabId) => void;
  onReadableModeChange: (mode: "compare" | "clean") => void;
  onCopy: (value: string, label: string) => void;
}) {
  const meta = STATUS_META[job.status];
  const warningCount =
    job.statistics.warnings ??
    job.diagnostics.filter(
      (diagnostic) =>
        diagnostic.severity === "warning" || diagnostic.severity === "error",
    ).length;
  const statistics = job.statistics;
  const hasRecordStatistics =
    statistics.recordSections !== undefined ||
    statistics.prototypes !== undefined ||
    statistics.instructions !== undefined;
  const recordDetail = [
    statistics.recordSections === undefined
      ? undefined
      : `${formatCount(statistics.recordSections)} sections`,
    statistics.prototypes === undefined
      ? undefined
      : `${formatCount(statistics.prototypes)} prototypes`,
    statistics.childReferences === undefined
      ? undefined
      : statistics.resolvedChildReferences === undefined
        ? `${formatCount(statistics.childReferences)} child links`
        : `${formatCount(statistics.resolvedChildReferences)}/${formatCount(statistics.childReferences)} child links`,
  ]
    .filter((value): value is string => value !== undefined)
    .join(" · ");
  const recordTitle = [
    statistics.constants === undefined
      ? undefined
      : `${formatCount(statistics.constants)} constants`,
    statistics.constantReferences === undefined
      ? undefined
      : `${formatCount(statistics.constantReferences)} constant references`,
    statistics.stringReferences === undefined
      ? undefined
      : `${formatCount(statistics.stringReferences)} string references`,
    statistics.decodedBytes === undefined
      ? undefined
      : `${formatBytes(statistics.decodedBytes)} structurally decoded`,
    statistics.unresolvedBytes === undefined
      ? undefined
      : `${formatBytes(statistics.unresolvedBytes)} unresolved`,
    statistics.outerRootPrototype === undefined
      ? undefined
      : `outer root #${formatCount(statistics.outerRootPrototype)}`,
    statistics.nestedRootPrototype === undefined
      ? undefined
      : `nested root #${formatCount(statistics.nestedRootPrototype)}`,
  ]
    .filter((value): value is string => value !== undefined)
    .join(" · ");
  const hasSemanticStatistics =
    statistics.semanticCoverageRatio !== undefined ||
    statistics.semanticInstructions !== undefined ||
    statistics.protocolInstructions !== undefined ||
    statistics.unknownInstructions !== undefined;
  const semanticDetail = [
    statistics.semanticInstructions === undefined
      ? undefined
      : `${formatCount(statistics.semanticInstructions)} semantic`,
    statistics.protocolInstructions === undefined
      ? undefined
      : `${formatCount(statistics.protocolInstructions)} protocol`,
    statistics.unknownInstructions === undefined
      ? undefined
      : `${formatCount(statistics.unknownInstructions)} unknown`,
    statistics.unresolvedBytes === undefined || statistics.unresolvedBytes === 0
      ? undefined
      : `${formatBytes(statistics.unresolvedBytes)} unresolved bytes`,
  ]
    .filter((value): value is string => value !== undefined)
    .join(" · ");
  const recoveryNeedsAttention =
    (statistics.unknownInstructions ?? 0) > 0 ||
    (statistics.unresolvedBytes ?? 0) > 0 ||
    (statistics.childReferences !== undefined &&
      statistics.resolvedChildReferences !== undefined &&
      statistics.resolvedChildReferences < statistics.childReferences);
  const recoveryValue = hasSemanticStatistics
    ? statistics.semanticCoverageRatio === undefined
      ? statistics.semanticInstructions === undefined
        ? `${formatCount(statistics.unknownInstructions)} unknown`
        : `${formatCount(statistics.semanticInstructions)} mapped`
      : formatCoverageRatio(statistics.semanticCoverageRatio)
    : statistics.childReferences !== undefined
      ? statistics.resolvedChildReferences === undefined
        ? `${formatCount(statistics.childReferences)} links`
        : `${formatCount(statistics.resolvedChildReferences)}/${formatCount(statistics.childReferences)} links`
      : formatBytes(statistics.decodedBytes);
  const recoveryDetail = hasSemanticStatistics
    ? semanticDetail || "Semantic accounting unavailable"
    : [
        statistics.decodedBytes === undefined
          ? undefined
          : `${formatBytes(statistics.decodedBytes)} decoded`,
        statistics.unresolvedBytes === undefined
          ? undefined
          : `${formatBytes(statistics.unresolvedBytes)} unresolved`,
      ]
        .filter((value): value is string => value !== undefined)
        .join(" · ") || "Structural recovery statistics unavailable";

  return (
    <main className="workspace-page">
      <section className="job-heading">
        <div className="job-heading__identity">
          <span className="file-emblem">
            <Icon name="file" size={23} />
            <small>{job.input.name.split(".").at(-1)?.slice(0, 4) ?? "LUA"}</small>
          </span>
          <div>
            <div className="job-heading__title-line">
              <h1>{job.input.name}</h1>
              <StatusPill status={job.status} />
            </div>
            <div className="job-heading__meta">
              <span>{formatBytes(job.input.size)}</span>
              <span>{job.input.dialect ?? "Dialect unknown"}</span>
              <span>
                {job.input.lineCount === undefined
                  ? "Line count unavailable"
                  : `${formatCount(job.input.lineCount)} source lines`}
              </span>
              <span
                className="job-heading__hash"
                title={job.input.sha256 ?? "SHA-256 unavailable"}
              >
                SHA-256{" "}
                {job.input.sha256
                  ? `${job.input.sha256.slice(0, 10)}…${job.input.sha256.slice(-8)}`
                  : "unavailable"}
              </span>
            </div>
          </div>
        </div>
        <AuthorizedUseNote compact />
      </section>

      <section className={`result-banner result-banner--${meta.tone}`}>
        <span className="result-banner__icon">
          <Icon
            name={
              meta.tone === "success"
                ? "check"
                : meta.tone === "danger"
                  ? "alert"
                  : meta.tone === "warning"
                    ? "warning"
                    : "info"
            }
            size={18}
          />
        </span>
        <div>
          <strong>{meta.title}</strong>
          <p>{job.summary ?? meta.description}</p>
        </div>
        {job.statistics.durationMs !== undefined && (
          <span className="result-banner__duration">
            {formatDuration(job.statistics.durationMs)}
          </span>
        )}
      </section>

      <section className="summary-grid">
        <SummaryCard
          detail={`${formatCount(job.input.lineCount)} source lines`}
          icon="file"
          label="Input"
          value={formatBytes(job.input.size)}
        />
        <SummaryCard
          detail={
            hasRecordStatistics
              ? recordDetail || "Decoded record totals available"
              : statistics.prototypeSummaries !== undefined
                ? `${formatCount(statistics.topIrRows)} top-prototype raw IR rows`
                : `${formatCount(statistics.transformations)} evidence-backed changes`
          }
          icon="code"
          label={hasRecordStatistics ? "Decoded" : "Analyzed"}
          title={hasRecordStatistics ? recordTitle : undefined}
          tone={
            hasRecordStatistics
              ? "accent"
              : job.status === "verified"
                ? "success"
                : undefined
          }
          value={
            hasRecordStatistics
              ? `${formatCount(statistics.instructions)} instructions`
              : statistics.prototypeSummaries !== undefined
                ? `${formatCount(statistics.prototypeSummaries)} prototype summaries`
                : `${formatCount(statistics.functions)} functions`
          }
        />
        {hasRecordStatistics ? (
          <SummaryCard
            detail={recoveryDetail}
            icon={recoveryNeedsAttention ? "warning" : "check"}
            label={hasSemanticStatistics ? "Semantics" : "Recovery"}
            title={`${recordTitle}${recordTitle && semanticDetail ? " · " : ""}${semanticDetail}`}
            tone={recoveryNeedsAttention ? "warning" : "success"}
            value={recoveryValue}
          />
        ) : (
          <SummaryCard
            detail={`${formatCount(warningCount)} warning and error diagnostics`}
            icon={warningCount > 0 ? "warning" : "check"}
            label="Diagnostics"
            tone={warningCount > 0 ? "warning" : "success"}
            value={formatCount(warningCount)}
          />
        )}
      </section>

      <div className="workspace-grid">
        <aside className="workspace-sidebar">
          <DetectionPanel job={job} />
          <JobTimelinePanel stages={job.stages} />
        </aside>

        <div className="workspace-main">
          <ResultViewer
            activeTab={activeTab}
            job={job}
            onCopy={onCopy}
            onReadableModeChange={onReadableModeChange}
            onTabChange={onTabChange}
            readableMode={readableMode}
          />
          <DiagnosticsPanel diagnostics={job.diagnostics} />
        </div>
      </div>
    </main>
  );
}

export default function App() {
  const [phase, setPhase] = useState<AppPhase>("idle");
  const [job, setJob] = useState<JobViewModel | null>(null);
  const [activeTab, setActiveTab] = useState<TabId>("readable");
  const [readableMode, setReadableMode] = useState<"compare" | "clean">("compare");
  const [dropActive, setDropActive] = useState(false);
  const [pickerBusy, setPickerBusy] = useState(false);
  const [exportBusy, setExportBusy] = useState(false);
  const [cancelling, setCancelling] = useState(false);
  const [notice, setNotice] = useState<string>();
  const [failureMessage, setFailureMessage] = useState<string>();
  const [toast, setToast] = useState<string>();
  const [progress, setProgress] = useState<ProgressState>({
    percent: 3,
    message: "Preparing a restricted analysis worker…",
    stages: initialStages(),
  });

  const dragDepth = useRef(0);
  const cancelled = useRef(false);
  const activeJobId = useRef<string | undefined>(undefined);
  const runGeneration = useRef(0);
  const acceptingProgress = useRef(false);
  const expectedInputPath = useRef<string | undefined>(undefined);
  const retiredJobIds = useRef(new Set<string>());
  const pendingCancellation = useRef<PendingCancellation | undefined>(undefined);

  const retireJobId = (jobId?: string) => {
    if (jobId === undefined) {
      return;
    }
    retiredJobIds.current.delete(jobId);
    retiredJobIds.current.add(jobId);
    while (retiredJobIds.current.size > 64) {
      const oldest = retiredJobIds.current.values().next().value as
        | string
        | undefined;
      if (oldest === undefined) {
        break;
      }
      retiredJobIds.current.delete(oldest);
    }
  };

  const stopAcceptingProgress = (additionalJobId?: string) => {
    acceptingProgress.current = false;
    expectedInputPath.current = undefined;
    retireJobId(activeJobId.current);
    retireJobId(additionalJobId);
    activeJobId.current = undefined;
  };

  const api = window.deobfuscator;

  useEffect(() => {
    if (!api) {
      return;
    }

    const dispose = api.onProgress((event) => {
      if (!shouldAcceptProgressEvent(event, {
        accepting: acceptingProgress.current,
        expectedInputPath: expectedInputPath.current,
        activeJobId: activeJobId.current,
        retiredJobIds: retiredJobIds.current,
      })) {
        return;
      }

      if (activeJobId.current === undefined && event.jobId !== undefined) {
        activeJobId.current = event.jobId;
      }

      setProgress((current) => ({
        jobId: event.jobId ?? current.jobId,
        filePath: event.inputPath ?? current.filePath,
        percent:
          event.percent === undefined
            ? current.percent
            : Math.min(100, Math.max(0, event.percent)),
        message: event.message ?? current.message,
        stages: applyProgressToStages(current.stages, event),
      }));
    });

    return typeof dispose === "function" ? dispose : undefined;
  }, [api]);

  useEffect(() => {
    if (!toast) {
      return;
    }

    const timeout = window.setTimeout(() => setToast(undefined), 3600);
    return () => window.clearTimeout(timeout);
  }, [toast]);

  const reset = () => {
    runGeneration.current += 1;
    cancelled.current = false;
    pendingCancellation.current = undefined;
    stopAcceptingProgress();
    setPhase("idle");
    setJob(null);
    setFailureMessage(undefined);
    setNotice(undefined);
    setActiveTab("readable");
    setReadableMode("compare");
    setProgress({
      percent: 3,
      message: "Preparing a restricted analysis worker…",
      stages: initialStages(),
    });
  };

  const runAnalysis = async (path: string) => {
    if (!api) {
      setNotice(
        "The secure desktop bridge is unavailable. Open the packaged app or use the sample preview.",
      );
      return;
    }

    const generation = runGeneration.current + 1;
    runGeneration.current = generation;
    cancelled.current = false;
    pendingCancellation.current = undefined;
    stopAcceptingProgress();
    acceptingProgress.current = true;
    expectedInputPath.current = path;
    setNotice(undefined);
    setFailureMessage(undefined);
    setJob(null);
    setActiveTab("readable");
    setReadableMode("compare");
    setProgress({
      filePath: path,
      percent: 4,
      message: "Importing and hashing the original bytes…",
      stages: initialStages(),
    });
    setPhase("analyzing");

    try {
      const result = await api.analyzeFile(path);
      const pending = pendingCancellation.current as PendingCancellation | undefined;
      if (
        pending?.generation === generation &&
        !(await cancellationAllowsCompletedResult(pending.promise))
      ) {
        return;
      }
      if (cancelled.current || generation !== runGeneration.current) {
        return;
      }

      stopAcceptingProgress(result.jobId);
      const normalized = normalizeAnalysisResult(result, path);
      setJob(normalized);
      setReadableMode(
        normalized.readableKind === "source-code" ? "compare" : "clean",
      );
      setActiveTab(
        normalized.status === "unsupported" ||
        normalized.status === "failed"
          ? "validation"
          : normalized.artifacts.readable
            ? "readable"
            : normalized.artifacts.decodedRecords
              ? "records"
              : "validation",
      );
      setPhase("result");
    } catch (error) {
      const pending = pendingCancellation.current as PendingCancellation | undefined;
      if (
        pending?.generation === generation &&
        !(await cancellationAllowsCompletedResult(pending.promise))
      ) {
        return;
      }
      if (cancelled.current || generation !== runGeneration.current) {
        return;
      }

      stopAcceptingProgress();
      setFailureMessage(
        error instanceof Error
          ? error.message
          : "The analysis worker returned an unexpected error.",
      );
      setPhase("error");
    }
  };

  const chooseFile = async () => {
    if (!api) {
      setNotice(
        "The file picker is available in the packaged desktop app. Use the sample preview to inspect this interface.",
      );
      return;
    }

    setPickerBusy(true);
    setNotice(undefined);
    try {
      const chosen = await api.chooseFile();
      const path = typeof chosen === "string" ? chosen : chosen?.path;
      if (path) {
        await runAnalysis(path);
      }
    } catch (error) {
      setNotice(
        error instanceof Error
          ? error.message
          : "The file picker could not be opened.",
      );
    } finally {
      setPickerBusy(false);
    }
  };

  const handleDragEnter: React.DragEventHandler<HTMLDivElement> = (event) => {
    event.preventDefault();
    dragDepth.current += 1;
    setDropActive(true);
  };

  const handleDragLeave: React.DragEventHandler<HTMLDivElement> = (event) => {
    event.preventDefault();
    dragDepth.current -= 1;
    if (dragDepth.current <= 0) {
      dragDepth.current = 0;
      setDropActive(false);
    }
  };

  const handleDragOver: React.DragEventHandler<HTMLDivElement> = (event) => {
    event.preventDefault();
    event.dataTransfer.dropEffect = "copy";
  };

  const handleDrop: React.DragEventHandler<HTMLDivElement> = (event) => {
    event.preventDefault();
    dragDepth.current = 0;
    setDropActive(false);

    const file = event.dataTransfer.files.item(0) as
      | (File & { path?: string })
      | null;
    if (!file) {
      return;
    }

    let droppedPath: string | undefined;
    try {
      droppedPath = api?.getPathForFile?.(file) || file.path;
    } catch {
      droppedPath = file.path;
    }

    if (!droppedPath) {
      setNotice(
        "Windows did not expose a safe local path for that drop. Use Choose a file instead.",
      );
      return;
    }

    void runAnalysis(droppedPath);
  };

  const showSample = () => {
    runGeneration.current += 1;
    cancelled.current = false;
    pendingCancellation.current = undefined;
    stopAcceptingProgress();
    setJob(createSampleJob());
    setActiveTab("readable");
    setReadableMode("compare");
    setNotice(undefined);
    setPhase("result");
  };

  const cancelAnalysis = async () => {
    if (!api || activeJobId.current === undefined) {
      return;
    }

    const generation = runGeneration.current;
    const targetJobId = activeJobId.current;
    const cancellationPromise = Promise.resolve().then(() =>
      api.cancelJob(targetJobId),
    );
    const request: PendingCancellation = {
      generation,
      promise: cancellationPromise,
    };
    pendingCancellation.current = request;
    setCancelling(true);
    try {
      const outcome = await cancellationPromise;
      if (generation !== runGeneration.current) {
        return;
      }
      if (pendingCancellation.current === request) {
        pendingCancellation.current = undefined;
      }
      if (outcome.outcome === "cancelled") {
        cancelled.current = true;
        runGeneration.current += 1;
        stopAcceptingProgress(targetJobId);
        setPhase("cancelled");
      } else {
        cancelled.current = false;
      }
    } catch (error) {
      if (generation !== runGeneration.current) {
        return;
      }
      runGeneration.current += 1;
      cancelled.current = false;
      stopAcceptingProgress(targetJobId);
      setFailureMessage(
        error instanceof Error
          ? `Cancellation was not confirmed: ${error.message}`
          : "Cancellation was not confirmed; the in-flight result was discarded.",
      );
      setPhase("error");
    } finally {
      if (pendingCancellation.current === request) {
        pendingCancellation.current = undefined;
      }
      setCancelling(false);
    }
  };

  const exportJob = async () => {
    if (!api || !job || job.status === "sample") {
      return;
    }

    setExportBusy(true);
    try {
      const result = await api.exportJob(job.jobId);
      const path = getExportPath(result);
      if (typeof result === "object" && result?.cancelled) {
        return;
      }
      setToast(path ? `Exported to ${path}` : "Result bundle exported");
    } catch (error) {
      setToast(
        error instanceof Error ? error.message : "The export could not be completed.",
      );
    } finally {
      setExportBusy(false);
    }
  };

  const copyText = async (value: string, label: string) => {
    try {
      await navigator.clipboard.writeText(value);
      setToast(label);
    } catch {
      setToast("Clipboard access was unavailable");
    }
  };

  return (
    <div className="app-shell">
      <Header
        canExport={Boolean(job && job.status !== "sample")}
        exportBusy={exportBusy}
        isSample={job?.status === "sample"}
        onChoose={() => void chooseFile()}
        onExport={() => void exportJob()}
        phase={phase}
        pickerBusy={pickerBusy}
      />

      {phase === "idle" && (
        <EmptyState
          bridgeAvailable={Boolean(api)}
          dropActive={dropActive}
          notice={notice}
          onChoose={() => void chooseFile()}
          onDragEnter={handleDragEnter}
          onDragLeave={handleDragLeave}
          onDragOver={handleDragOver}
          onDrop={handleDrop}
          onSample={showSample}
          pickerBusy={pickerBusy}
        />
      )}

      {phase === "analyzing" && (
        <AnalysisLoading
          canCancel={Boolean(progress.jobId || activeJobId.current)}
          cancelling={cancelling}
          onCancel={() => void cancelAnalysis()}
          progress={progress}
        />
      )}

      {phase === "error" && (
        <FailureState
          message={failureMessage}
          onChoose={() => void chooseFile()}
          onReset={reset}
        />
      )}

      {phase === "cancelled" && (
        <FailureState
          cancelled
          onChoose={() => void chooseFile()}
          onReset={reset}
        />
      )}

      {phase === "result" && job && (
        <JobWorkspace
          activeTab={activeTab}
          job={job}
          onCopy={(value, label) => void copyText(value, label)}
          onReadableModeChange={setReadableMode}
          onTabChange={setActiveTab}
          readableMode={readableMode}
        />
      )}

      {toast && (
        <div aria-live="polite" className="toast" role="status">
          <Icon name="check" size={16} />
          <span>{toast}</span>
        </div>
      )}
    </div>
  );
}


