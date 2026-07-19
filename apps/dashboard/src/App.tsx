import { FormEvent, KeyboardEvent, useEffect, useId, useMemo, useRef, useState } from "react";
import {
  ArrowRight,
  CheckCircle,
  Clock,
  Code,
  DownloadSimple,
  FileText,
  Files,
  Flask,
  FolderOpen,
  GlobeSimple,
  Info,
  LockKey,
  MagnifyingGlass,
  ShieldCheck,
  TestTube,
  Warning,
  WarningOctagon,
  Wrench,
} from "@phosphor-icons/react";
import { downloadExport, scanDemo, scanSource, scanUrl } from "./api";
import type { ScanResponse, SecurityFinding, Severity } from "./types";

type ScanMode = "source" | "url";
type ScanOperation = ScanMode | "demo";
type SeverityFilter = "all" | Severity;

const severityOrder: Severity[] = ["critical", "high", "medium", "low", "info"];
const severityRank = new Map(severityOrder.map((severity, index) => [severity, index]));

const severityLabels: Record<Severity, string> = {
  critical: "Critical",
  high: "High",
  medium: "Medium",
  low: "Low",
  info: "Info",
};

function SeverityGlyph({ severity, size = 16 }: { severity: Severity; size?: number }) {
  if (severity === "critical") {
    return <WarningOctagon aria-hidden="true" size={size} weight="fill" />;
  }
  if (severity === "high" || severity === "medium") {
    return <Warning aria-hidden="true" size={size} weight="fill" />;
  }
  if (severity === "low") {
    return <ShieldCheck aria-hidden="true" size={size} weight="fill" />;
  }
  return <Info aria-hidden="true" size={size} weight="fill" />;
}

function SeverityBadge({ severity }: { severity: Severity }) {
  return (
    <span className={`severity-badge severity-${severity}`}>
      <SeverityGlyph severity={severity} />
      {severityLabels[severity]}
    </span>
  );
}

function locationLabel(finding: SecurityFinding): string {
  const location = finding.location;
  const base = location.path || location.endpoint || location.url || "Location unavailable";
  if (location.line) {
    return `${base}:${location.line}${location.column ? `:${location.column}` : ""}`;
  }
  return base;
}

function displayDate(value: string): string {
  const date = new Date(value);
  if (Number.isNaN(date.getTime())) return "Time unavailable";
  return new Intl.DateTimeFormat(undefined, {
    dateStyle: "medium",
    timeStyle: "short",
  }).format(date);
}

function displayDuration(durationMs: number): string {
  if (durationMs < 1_000) return `${durationMs} ms`;
  return `${(durationMs / 1_000).toFixed(1)} s`;
}

function AppHeader() {
  return (
    <header className="app-header">
      <div className="header-inner">
        <a className="brand" href="/" aria-label="Patchwork Security Lab home">
          <span className="brand-mark" aria-hidden="true">
            <ShieldCheck size={22} weight="duotone" />
          </span>
          <span className="brand-copy">
            <strong>Patchwork</strong>
            <span>Security Lab</span>
          </span>
        </a>
        <div className="header-product" aria-label="Current tool">
          <span>Sentinel</span>
          <span className="header-divider" aria-hidden="true" />
          <span className="header-product-label">Security checker</span>
        </div>
        <div className="safety-note">
          <LockKey aria-hidden="true" size={17} weight="duotone" />
          Passive by default
        </div>
      </div>
    </header>
  );
}

function ScanComposer({
  mode,
  setMode,
  target,
  setTarget,
  loading,
  onSubmit,
  onDemo,
  error,
}: {
  mode: ScanMode;
  setMode: (mode: ScanMode) => void;
  target: string;
  setTarget: (target: string) => void;
  loading: boolean;
  onSubmit: (event: FormEvent<HTMLFormElement>) => void;
  onDemo: () => void;
  error: string | null;
}) {
  const sourceTabId = useId();
  const urlTabId = useId();
  const inputId = useId();
  const helperId = useId();
  const errorId = useId();
  const sourceTabRef = useRef<HTMLButtonElement>(null);
  const urlTabRef = useRef<HTMLButtonElement>(null);

  const selectTab = (nextMode: ScanMode, moveFocus = false) => {
    setMode(nextMode);
    if (moveFocus) {
      const nextTab = nextMode === "source" ? sourceTabRef.current : urlTabRef.current;
      nextTab?.focus();
    }
  };

  const handleTabKeyDown = (event: KeyboardEvent<HTMLButtonElement>) => {
    let nextMode: ScanMode | null = null;
    if (event.key === "ArrowLeft" || event.key === "ArrowRight") {
      nextMode = mode === "source" ? "url" : "source";
    } else if (event.key === "Home") {
      nextMode = "source";
    } else if (event.key === "End") {
      nextMode = "url";
    }
    if (!nextMode) return;
    event.preventDefault();
    selectTab(nextMode, true);
  };

  return (
    <section className="scan-composer" aria-labelledby="scan-heading">
      <div className="composer-heading">
        <div>
          <h2 id="scan-heading">Start a review</h2>
          <p>Choose a server-local project or a public website. Checks are read-only.</p>
        </div>
        <button className="button button-secondary" type="button" onClick={onDemo} disabled={loading}>
          <Flask aria-hidden="true" size={18} />
          Load sample
        </button>
      </div>

      <div className="scan-tabs" role="tablist" aria-label="Scan target type">
        <button
          ref={sourceTabRef}
          id={sourceTabId}
          className="scan-tab"
          type="button"
          role="tab"
          aria-selected={mode === "source"}
          aria-controls="scan-form-panel"
          tabIndex={mode === "source" ? 0 : -1}
          onClick={() => selectTab("source")}
          onKeyDown={handleTabKeyDown}
        >
          <FolderOpen aria-hidden="true" size={18} />
          Source repository
        </button>
        <button
          ref={urlTabRef}
          id={urlTabId}
          className="scan-tab"
          type="button"
          role="tab"
          aria-selected={mode === "url"}
          aria-controls="scan-form-panel"
          tabIndex={mode === "url" ? 0 : -1}
          onClick={() => selectTab("url")}
          onKeyDown={handleTabKeyDown}
        >
          <GlobeSimple aria-hidden="true" size={18} />
          Public website
        </button>
      </div>

      <div
        id="scan-form-panel"
        role="tabpanel"
        aria-labelledby={mode === "source" ? sourceTabId : urlTabId}
      >
        <form className="scan-form" onSubmit={onSubmit} noValidate>
          <div className="input-block">
            <label htmlFor={inputId}>{mode === "source" ? "Project path" : "Public URL"}</label>
            <div className="input-row">
              <div className="input-shell">
                {mode === "source" ? (
                  <FolderOpen aria-hidden="true" size={19} />
                ) : (
                  <GlobeSimple aria-hidden="true" size={19} />
                )}
                <input
                  id={inputId}
                  type={mode === "url" ? "url" : "text"}
                  value={target}
                  onChange={(event) => setTarget(event.target.value)}
                  placeholder={mode === "source" ? "." : "https://example.com"}
                  aria-describedby={`${helperId}${error ? ` ${errorId}` : ""}`}
                  aria-invalid={Boolean(error)}
                  autoComplete="off"
                  spellCheck={false}
                  disabled={loading}
                />
              </div>
              <button className="button button-primary" type="submit" disabled={loading || !target.trim()}>
                {loading ? "Reviewing..." : mode === "source" ? "Scan source" : "Scan website"}
                {!loading && <ArrowRight aria-hidden="true" size={18} weight="bold" />}
              </button>
            </div>
            <p id={helperId} className="field-helper">
              {mode === "source"
                ? "Use . to scan the mounted workspace, or enter a path inside it. Generated folders and file size are bounded."
                : "Only passive HTTP checks run. Private addresses and unsafe redirects are rejected by the scanner."}
            </p>
            {error && (
              <p id={errorId} className="field-error" role="alert">
                <WarningOctagon aria-hidden="true" size={17} weight="fill" />
                {error}
              </p>
            )}
          </div>
        </form>
      </div>
    </section>
  );
}

function LoadingState({ operation }: { operation: ScanOperation }) {
  const title =
    operation === "source"
      ? "Reviewing source evidence"
      : operation === "url"
        ? "Inspecting public responses"
        : "Preparing sample evidence";
  const description =
    operation === "demo"
      ? "This sample is generated locally and is not a scan of your application."
      : "Results will distinguish observations from heuristic signals.";

  return (
    <section className="loading-state" aria-live="polite" aria-busy="true">
      <div className="loading-copy">
        <span className="loading-icon" aria-hidden="true">
          <ShieldCheck size={22} weight="duotone" />
        </span>
        <div>
          <h2>{title}</h2>
          <p>{description}</p>
        </div>
      </div>
      <div className="skeleton-grid" aria-hidden="true">
        <span />
        <span />
        <span />
        <span />
      </div>
    </section>
  );
}

function IdleState({ onDemo }: { onDemo: () => void }) {
  return (
    <section className="idle-state" aria-labelledby="idle-heading">
      <div className="idle-icon" aria-hidden="true">
        <ShieldCheck size={30} weight="duotone" />
      </div>
      <div className="idle-content">
        <h2 id="idle-heading">Evidence, not an opaque score</h2>
        <p>
          Each finding includes its location, observed evidence, likely impact, remediation, and a verification step.
        </p>
        <button className="text-button" type="button" onClick={onDemo}>
          Explore a sample review
          <ArrowRight aria-hidden="true" size={17} weight="bold" />
        </button>
      </div>
      <div className="review-sequence" aria-label="Review output includes">
        <div>
          <Code aria-hidden="true" size={19} />
          <span>Observed</span>
        </div>
        <div>
          <Warning aria-hidden="true" size={19} />
          <span>Impact</span>
        </div>
        <div>
          <Wrench aria-hidden="true" size={19} />
          <span>Remediate</span>
        </div>
        <div>
          <TestTube aria-hidden="true" size={19} />
          <span>Verify</span>
        </div>
      </div>
    </section>
  );
}

function Summary({ scan }: { scan: ScanResponse }) {
  const values: Array<{ label: string; value: number; severity?: Severity }> = [
    { label: "Total", value: scan.summary.total },
    ...severityOrder.map((severity) => ({
      label: severityLabels[severity],
      value: scan.summary[severity],
      severity,
    })),
  ];
  return (
    <dl className="summary-strip" aria-label="Finding summary">
      {values.map((item) => (
        <div className="summary-item" key={item.label}>
          <dt>
            {item.severity ? <SeverityGlyph severity={item.severity} size={15} /> : <Files size={15} />}
            {item.label}
          </dt>
          <dd>{item.value}</dd>
        </div>
      ))}
    </dl>
  );
}

interface ExportFeedback {
  tone: "success" | "error";
  text: string;
}

function ResultsToolbar({
  scan,
  onExport,
  exportBusy,
  exportMessage,
}: {
  scan: ScanResponse;
  onExport: (format: "json" | "sarif") => void;
  exportBusy: "json" | "sarif" | null;
  exportMessage: ExportFeedback | null;
}) {
  const statusLabel = scan.status === "completed" ? "Complete" : scan.status === "partial" ? "Partial" : "Failed";
  return (
    <div className="results-toolbar">
      <div className="scan-identity">
        <div className="scan-title-line">
          <h2 id="results-heading" tabIndex={-1}>Review results</h2>
          <span className={`scan-status scan-status-${scan.status}`}>{statusLabel}</span>
          {Boolean(scan.metadata.sample_data) && <span className="sample-label">Sample data</span>}
        </div>
        <p className="scan-target" title={scan.target}>{scan.target}</p>
        <div className="scan-meta">
          <span><Clock aria-hidden="true" size={15} />{displayDate(scan.completed_at)}</span>
          <span>{displayDuration(scan.duration_ms)}</span>
          {scan.coverage.files_scanned != null ? <span>{scan.coverage.files_scanned} files</span> : null}
          {scan.coverage.pages_scanned != null ? <span>{scan.coverage.pages_scanned} pages</span> : null}
          {scan.coverage.skipped ? <span>{scan.coverage.skipped} skipped</span> : null}
          {scan.summary.checks_run ? <span>{scan.summary.checks_run} checks</span> : null}
        </div>
      </div>
      <div className="export-area">
        <div className="export-actions" aria-label="Download scan evidence">
          <button
            className="button button-secondary button-compact"
            type="button"
            onClick={() => onExport("json")}
            disabled={Boolean(exportBusy)}
          >
            <DownloadSimple aria-hidden="true" size={17} />
            {exportBusy === "json" ? "Preparing JSON..." : "Download JSON"}
          </button>
          <button
            className="button button-secondary button-compact"
            type="button"
            onClick={() => onExport("sarif")}
            disabled={Boolean(exportBusy)}
          >
            <DownloadSimple aria-hidden="true" size={17} />
            {exportBusy === "sarif" ? "Preparing SARIF..." : "Download SARIF"}
          </button>
        </div>
        {exportMessage && (
          <p
            className={`export-message export-message-${exportMessage.tone}`}
            role={exportMessage.tone === "error" ? "alert" : "status"}
          >
            {exportMessage.text}
          </p>
        )}
      </div>
    </div>
  );
}

function FindingFilters({
  scan,
  search,
  setSearch,
  severity,
  setSeverity,
}: {
  scan: ScanResponse;
  search: string;
  setSearch: (search: string) => void;
  severity: SeverityFilter;
  setSeverity: (severity: SeverityFilter) => void;
}) {
  const searchId = useId();
  return (
    <div className="finding-filters">
      <div className="search-field">
        <label className="visually-hidden" htmlFor={searchId}>Search findings</label>
        <MagnifyingGlass aria-hidden="true" size={18} />
        <input
          id={searchId}
          type="search"
          value={search}
          onChange={(event) => setSearch(event.target.value)}
          placeholder="Search title, rule, path"
        />
      </div>
      <div className="severity-filters" aria-label="Filter by severity">
        <button
          type="button"
          className="filter-button"
          aria-pressed={severity === "all"}
          onClick={() => setSeverity("all")}
        >
          All <span>{scan.summary.total}</span>
        </button>
        {severityOrder.map((item) => (
          <button
            type="button"
            className={`filter-button filter-${item}`}
            aria-pressed={severity === item}
            onClick={() => setSeverity(item)}
            key={item}
          >
            <SeverityGlyph severity={item} size={14} />
            {severityLabels[item]} <span>{scan.summary[item]}</span>
          </button>
        ))}
      </div>
    </div>
  );
}

function FindingsList({
  findings,
  selectedId,
  onSelect,
}: {
  findings: SecurityFinding[];
  selectedId: string | null;
  onSelect: (id: string) => void;
}) {
  if (findings.length === 0) {
    return (
      <div className="filtered-empty">
        <MagnifyingGlass aria-hidden="true" size={22} />
        <h3>No matching findings</h3>
        <p>Change the search text or severity filter.</p>
      </div>
    );
  }

  return (
    <ul className="finding-list" aria-label="Security findings">
      {findings.map((finding) => (
        <li className="finding-list-item" key={finding.id}>
          <button
            id={`finding-row-${finding.id}`}
            className="finding-row"
            type="button"
            aria-pressed={selectedId === finding.id}
            aria-controls="finding-detail-pane"
            onClick={() => onSelect(finding.id)}
          >
            <span className="finding-row-main">
              <span className="finding-row-top">
                <SeverityBadge severity={finding.severity} />
                <span className="finding-rule">{finding.rule_id}</span>
              </span>
              <strong>{finding.title}</strong>
              <span className="finding-location">{locationLabel(finding)}</span>
            </span>
            <span className="finding-confidence">
              {finding.confidence} confidence
            </span>
          </button>
        </li>
      ))}
    </ul>
  );
}

function DetailSection({
  icon,
  title,
  children,
}: {
  icon: React.ReactNode;
  title: string;
  children: React.ReactNode;
}) {
  return (
    <section className="detail-section">
      <h4>{icon}{title}</h4>
      <div className="detail-section-body">{children}</div>
    </section>
  );
}

function FindingDetail({ finding }: { finding: SecurityFinding | null }) {
  if (!finding) {
    return (
      <div className="detail-empty">
        <FileText aria-hidden="true" size={25} />
        <p>Select a finding to review its evidence.</p>
      </div>
    );
  }

  return (
    <article className="finding-detail" aria-labelledby={`finding-${finding.id}`}>
      <header className="detail-header">
        <div className="detail-labels">
          <SeverityBadge severity={finding.severity} />
          <span className="confidence-label">{finding.confidence} confidence</span>
          {finding.cwe && <span className="cwe-label">{finding.cwe}</span>}
        </div>
        <h3 id={`finding-${finding.id}`}>{finding.title}</h3>
        <p className="detail-rule">{finding.rule_id} / {finding.category}</p>
        <p className="detail-description">{finding.description}</p>
        <div className="detail-location">
          <Code aria-hidden="true" size={17} />
          <code>{locationLabel(finding)}</code>
        </div>
      </header>

      <div className="detail-sections">
        <DetailSection icon={<Code aria-hidden="true" size={18} />} title="Observed evidence">
          {finding.evidence.length > 0 ? (
            <div className="evidence-list">
              {finding.evidence.map((item, index) => (
                <div className="evidence-item" key={`${item.label}-${index}`}>
                  <strong>{item.label}</strong>
                  <p>{item.value}</p>
                  {item.code && <pre><code>{item.code}</code></pre>}
                </div>
              ))}
            </div>
          ) : (
            <p>No structured evidence was returned for this check.</p>
          )}
        </DetailSection>

        <DetailSection icon={<Warning aria-hidden="true" size={18} />} title="Why it matters">
          <p>{finding.impact}</p>
        </DetailSection>

        <DetailSection icon={<Wrench aria-hidden="true" size={18} />} title="Remediation">
          <p>{finding.remediation}</p>
        </DetailSection>

        <DetailSection icon={<TestTube aria-hidden="true" size={18} />} title="Verify the fix">
          <p>{finding.verification}</p>
        </DetailSection>

        {finding.references.length > 0 && (
          <DetailSection icon={<FileText aria-hidden="true" size={18} />} title="References">
            <ul className="reference-list">
              {finding.references.map((reference) => (
                <li key={reference}>
                  <a href={reference} target="_blank" rel="noreferrer">{reference}</a>
                </li>
              ))}
            </ul>
          </DetailSection>
        )}
      </div>
    </article>
  );
}

function CoverageNotice({ scan }: { scan: ScanResponse }) {
  if (scan.status === "completed" && scan.coverage.completeness === "complete") return null;

  const failed = scan.status === "failed" || scan.coverage.completeness === "failed";
  return (
    <div className={`coverage-notice coverage-notice-${failed ? "failed" : "partial"}`} role={failed ? "alert" : "note"}>
      {failed ? (
        <WarningOctagon aria-hidden="true" size={19} weight="fill" />
      ) : (
        <Warning aria-hidden="true" size={19} weight="fill" />
      )}
      <div>
        <strong>{failed ? "Review did not complete" : "Review coverage is partial"}</strong>
        <p>
          {failed
            ? "The scanner could not complete the requested checks. Treat any returned findings as incomplete evidence."
            : "The scanner reached a configured bound or skipped part of the target. Review the scope notes before making a decision."}
        </p>
      </div>
    </div>
  );
}

function ZeroResultState({ scan }: { scan: ScanResponse }) {
  const failed = scan.status === "failed" || scan.coverage.completeness === "failed";
  const partial = scan.status === "partial" || scan.coverage.completeness === "partial";

  if (failed) {
    return (
      <div className="zero-state zero-state-failed">
        <WarningOctagon aria-hidden="true" size={34} weight="duotone" />
        <h3>No complete result was produced</h3>
        <p>No findings were returned, but the review failed. Resolve the scope note or server error and run it again.</p>
      </div>
    );
  }
  if (partial) {
    return (
      <div className="zero-state zero-state-partial">
        <Warning aria-hidden="true" size={34} weight="duotone" />
        <h3>No findings in the checked portion</h3>
        <p>Coverage was partial, so this is not a clean result. Review skipped work and rerun with appropriate bounds.</p>
      </div>
    );
  }
  return (
    <div className="zero-state zero-state-clean">
      <CheckCircle aria-hidden="true" size={34} weight="duotone" />
      <h3>No findings in this review</h3>
      <p>This result covers only the checks that ran. It does not prove the target is vulnerability-free.</p>
    </div>
  );
}

function ResultsView({ scan }: { scan: ScanResponse }) {
  const orderedFindings = useMemo(
    () =>
      [...scan.findings].sort((left, right) => {
        const severityDifference =
          (severityRank.get(left.severity) ?? severityOrder.length) -
          (severityRank.get(right.severity) ?? severityOrder.length);
        if (severityDifference !== 0) return severityDifference;
        return (
          left.rule_id.localeCompare(right.rule_id) ||
          locationLabel(left).localeCompare(locationLabel(right)) ||
          left.id.localeCompare(right.id)
        );
      }),
    [scan.findings],
  );
  const [severity, setSeverity] = useState<SeverityFilter>("all");
  const [search, setSearch] = useState("");
  const [selectedId, setSelectedId] = useState<string | null>(orderedFindings[0]?.id ?? null);
  const [exportBusy, setExportBusy] = useState<"json" | "sarif" | null>(null);
  const [exportMessage, setExportMessage] = useState<ExportFeedback | null>(null);

  useEffect(() => {
    setSeverity("all");
    setSearch("");
    setSelectedId(orderedFindings[0]?.id ?? null);
    setExportMessage(null);
  }, [scan.id, orderedFindings]);

  const filteredFindings = useMemo(() => {
    const query = search.trim().toLowerCase();
    return orderedFindings.filter((finding) => {
      if (severity !== "all" && finding.severity !== severity) return false;
      if (!query) return true;
      return [
        finding.title,
        finding.rule_id,
        finding.category,
        finding.description,
        locationLabel(finding),
      ].some((value) => value.toLowerCase().includes(query));
    });
  }, [orderedFindings, search, severity]);

  useEffect(() => {
    if (selectedId && filteredFindings.some((finding) => finding.id === selectedId)) return;
    setSelectedId(filteredFindings[0]?.id ?? null);
  }, [filteredFindings, selectedId]);

  const selectedFinding = orderedFindings.find((finding) => finding.id === selectedId) ?? null;

  const handleSelect = (id: string) => {
    setSelectedId(id);
    const detailPane = document.getElementById("finding-detail-pane");
    if (detailPane) detailPane.scrollTop = 0;
    if (window.matchMedia("(max-width: 760px)").matches) {
      requestAnimationFrame(() => {
        detailPane?.scrollIntoView({
          behavior: window.matchMedia("(prefers-reduced-motion: reduce)").matches ? "auto" : "smooth",
          block: "start",
        });
      });
    }
  };

  const handleExport = async (format: "json" | "sarif") => {
    setExportBusy(format);
    setExportMessage(null);
    try {
      await downloadExport(scan.id, format);
      setExportMessage({ tone: "success", text: `${format.toUpperCase()} downloaded.` });
    } catch (error) {
      const detail = error instanceof Error ? error.message : "The export could not be created.";
      setExportMessage({ tone: "error", text: `${format.toUpperCase()} export failed. ${detail}` });
    } finally {
      setExportBusy(null);
    }
  };

  return (
    <section className="results" aria-labelledby="results-heading">
      <ResultsToolbar
        scan={scan}
        onExport={handleExport}
        exportBusy={exportBusy}
        exportMessage={exportMessage}
      />
      <Summary scan={scan} />
      <CoverageNotice scan={scan} />

      {scan.limitations.length > 0 && (
        <div className="limitations" role="note">
          <Info aria-hidden="true" size={19} weight="fill" />
          <div>
            <strong>Scope note</strong>
            {scan.limitations.map((limitation) => <p key={limitation}>{limitation}</p>)}
          </div>
        </div>
      )}

      {orderedFindings.length === 0 ? (
        <ZeroResultState scan={scan} />
      ) : (
        <>
          <FindingFilters
            scan={scan}
            search={search}
            setSearch={setSearch}
            severity={severity}
            setSeverity={setSeverity}
          />
          <div className="evidence-workspace">
            <div className="finding-pane">
              <div className="pane-heading">
                <h3>Findings</h3>
                <span role="status" aria-live="polite">{filteredFindings.length} shown</span>
              </div>
              <FindingsList findings={filteredFindings} selectedId={selectedId} onSelect={handleSelect} />
            </div>
            <div id="finding-detail-pane" className="detail-pane" role="region" aria-label="Finding evidence">
              <p className="visually-hidden" role="status" aria-live="polite" aria-atomic="true">
                {selectedFinding ? `Showing details for ${selectedFinding.title}.` : "No finding selected."}
              </p>
              <FindingDetail finding={selectedFinding} />
            </div>
          </div>
        </>
      )}
    </section>
  );
}

export function App() {
  const [mode, setMode] = useState<ScanMode>("source");
  const [targets, setTargets] = useState<Record<ScanMode, string>>({ source: ".", url: "" });
  const [activeOperation, setActiveOperation] = useState<ScanOperation | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [scan, setScan] = useState<ScanResponse | null>(null);

  const loading = activeOperation !== null;
  const target = targets[mode];
  const setTarget = (value: string) => setTargets((current) => ({ ...current, [mode]: value }));

  const runScan = async (kind: ScanOperation, operation: () => Promise<ScanResponse>) => {
    setActiveOperation(kind);
    setError(null);
    try {
      const result = await operation();
      setScan(result);
      requestAnimationFrame(() => {
        const resultsHeading = document.getElementById("results-heading");
        const reduceMotion = window.matchMedia("(prefers-reduced-motion: reduce)").matches;
        resultsHeading?.focus({ preventScroll: true });
        resultsHeading?.scrollIntoView({ behavior: reduceMotion ? "auto" : "smooth", block: "start" });
      });
    } catch (scanError) {
      setError(scanError instanceof Error ? scanError.message : "The review could not be completed.");
    } finally {
      setActiveOperation(null);
    }
  };

  const handleSubmit = (event: FormEvent<HTMLFormElement>) => {
    event.preventDefault();
    const trimmedTarget = target.trim();
    if (!trimmedTarget) {
      setError(mode === "source" ? "Enter a project path." : "Enter a public website URL.");
      return;
    }
    void runScan(mode, () => (mode === "source" ? scanSource(trimmedTarget) : scanUrl(trimmedTarget)));
  };

  const handleDemo = () => void runScan("demo", scanDemo);

  return (
    <div className="app-shell">
      <a className="skip-link" href="#main-content">Skip to main content</a>
      <AppHeader />
      <main id="main-content" className="main-content">
        <section className="page-intro" aria-labelledby="page-title">
          <div>
            <p className="product-kicker">AI application security review</p>
            <h1 id="page-title">Trace every finding to evidence.</h1>
            <p>Review source code and public website surfaces with clear uncertainty, remediation, and verification steps.</p>
          </div>
          <div className="review-boundary" role="note" aria-label="Review boundary">
            <ShieldCheck aria-hidden="true" size={21} weight="duotone" />
            <p><strong>Decision support</strong> Automated checks help prioritize review. They do not replace a penetration test.</p>
          </div>
        </section>

        <ScanComposer
          mode={mode}
          setMode={(nextMode) => {
            setMode(nextMode);
            setError(null);
          }}
          target={target}
          setTarget={setTarget}
          loading={loading}
          onSubmit={handleSubmit}
          onDemo={handleDemo}
          error={error}
        />

        {activeOperation ? (
          <LoadingState operation={activeOperation} />
        ) : scan ? (
          <ResultsView scan={scan} />
        ) : (
          <IdleState onDemo={handleDemo} />
        )}
      </main>
      <footer className="app-footer">
        <p>Patchwork Sentinel performs bounded, read-only checks and reports uncertainty honestly.</p>
        <a href="/docs">API documentation</a>
      </footer>
    </div>
  );
}
