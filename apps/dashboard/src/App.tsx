import { FormEvent, KeyboardEvent, useEffect, useId, useMemo, useRef, useState } from "react";
import {
  ArrowDown,
  ArrowRight,
  ArrowUp,
  Brain,
  CalendarBlank,
  ChartLine,
  ChartLineUp,
  CheckCircle,
  Clock,
  Code,
  Database,
  DownloadSimple,
  FileText,
  Files,
  Flask,
  FolderOpen,
  GlobeSimple,
  Info,
  LockKey,
  MagnifyingGlass,
  Minus,
  ShieldCheck,
  Target,
  TestTube,
  Warning,
  WarningOctagon,
  Wrench,
} from "@phosphor-icons/react";
import { analyzeStock, downloadExport, scanDemo, scanSource, scanUrl, stockDemo } from "./api";
import type {
  FactorDirection,
  ScanResponse,
  SecurityFinding,
  Severity,
  StockAnalysisResponse,
  StockOpinion,
} from "./types";

type Product = "sentinel" | "signallab";
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

function AppHeader({
  product,
  onProductChange,
}: {
  product: Product;
  onProductChange: (product: Product) => void;
}) {
  const sentinelRef = useRef<HTMLButtonElement>(null);
  const signalLabRef = useRef<HTMLButtonElement>(null);

  const selectProduct = (nextProduct: Product, moveFocus = false) => {
    onProductChange(nextProduct);
    if (moveFocus) {
      (nextProduct === "sentinel" ? sentinelRef.current : signalLabRef.current)?.focus();
    }
  };

  const handleProductKeyDown = (event: KeyboardEvent<HTMLButtonElement>) => {
    let nextProduct: Product | null = null;
    if (event.key === "ArrowLeft" || event.key === "ArrowRight") {
      nextProduct = product === "sentinel" ? "signallab" : "sentinel";
    } else if (event.key === "Home") {
      nextProduct = "sentinel";
    } else if (event.key === "End") {
      nextProduct = "signallab";
    }
    if (!nextProduct) return;
    event.preventDefault();
    selectProduct(nextProduct, true);
  };

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
        <nav className="product-navigation" aria-label="Patchwork tools">
          <button
            ref={sentinelRef}
            type="button"
            aria-current={product === "sentinel" ? "page" : undefined}
            onClick={() => selectProduct("sentinel")}
            onKeyDown={handleProductKeyDown}
          >
            <ShieldCheck aria-hidden="true" size={17} weight="duotone" />
            <span>Sentinel</span>
          </button>
          <button
            ref={signalLabRef}
            type="button"
            aria-current={product === "signallab" ? "page" : undefined}
            onClick={() => selectProduct("signallab")}
            onKeyDown={handleProductKeyDown}
          >
            <ChartLineUp aria-hidden="true" size={17} weight="duotone" />
            <span>SignalLab</span>
          </button>
        </nav>
        <div className="safety-note">
          {product === "sentinel" ? (
            <LockKey aria-hidden="true" size={17} weight="duotone" />
          ) : (
            <Info aria-hidden="true" size={17} weight="duotone" />
          )}
          {product === "sentinel" ? "Passive by default" : "Research, not advice"}
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

type StockOperation = "analysis" | "demo";

const opinionLabels: Record<StockOpinion, string> = {
  bullish: "Bullish",
  neutral: "Neutral",
  bearish: "Bearish",
};
const tickerPattern = /^[A-Z0-9][A-Z0-9._-]{0,15}$/;
const syntheticDemoInputs = {
  symbol: "SYNTH_A",
  benchmark: "SYNTH_MKT",
  horizonDays: 20,
} as const;

function formatPercent(value: number, digits = 1): string {
  return `${(value * 100).toFixed(digits)}%`;
}

function formatCount(value: number): string {
  return new Intl.NumberFormat().format(value);
}

function formatDateOnly(value: string): string {
  const date = new Date(`${value}T00:00:00Z`);
  if (Number.isNaN(date.getTime())) return value;
  return new Intl.DateTimeFormat(undefined, {
    dateStyle: "medium",
    timeZone: "UTC",
  }).format(date);
}

function OpinionGlyph({ opinion, size = 18 }: { opinion: StockOpinion; size?: number }) {
  if (opinion === "bullish") return <ArrowUp aria-hidden="true" size={size} weight="bold" />;
  if (opinion === "bearish") return <ArrowDown aria-hidden="true" size={size} weight="bold" />;
  return <Minus aria-hidden="true" size={size} weight="bold" />;
}

function DirectionGlyph({ direction }: { direction: FactorDirection }) {
  if (direction === "positive") return <ArrowUp aria-hidden="true" size={14} weight="bold" />;
  if (direction === "negative") return <ArrowDown aria-hidden="true" size={14} weight="bold" />;
  return <Minus aria-hidden="true" size={14} weight="bold" />;
}

function StockComposer({
  csvPath,
  setCsvPath,
  symbol,
  setSymbol,
  benchmark,
  setBenchmark,
  horizonDays,
  setHorizonDays,
  loading,
  onSubmit,
  onDemo,
  error,
}: {
  csvPath: string;
  setCsvPath: (value: string) => void;
  symbol: string;
  setSymbol: (value: string) => void;
  benchmark: string;
  setBenchmark: (value: string) => void;
  horizonDays: number | "";
  setHorizonDays: (value: number | "") => void;
  loading: boolean;
  onSubmit: (event: FormEvent<HTMLFormElement>) => void;
  onDemo: () => void;
  error: string | null;
}) {
  const csvId = useId();
  const symbolId = useId();
  const benchmarkId = useId();
  const horizonId = useId();
  const helperId = useId();
  const errorId = useId();

  return (
    <section className="stock-composer" aria-labelledby="stock-composer-heading">
      <div className="composer-heading stock-composer-heading">
        <div>
          <h2 id="stock-composer-heading">Analyze price history</h2>
          <p>Use a server-local CSV, or start with reproducible synthetic data.</p>
        </div>
        <button className="button button-secondary" type="button" onClick={onDemo} disabled={loading}>
          <Flask aria-hidden="true" size={18} />
          Load synthetic sample
        </button>
      </div>

      <form className="stock-form" onSubmit={onSubmit} noValidate>
        <div className="stock-field stock-field-path">
          <label htmlFor={csvId}>Server-local CSV path</label>
          <div className="input-shell">
            <Database aria-hidden="true" size={19} />
            <input
              id={csvId}
              type="text"
              value={csvPath}
              onChange={(event) => setCsvPath(event.target.value)}
              placeholder="/workspace/data/prices.csv"
              aria-describedby={`${helperId}${error ? ` ${errorId}` : ""}`}
              aria-invalid={Boolean(error)}
              autoComplete="off"
              spellCheck={false}
              disabled={loading}
            />
          </div>
        </div>

        <div className="stock-form-row">
          <div className="stock-field">
            <label htmlFor={symbolId}>Symbol</label>
            <input
              id={symbolId}
              className="stock-text-input"
              type="text"
              value={symbol}
              onChange={(event) => setSymbol(event.target.value.toUpperCase())}
              placeholder="AAPL"
              maxLength={16}
              autoComplete="off"
              spellCheck={false}
              disabled={loading}
            />
          </div>
          <div className="stock-field">
            <label htmlFor={benchmarkId}>Benchmark</label>
            <input
              id={benchmarkId}
              className="stock-text-input"
              type="text"
              value={benchmark}
              onChange={(event) => setBenchmark(event.target.value.toUpperCase())}
              placeholder="SPY"
              maxLength={16}
              autoComplete="off"
              spellCheck={false}
              disabled={loading}
            />
          </div>
          <div className="stock-field">
            <label htmlFor={horizonId}>Horizon (trading days)</label>
            <input
              id={horizonId}
              className="stock-text-input"
              type="number"
              min={5}
              max={60}
              step={1}
              value={horizonDays}
              onChange={(event) => {
                const value = event.currentTarget.value;
                setHorizonDays(value === "" ? "" : event.currentTarget.valueAsNumber);
              }}
              disabled={loading}
            />
          </div>
          <button
            className="button button-primary stock-analyze-button"
            type="submit"
            disabled={loading || !csvPath.trim() || !symbol.trim() || !benchmark.trim()}
          >
            {loading ? "Analyzing..." : "Analyze"}
            {!loading && <ArrowRight aria-hidden="true" size={18} weight="bold" />}
          </button>
        </div>

        <p id={helperId} className="field-helper stock-helper">
          The API reads the path on the server. The model estimates relative performance against {benchmark || "the benchmark"}; it does not predict a guaranteed return.
        </p>
        {error && (
          <p id={errorId} className="field-error" role="alert">
            <WarningOctagon aria-hidden="true" size={17} weight="fill" />
            {error} {" "}
            <span>{"A previous result remains below when available."}</span>
          </p>
        )}
      </form>
    </section>
  );
}

function StockLoadingState({ operation }: { operation: StockOperation }) {
  return (
    <section className="loading-state stock-loading" aria-live="polite" aria-busy="true">
      <div className="loading-copy">
        <span className="loading-icon" aria-hidden="true">
          <Brain size={22} weight="duotone" />
        </span>
        <div>
          <h2>{operation === "demo" ? "Preparing synthetic research" : "Evaluating market factors"}</h2>
          <p>Training evidence and held-out metrics will be shown with the opinion.</p>
        </div>
      </div>
      <div className="stock-skeleton" aria-hidden="true">
        <span />
        <span />
        <span />
        <span />
        <span />
      </div>
    </section>
  );
}

function StockIdleState({ onDemo }: { onDemo: () => void }) {
  return (
    <section className="stock-idle" aria-labelledby="stock-idle-heading">
      <div className="idle-icon" aria-hidden="true">
        <ChartLine size={30} weight="duotone" />
      </div>
      <div className="idle-content">
        <h2 id="stock-idle-heading">An opinion you can inspect</h2>
        <p>
          SignalLab reports an outperformance probability, the factors behind it, and held-out test metrics so you can judge the model—not just its label.
        </p>
        <button className="text-button" type="button" onClick={onDemo}>
          Explore synthetic sample data
          <ArrowRight aria-hidden="true" size={17} weight="bold" />
        </button>
      </div>
      <div className="research-sequence" aria-label="Research output includes">
        <span><Target aria-hidden="true" size={19} />Probability</span>
        <span><Brain aria-hidden="true" size={19} />Factor evidence</span>
        <span><ChartLine aria-hidden="true" size={19} />Held-out metrics</span>
      </div>
    </section>
  );
}

function StockAnalysisView({ analysis }: { analysis: StockAnalysisResponse }) {
  const evaluation = analysis.model.evaluation;
  const metrics = [
    { label: "Accuracy", value: formatPercent(evaluation.accuracy) },
    { label: "Balanced accuracy", value: formatPercent(evaluation.balanced_accuracy) },
    { label: "ROC AUC", value: evaluation.roc_auc == null ? "Unavailable" : evaluation.roc_auc.toFixed(3) },
    { label: "Brier score", value: evaluation.brier_score.toFixed(3) },
    { label: "Constant baseline", value: evaluation.constant_brier.toFixed(3) },
    { label: "Positive base rate", value: formatPercent(evaluation.base_rate) },
    { label: "Effective windows", value: formatCount(evaluation.effective_windows) },
  ];

  return (
    <section className="stock-results" aria-labelledby="stock-results-heading">
      <header className="stock-result-header">
        <div>
          <div className="stock-result-title-line">
            <h2 id="stock-results-heading" tabIndex={-1}>Research opinion for {analysis.symbol}</h2>
            {analysis.sample_data && <span className="sample-label">Synthetic sample</span>}
          </div>
          <p>
            Compared with {analysis.benchmark} over {analysis.horizon_days} trading days, using data through {formatDateOnly(analysis.as_of)}.
          </p>
        </div>
        <span className="analysis-id">Analysis {analysis.id}</span>
      </header>

      <div className="investment-disclaimer" role="note" aria-label="Investment disclaimer">
        <Warning aria-hidden="true" size={21} weight="fill" />
        <div>
          <strong>Research output—not financial advice</strong>
          <p>{analysis.disclaimer}</p>
        </div>
      </div>

      <div className="opinion-overview">
        <div className={`opinion-block opinion-${analysis.opinion}`}>
          <span className="opinion-label"><OpinionGlyph opinion={analysis.opinion} />Model opinion</span>
          <strong>{opinionLabels[analysis.opinion]}</strong>
          <span>{analysis.confidence} evidence strength</span>
        </div>
        <div className="probability-block">
          <span>Estimated probability of outperforming {analysis.benchmark}</span>
          <strong>{formatPercent(analysis.probability_outperform)}</strong>
          <p>Calibrated model estimate for the stated horizon, not a promised outcome.</p>
        </div>
        <dl className="research-context">
          <div>
            <dt><CalendarBlank aria-hidden="true" size={15} />As of</dt>
            <dd>{formatDateOnly(analysis.as_of)}</dd>
          </div>
          <div>
            <dt><Target aria-hidden="true" size={15} />Horizon</dt>
            <dd>{analysis.horizon_days} trading days</dd>
          </div>
          <div>
            <dt><ChartLine aria-hidden="true" size={15} />Benchmark</dt>
            <dd>{analysis.benchmark}</dd>
          </div>
        </dl>
      </div>

      <div className="stock-result-section factor-section">
        <div className="stock-section-heading">
          <div>
            <h3>Factor evidence</h3>
            <p>Inputs that influenced this specific opinion. Direction is always written, not communicated by color alone.</p>
          </div>
          <span>{analysis.rationale.length} factors</span>
        </div>
        {analysis.rationale.length > 0 ? (
          <ol className="factor-list">
            {analysis.rationale.map((factor) => (
              <li key={factor.feature}>
                <div className="factor-name">
                  <strong>{factor.label}</strong>
                  <code>{factor.feature}</code>
                </div>
                <span className="factor-value">{factor.value.toFixed(4)}</span>
                <span className={`direction-label direction-${factor.direction}`}>
                  <DirectionGlyph direction={factor.direction} />
                  {factor.direction}
                </span>
                <p>{factor.explanation}</p>
              </li>
            ))}
          </ol>
        ) : (
          <p className="stock-empty-copy">No factor rationale was returned for this analysis.</p>
        )}
      </div>

      <div className="stock-result-section model-section">
        <div className="stock-section-heading">
          <div>
            <h3>Held-out test evaluation</h3>
            <p>These metrics do not fit the model or calibrate its probabilities; they conservatively gate how the opinion is presented.</p>
          </div>
          <span>{formatCount(evaluation.samples)} labeled rows</span>
        </div>
        <dl className="evaluation-metrics" aria-label="Held-out model metrics">
          {metrics.map((metric) => (
            <div key={metric.label}>
              <dt>{metric.label}</dt>
              <dd>{metric.value}</dd>
            </div>
          ))}
        </dl>
        <div className="model-provenance">
          <div>
            <span>Test period</span>
            <strong>{formatDateOnly(evaluation.test_start)} – {formatDateOnly(evaluation.test_end)}</strong>
          </div>
          <div>
            <span>Model</span>
            <strong>{analysis.model.name} v{analysis.model.version}</strong>
          </div>
          <div>
            <span>Training cutoff</span>
            <strong>{formatDateOnly(analysis.model.trained_through)}</strong>
          </div>
          <div>
            <span>Training scope</span>
            <strong>{formatCount(analysis.model.training_rows)} rows · {analysis.model.feature_count} features</strong>
          </div>
          <div className="model-symbols">
            <span>Training symbols</span>
            <strong>{analysis.model.symbols.join(", ")}</strong>
          </div>
        </div>
      </div>

      <div className="stock-result-section limitation-section">
        <h3>Limitations to consider</h3>
        {analysis.limitations.length > 0 ? (
          <ul>
            {analysis.limitations.map((limitation) => <li key={limitation}>{limitation}</li>)}
          </ul>
        ) : (
          <p>No additional limitations were returned. General model and market uncertainty still apply.</p>
        )}
      </div>
    </section>
  );
}

function SignalLab() {
  const [csvPath, setCsvPath] = useState("");
  const [symbol, setSymbol] = useState("STOCK");
  const [benchmark, setBenchmark] = useState("SPY");
  const [horizonDays, setHorizonDays] = useState<number | "">(20);
  const [activeOperation, setActiveOperation] = useState<StockOperation | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [analysis, setAnalysis] = useState<StockAnalysisResponse | null>(null);

  const loading = activeOperation !== null;
  const normalizedInputs = () => ({
    symbol: symbol.trim().toUpperCase(),
    benchmark: benchmark.trim().toUpperCase(),
    horizonDays: Number(horizonDays),
  });

  const runAnalysis = async (
    kind: StockOperation,
    operation: () => Promise<StockAnalysisResponse>,
  ) => {
    setActiveOperation(kind);
    setError(null);
    try {
      const result = await operation();
      setAnalysis(result);
      requestAnimationFrame(() => {
        const heading = document.getElementById("stock-results-heading");
        const reduceMotion = window.matchMedia("(prefers-reduced-motion: reduce)").matches;
        heading?.focus({ preventScroll: true });
        heading?.scrollIntoView({ behavior: reduceMotion ? "auto" : "smooth", block: "start" });
      });
    } catch (analysisError) {
      setError(analysisError instanceof Error ? analysisError.message : "The stock analysis could not be completed.");
    } finally {
      setActiveOperation(null);
    }
  };

  const validateInputs = (requirePath: boolean): boolean => {
    if (requirePath && !csvPath.trim()) {
      setError("Enter a server-local CSV path.");
      return false;
    }
    const normalizedSymbol = symbol.trim().toUpperCase();
    const normalizedBenchmark = benchmark.trim().toUpperCase();
    if (!tickerPattern.test(normalizedSymbol) || !tickerPattern.test(normalizedBenchmark)) {
      setError("Use a 1–16 character ticker with letters, numbers, dots, underscores, or hyphens.");
      return false;
    }
    const parsedHorizon = Number(horizonDays);
    if (!Number.isInteger(parsedHorizon) || parsedHorizon < 5 || parsedHorizon > 60) {
      setError("Choose a horizon from 5 to 60 trading days.");
      return false;
    }
    return true;
  };

  const handleSubmit = (event: FormEvent<HTMLFormElement>) => {
    event.preventDefault();
    if (!validateInputs(true)) return;
    void runAnalysis("analysis", () => analyzeStock({ csvPath: csvPath.trim(), ...normalizedInputs() }));
  };

  const handleDemo = () => {
    void runAnalysis("demo", () => stockDemo(syntheticDemoInputs));
  };

  return (
    <>
      <section className="page-intro stock-intro" aria-labelledby="page-title">
        <div>
          <p className="product-kicker">Transparent ML stock research</p>
          <h1 id="page-title">Inspect the opinion, evidence, and test.</h1>
          <p>Estimate relative performance with calibrated probabilities, factor-level rationale, and visible held-out evaluation.</p>
        </div>
        <div className="review-boundary" role="note" aria-label="Research boundary">
          <Info aria-hidden="true" size={21} weight="duotone" />
          <p><strong>Decision support</strong> Historical patterns can fail when markets change. SignalLab does not provide investment advice.</p>
        </div>
      </section>

      <StockComposer
        csvPath={csvPath}
        setCsvPath={setCsvPath}
        symbol={symbol}
        setSymbol={setSymbol}
        benchmark={benchmark}
        setBenchmark={setBenchmark}
        horizonDays={horizonDays}
        setHorizonDays={setHorizonDays}
        loading={loading}
        onSubmit={handleSubmit}
        onDemo={handleDemo}
        error={error}
      />

      {activeOperation ? (
        <StockLoadingState operation={activeOperation} />
      ) : analysis ? (
        <StockAnalysisView analysis={analysis} />
      ) : (
        <StockIdleState onDemo={handleDemo} />
      )}
    </>
  );
}

export function App() {
  const [product, setProduct] = useState<Product>("sentinel");
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
      <AppHeader product={product} onProductChange={setProduct} />
      <main id="main-content" className="main-content">
        {product === "sentinel" ? (
          <>
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
          </>
        ) : (
          <SignalLab />
        )}
      </main>
      <footer className="app-footer">
        <p>
          {product === "sentinel"
            ? "Patchwork Sentinel performs bounded, read-only checks and reports uncertainty honestly."
            : "Patchwork SignalLab reports probabilistic research with model evidence and explicit limitations."}
        </p>
        <a href="/docs">API documentation</a>
      </footer>
    </div>
  );
}
