import { act, render, screen, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { axe } from "jest-axe";
import { beforeEach, describe, expect, it, vi } from "vitest";
import { App } from "./App";
import { analyzeStock, downloadExport, scanDemo, scanSource, stockDemo } from "./api";
import type {
  ScanResponse,
  SecurityFinding,
  Severity,
  StockAnalysisResponse,
} from "./types";

vi.mock("./api", () => ({
  analyzeStock: vi.fn(),
  downloadExport: vi.fn(),
  scanDemo: vi.fn(),
  scanSource: vi.fn(),
  scanUrl: vi.fn(),
  stockDemo: vi.fn(),
}));

const mockedAnalyzeStock = vi.mocked(analyzeStock);
const mockedDownloadExport = vi.mocked(downloadExport);
const mockedScanDemo = vi.mocked(scanDemo);
const mockedScanSource = vi.mocked(scanSource);
const mockedStockDemo = vi.mocked(stockDemo);

const severityValues: Severity[] = ["critical", "high", "medium", "low", "info"];

function finding(id: string, severity: Severity, title: string): SecurityFinding {
  return {
    id,
    rule_id: `AISEC-${id.toUpperCase()}`,
    title,
    severity,
    confidence: severity === "critical" ? "confirmed" : "high",
    category: "Test category",
    description: `${title} description`,
    impact: `${title} impact`,
    location: { path: `src/${id}.py`, line: 12 },
    evidence: [{ label: "Observed", value: `${title} evidence` }],
    remediation: `${title} remediation`,
    verification: `${title} verification`,
    references: [],
    status: "open",
  };
}

function scanResponse(
  overrides: Partial<ScanResponse> & Pick<Partial<ScanResponse>, "findings"> = {},
): ScanResponse {
  const findings = overrides.findings ?? [];
  const counts = Object.fromEntries(
    severityValues.map((severity) => [
      severity,
      findings.filter((item) => item.severity === severity).length,
    ]),
  ) as Record<Severity, number>;

  return {
    id: "scan-1",
    target_type: "source",
    target: "/workspace/project",
    status: "completed",
    started_at: "2026-07-18T12:00:00Z",
    completed_at: "2026-07-18T12:00:01Z",
    duration_ms: 1_000,
    summary: {
      total: findings.length,
      ...counts,
      confirmed: findings.filter((item) => item.confidence === "confirmed").length,
      checks_run: 12,
      files_scanned: 8,
    },
    coverage: {
      completeness: "complete",
      files_scanned: 8,
      pages_scanned: null,
      skipped: 0,
    },
    findings,
    limitations: [],
    metadata: {},
    ...overrides,
  };
}

function stockResponse(overrides: Partial<StockAnalysisResponse> = {}): StockAnalysisResponse {
  return {
    id: "stock-analysis-1",
    symbol: "SYNTH_A",
    benchmark: "SYNTH_MKT",
    as_of: "2026-06-30",
    horizon_days: 20,
    opinion: "bullish",
    probability_outperform: 0.637,
    confidence: "moderate",
    sample_data: false,
    rationale: [
      {
        feature: "relative_momentum_20d",
        label: "Relative momentum",
        value: 0.0472,
        direction: "positive",
        explanation: "The symbol recently outpaced its benchmark over the feature window.",
      },
      {
        feature: "volatility_20d",
        label: "Recent volatility",
        value: 0.212,
        direction: "negative",
        explanation: "Higher recent variability reduced the model estimate.",
      },
    ],
    limitations: ["Regime changes may make historical relationships unreliable."],
    disclaimer: "This experimental output is for research and education only. It is not financial advice.",
    model: {
      name: "SignalLab Gradient Boosting",
      version: "1.0.0",
      trained_through: "2025-12-31",
      training_rows: 12_400,
      symbols: ["SYNTH_A", "SYNTH_B"],
      feature_count: 9,
      evaluation: {
        test_start: "2026-01-01",
        test_end: "2026-06-30",
        samples: 842,
        effective_windows: 21,
        accuracy: 0.581,
        balanced_accuracy: 0.566,
        brier_score: 0.238,
        constant_brier: 0.25,
        roc_auc: 0.604,
        base_rate: 0.492,
      },
    },
    ...overrides,
  };
}

beforeEach(() => {
  vi.clearAllMocks();
  mockedDownloadExport.mockResolvedValue();
});

describe("Sentinel dashboard", () => {
  it("prefills the mounted workspace and implements the complete ARIA tab keyboard pattern", async () => {
    const user = userEvent.setup();
    render(<App />);

    const sourceTab = screen.getByRole("tab", { name: "Source repository" });
    const urlTab = screen.getByRole("tab", { name: "Public website" });
    expect(screen.getByRole("textbox", { name: "Project path" })).toHaveValue(".");

    sourceTab.focus();
    await user.keyboard("{ArrowRight}");
    expect(urlTab).toHaveFocus();
    expect(urlTab).toHaveAttribute("aria-selected", "true");

    await user.keyboard("{Home}");
    expect(sourceTab).toHaveFocus();
    expect(sourceTab).toHaveAttribute("aria-selected", "true");

    await user.keyboard("{End}");
    expect(urlTab).toHaveFocus();
    await user.keyboard("{ArrowLeft}");
    expect(sourceTab).toHaveFocus();
  });

  it("keeps loading language tied to the operation in flight", async () => {
    const user = userEvent.setup();
    let completeScan!: (scan: ScanResponse) => void;
    let completeDemo!: (scan: ScanResponse) => void;
    mockedScanSource.mockReturnValue(
      new Promise((resolve) => {
        completeScan = resolve;
      }),
    );
    mockedScanDemo.mockReturnValue(
      new Promise((resolve) => {
        completeDemo = resolve;
      }),
    );
    render(<App />);

    await user.click(screen.getByRole("button", { name: "Scan source" }));
    expect(screen.getByRole("heading", { name: "Reviewing source evidence" })).toBeInTheDocument();
    await user.click(screen.getByRole("tab", { name: "Public website" }));
    expect(screen.getByRole("heading", { name: "Reviewing source evidence" })).toBeInTheDocument();
    expect(screen.queryByRole("heading", { name: "Inspecting public responses" })).not.toBeInTheDocument();

    await act(async () => {
      completeScan(scanResponse());
    });
    expect(await screen.findByRole("heading", { name: "Review results" })).toBeInTheDocument();

    await user.click(screen.getByRole("button", { name: "Load sample" }));
    expect(screen.getByRole("heading", { name: "Preparing sample evidence" })).toBeInTheDocument();
    expect(screen.getByText("This sample is generated locally and is not a scan of your application.")).toBeInTheDocument();
    await act(async () => {
      completeDemo(scanResponse({ id: "demo-after-source", target_type: "demo" }));
    });
  });

  it("sorts findings by severity, preserves button semantics, and announces selection", async () => {
    const user = userEvent.setup();
    const high = finding("high-1", "high", "High-priority finding");
    const critical = finding("critical-1", "critical", "Critical finding");
    mockedScanDemo.mockResolvedValue(
      scanResponse({ id: "demo-scan", target_type: "demo", findings: [high, critical] }),
    );
    render(<App />);

    await user.click(screen.getByRole("button", { name: "Load sample" }));
    const list = await screen.findByRole("list", { name: "Security findings" });
    const rows = within(list).getAllByRole("button");
    expect(rows[0]).toHaveTextContent("Critical finding");
    expect(rows[0]).toHaveAttribute("aria-pressed", "true");
    expect(rows[1]).toHaveTextContent("High-priority finding");

    const detailPane = screen.getByRole("region", { name: "Finding evidence" });
    detailPane.scrollTop = 240;
    await user.click(rows[1]);
    expect(rows[1]).toHaveAttribute("aria-pressed", "true");
    expect(detailPane.scrollTop).toBe(0);
    expect(within(detailPane).getByRole("heading", {
      name: "High-priority finding",
    })).toBeInTheDocument();
    expect(screen.getByText("Showing details for High-priority finding.")).toBeInTheDocument();
  });

  it.each([
    {
      label: "failed",
      response: scanResponse({
        status: "failed",
        coverage: { completeness: "failed", files_scanned: 0, pages_scanned: null, skipped: 1 },
        limitations: ["The target could not be read."],
      }),
      heading: "No complete result was produced",
    },
    {
      label: "partial",
      response: scanResponse({
        status: "partial",
        coverage: { completeness: "partial", files_scanned: 8, pages_scanned: null, skipped: 3 },
        limitations: ["Three files were skipped."],
      }),
      heading: "No findings in the checked portion",
    },
    {
      label: "complete",
      response: scanResponse(),
      heading: "No findings in this review",
    },
  ])("renders a status-aware $label zero-result state", async ({ response, heading }) => {
    const user = userEvent.setup();
    mockedScanSource.mockResolvedValue(response);
    render(<App />);

    await user.click(screen.getByRole("button", { name: "Scan source" }));
    expect(await screen.findByRole("heading", { name: heading })).toBeInTheDocument();
  });

  it("reveals selected detail on mobile and provides clear export success and error feedback", async () => {
    const user = userEvent.setup();
    const first = finding("first", "high", "First finding");
    const second = finding("second", "medium", "Second finding");
    mockedScanDemo.mockResolvedValue(scanResponse({ target_type: "demo", findings: [first, second] }));
    vi.mocked(window.matchMedia).mockImplementation((query: string) => ({
      matches: query === "(max-width: 760px)",
      media: query,
      onchange: null,
      addListener: vi.fn(),
      removeListener: vi.fn(),
      addEventListener: vi.fn(),
      removeEventListener: vi.fn(),
      dispatchEvent: vi.fn(),
    }));
    const scrollSpy = vi.spyOn(Element.prototype, "scrollIntoView");
    render(<App />);

    await user.click(screen.getByRole("button", { name: "Load sample" }));
    const rows = within(await screen.findByRole("list", { name: "Security findings" })).getAllByRole("button");
    await user.click(rows[1]);
    await waitFor(() => expect(scrollSpy).toHaveBeenCalled());

    await user.click(screen.getByRole("button", { name: "Download JSON" }));
    expect(await screen.findByText("JSON downloaded.")).toHaveAttribute("role", "status");

    mockedDownloadExport.mockRejectedValueOnce(new Error("The server ended the request."));
    await user.click(screen.getByRole("button", { name: "Download SARIF" }));
    expect(await screen.findByRole("alert")).toHaveTextContent(
      "SARIF export failed. The server ended the request.",
    );
  });

  it("has no detectable axe violations in first-run and results states", async () => {
    const user = userEvent.setup();
    const sample = finding("sample", "critical", "Sample finding");
    mockedScanDemo.mockResolvedValue(scanResponse({ target_type: "demo", findings: [sample] }));
    const { container } = render(<App />);

    expect((await axe(container)).violations).toEqual([]);
    await user.click(screen.getByRole("button", { name: "Load sample" }));
    await screen.findByRole("heading", { name: "Review results" });
    expect((await axe(container)).violations).toEqual([]);
  });
});

describe("SignalLab dashboard", () => {
  it("exposes SignalLab as a top-level keyboard-navigable product and keeps stock modes out of Sentinel tabs", async () => {
    const user = userEvent.setup();
    render(<App />);

    const sentinel = screen.getByRole("button", { name: "Sentinel" });
    const signalLab = screen.getByRole("button", { name: "SignalLab" });
    expect(sentinel).toHaveAttribute("aria-current", "page");
    expect(screen.getAllByRole("tab")).toHaveLength(2);

    sentinel.focus();
    await user.keyboard("{ArrowRight}");
    expect(signalLab).toHaveFocus();
    expect(signalLab).toHaveAttribute("aria-current", "page");
    expect(screen.getByRole("heading", { name: "Inspect the opinion, evidence, and test." })).toBeInTheDocument();
    expect(screen.queryAllByRole("tab")).toHaveLength(0);
    expect(screen.getByRole("textbox", { name: "Benchmark" })).toHaveValue("SPY");
    expect(screen.getByRole("textbox", { name: "Symbol" })).toHaveValue("STOCK");
    expect(screen.getByRole("spinbutton", { name: "Horizon (trading days)" })).toHaveValue(20);

    await user.keyboard("{Home}");
    expect(sentinel).toHaveFocus();
    expect(screen.getByRole("heading", { name: "Trace every finding to evidence." })).toBeInTheDocument();

    await user.keyboard("{End}");
    expect(signalLab).toHaveFocus();
    expect(screen.getByRole("heading", { name: "Analyze price history" })).toBeInTheDocument();
  });

  it("submits a server-local CSV and presents transparent opinion evidence and untouched metrics", async () => {
    const user = userEvent.setup();
    let completeAnalysis!: (analysis: StockAnalysisResponse) => void;
    mockedAnalyzeStock.mockReturnValue(
      new Promise((resolve) => {
        completeAnalysis = resolve;
      }),
    );
    render(<App />);

    await user.click(screen.getByRole("button", { name: "SignalLab" }));
    await user.type(screen.getByRole("textbox", { name: "Server-local CSV path" }), "/workspace/data/prices.csv");
    await user.clear(screen.getByRole("textbox", { name: "Symbol" }));
    await user.type(screen.getByRole("textbox", { name: "Symbol" }), "msft");
    await user.click(screen.getByRole("button", { name: "Analyze" }));

    expect(mockedAnalyzeStock).toHaveBeenCalledWith({
      csvPath: "/workspace/data/prices.csv",
      symbol: "MSFT",
      benchmark: "SPY",
      horizonDays: 20,
    });
    expect(screen.getByRole("heading", { name: "Evaluating market factors" })).toBeInTheDocument();

    await act(async () => completeAnalysis(stockResponse({ symbol: "MSFT", benchmark: "SPY" })));
    expect(await screen.findByRole("heading", { name: "Research opinion for MSFT" })).toBeInTheDocument();
    expect(screen.getByText("Bullish")).toBeInTheDocument();
    expect(screen.getByText("63.7%")).toBeInTheDocument();
    expect(screen.getByText("moderate evidence strength")).toBeInTheDocument();
    expect(screen.getByText("Relative momentum")).toBeInTheDocument();
    expect(screen.getByText("positive")).toBeInTheDocument();
    expect(screen.getByText("Balanced accuracy").nextSibling).toHaveTextContent("56.6%");
    expect(screen.getByText("ROC AUC").nextSibling).toHaveTextContent("0.604");
    expect(screen.getByText("Constant baseline").nextSibling).toHaveTextContent("0.250");
    expect(screen.getByText("Effective windows").nextSibling).toHaveTextContent("21");
    expect(screen.getByText("Regime changes may make historical relationships unreliable.")).toBeInTheDocument();
    expect(screen.getByRole("note", { name: "Investment disclaimer" })).toHaveTextContent("not financial advice");
  });

  it("loads the synthetic sample separately and labels it without pretending it is live market evidence", async () => {
    const user = userEvent.setup();
    mockedStockDemo.mockResolvedValue(stockResponse({ sample_data: true }));
    render(<App />);

    await user.click(screen.getByRole("button", { name: "SignalLab" }));
    await user.click(screen.getByRole("button", { name: "Load synthetic sample" }));

    expect(mockedStockDemo).toHaveBeenCalledWith({
      symbol: "SYNTH_A",
      benchmark: "SYNTH_MKT",
      horizonDays: 20,
    });
    expect(await screen.findByText("Synthetic sample")).toBeInTheDocument();
    expect(screen.getByRole("heading", { name: "Research opinion for SYNTH_A" })).toBeInTheDocument();
  });

  it("keeps the prior analysis visible and announces an inline error when a refresh fails", async () => {
    const user = userEvent.setup();
    mockedStockDemo.mockResolvedValue(stockResponse());
    mockedAnalyzeStock.mockRejectedValue(new Error("The CSV could not be read by the server."));
    render(<App />);

    await user.click(screen.getByRole("button", { name: "SignalLab" }));
    await user.click(screen.getByRole("button", { name: "Load synthetic sample" }));
    expect(await screen.findByRole("heading", { name: "Research opinion for SYNTH_A" })).toBeInTheDocument();

    await user.type(screen.getByRole("textbox", { name: "Server-local CSV path" }), "/workspace/missing.csv");
    await user.click(screen.getByRole("button", { name: "Analyze" }));

    expect(await screen.findByRole("alert")).toHaveTextContent("The CSV could not be read by the server.");
    expect(screen.getByRole("heading", { name: "Research opinion for SYNTH_A" })).toBeInTheDocument();
    expect(screen.getByText("63.7%")).toBeInTheDocument();
  });

  it("has no detectable axe violations in SignalLab form and result states", async () => {
    const user = userEvent.setup();
    mockedStockDemo.mockResolvedValue(stockResponse({ sample_data: true }));
    const { container } = render(<App />);

    await user.click(screen.getByRole("button", { name: "SignalLab" }));
    expect((await axe(container)).violations).toEqual([]);
    await user.click(screen.getByRole("button", { name: "Load synthetic sample" }));
    await screen.findByRole("heading", { name: "Research opinion for SYNTH_A" });
    expect((await axe(container)).violations).toEqual([]);
  });
});
