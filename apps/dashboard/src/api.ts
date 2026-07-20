import type {
  ScanResponse,
  StockAnalysisRequest,
  StockAnalysisResponse,
  StockDemoRequest,
} from "./types";

const API_BASE = (import.meta.env.VITE_API_BASE_URL ?? "").replace(/\/$/, "");

interface ApiErrorBody {
  detail?: string | Array<{ msg?: string }>;
}

async function request<T>(path: string, init?: RequestInit): Promise<T> {
  let response: Response;
  try {
    response = await fetch(`${API_BASE}${path}`, {
      ...init,
      headers: {
        Accept: "application/json",
        ...(init?.body ? { "Content-Type": "application/json" } : {}),
        ...init?.headers,
      },
    });
  } catch {
    throw new Error("Could not reach the Patchwork API. Confirm that the server is running.");
  }

  if (!response.ok) {
    let body: ApiErrorBody = {};
    try {
      body = (await response.json()) as ApiErrorBody;
    } catch {
      // The fallback below is intentionally plain and safe for non-JSON proxies.
    }
    const detail = Array.isArray(body.detail)
      ? body.detail.map((item) => item.msg).filter(Boolean).join(" ")
      : body.detail;
    throw new Error(detail || `The request failed with status ${response.status}.`);
  }

  return (await response.json()) as T;
}

export function scanSource(path: string): Promise<ScanResponse> {
  return request<ScanResponse>("/api/scans/source", {
    method: "POST",
    body: JSON.stringify({ path }),
  });
}

export function scanUrl(url: string): Promise<ScanResponse> {
  return request<ScanResponse>("/api/scans/url", {
    method: "POST",
    body: JSON.stringify({ url }),
  });
}

export function scanDemo(): Promise<ScanResponse> {
  return request<ScanResponse>("/api/scans/demo", { method: "POST" });
}

export function analyzeStock(input: StockAnalysisRequest): Promise<StockAnalysisResponse> {
  return request<StockAnalysisResponse>("/api/stocks/analyze", {
    method: "POST",
    body: JSON.stringify({
      data_path: input.csvPath,
      symbol: input.symbol,
      benchmark: input.benchmark,
      horizon_days: input.horizonDays,
    }),
  });
}

export function stockDemo(input: StockDemoRequest): Promise<StockAnalysisResponse> {
  return request<StockAnalysisResponse>("/api/stocks/demo", {
    method: "POST",
    body: JSON.stringify({
      symbol: input.symbol,
      benchmark: input.benchmark,
      horizon_days: input.horizonDays,
    }),
  });
}

export async function downloadExport(scanId: string, format: "json" | "sarif"): Promise<void> {
  let response: Response;
  try {
    response = await fetch(`${API_BASE}/api/scans/${scanId}/export/${format}`, {
      headers: { Accept: format === "sarif" ? "application/sarif+json" : "application/json" },
    });
  } catch {
    throw new Error("Could not reach the Patchwork API. Confirm that the server is running.");
  }
  if (!response.ok) {
    throw new Error(`The ${format.toUpperCase()} export could not be created.`);
  }
  const blob = await response.blob();
  const downloadUrl = URL.createObjectURL(blob);
  const anchor = document.createElement("a");
  anchor.href = downloadUrl;
  anchor.download = `patchwork-${scanId}.${format === "sarif" ? "sarif" : "json"}`;
  document.body.append(anchor);
  anchor.click();
  anchor.remove();
  URL.revokeObjectURL(downloadUrl);
}
