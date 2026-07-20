export type Severity = "critical" | "high" | "medium" | "low" | "info";
export type TargetType = "source" | "url" | "demo";
export type ScanStatus = "completed" | "partial" | "failed";
export type ScanCompleteness = "complete" | "partial" | "failed";

export interface EvidenceItem {
  label: string;
  value: string;
  code?: string | null;
}

export interface FindingLocation {
  path?: string | null;
  url?: string | null;
  line?: number | null;
  column?: number | null;
  endpoint?: string | null;
}

export interface SecurityFinding {
  id: string;
  rule_id: string;
  title: string;
  severity: Severity;
  confidence: string;
  category: string;
  description: string;
  impact: string;
  location: FindingLocation;
  evidence: EvidenceItem[];
  remediation: string;
  verification: string;
  references: string[];
  cwe?: string | null;
  status: "open" | "accepted" | "resolved";
}

export interface ScanSummary {
  total: number;
  critical: number;
  high: number;
  medium: number;
  low: number;
  info: number;
  confirmed: number;
  checks_run?: number | null;
  files_scanned?: number | null;
  pages_scanned?: number | null;
  skipped?: number | null;
}

export interface ScanCoverage {
  completeness: ScanCompleteness;
  files_scanned?: number | null;
  pages_scanned?: number | null;
  skipped?: number | null;
}

export interface ScanResponse {
  id: string;
  target_type: TargetType;
  target: string;
  status: ScanStatus;
  started_at: string;
  completed_at: string;
  duration_ms: number;
  summary: ScanSummary;
  coverage: ScanCoverage;
  findings: SecurityFinding[];
  limitations: string[];
  metadata: Record<string, unknown>;
}

export type StockOpinion = "bullish" | "neutral" | "bearish";
export type StockConfidence = "low" | "moderate" | "high";
export type FactorDirection = "positive" | "negative" | "neutral";

export interface StockRationale {
  feature: string;
  label: string;
  value: number;
  direction: FactorDirection;
  explanation: string;
}

export interface StockModelEvaluation {
  test_start: string;
  test_end: string;
  samples: number;
  effective_windows: number;
  accuracy: number;
  balanced_accuracy: number;
  brier_score: number;
  constant_brier: number;
  roc_auc: number | null;
  base_rate: number;
}

export interface StockModelDetails {
  name: string;
  version: string;
  trained_through: string;
  training_rows: number;
  symbols: string[];
  feature_count: number;
  evaluation: StockModelEvaluation;
}

export interface StockAnalysisResponse {
  id: string;
  symbol: string;
  benchmark: string;
  as_of: string;
  horizon_days: number;
  opinion: StockOpinion;
  probability_outperform: number;
  confidence: StockConfidence;
  sample_data: boolean;
  rationale: StockRationale[];
  limitations: string[];
  disclaimer: string;
  model: StockModelDetails;
}

export interface StockAnalysisRequest {
  csvPath: string;
  symbol: string;
  benchmark: string;
  horizonDays: number;
}

export interface StockDemoRequest {
  symbol: string;
  benchmark: string;
  horizonDays: number;
}
