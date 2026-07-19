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
