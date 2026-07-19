# ruff: noqa: UP006, UP035, UP045 -- Retain Python 3.9-compatible typing syntax.
"""Stable data structures shared by the AI security scanners and reporters."""

from __future__ import annotations

import hashlib
from collections.abc import Mapping
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Dict, List, Optional

from patchwork_common import __version__


class Severity(str, Enum):
    """Finding impact, ordered from informational to critical."""

    INFO = "info"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class Confidence(str, Enum):
    """How strongly the observed evidence supports a finding."""

    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"


class ScanCompleteness(str, Enum):
    """Whether the configured scan surface was fully evaluated."""

    COMPLETE = "complete"
    PARTIAL = "partial"
    FAILED = "failed"


SEVERITY_RANK = {
    Severity.INFO: 0,
    Severity.LOW: 1,
    Severity.MEDIUM: 2,
    Severity.HIGH: 3,
    Severity.CRITICAL: 4,
}


@dataclass(frozen=True)
class Location:
    """A source-file or URL location associated with a finding."""

    uri: str
    line: Optional[int] = None
    column: Optional[int] = None
    end_line: Optional[int] = None

    def to_dict(self) -> Dict[str, Any]:
        result: Dict[str, Any] = {"uri": self.uri}
        if self.line is not None:
            result["line"] = self.line
        if self.column is not None:
            result["column"] = self.column
        if self.end_line is not None:
            result["end_line"] = self.end_line
        return result


@dataclass(frozen=True)
class Rule:
    """Metadata describing one deterministic scanner rule."""

    rule_id: str
    title: str
    description: str
    severity: Severity
    confidence: Confidence
    category: str
    impact: str
    remediation: str
    verification: str
    references: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "id": self.rule_id,
            "title": self.title,
            "description": self.description,
            "severity": self.severity.value,
            "confidence": self.confidence.value,
            "category": self.category,
            "impact": self.impact,
            "remediation": self.remediation,
            "verification": self.verification,
            "references": list(self.references),
        }


@dataclass
class Finding:
    """Evidence emitted when a rule matches a target."""

    rule_id: str
    title: str
    description: str
    severity: Severity
    confidence: Confidence
    category: str
    location: Location
    evidence: str
    impact: str
    remediation: str
    verification: str
    references: List[str] = field(default_factory=list)
    metadata: Dict[str, Any] = field(default_factory=dict)

    @classmethod
    def from_rule(
        cls,
        rule: Rule,
        location: Location,
        evidence: str,
        *,
        severity: Optional[Severity] = None,
        confidence: Optional[Confidence] = None,
        metadata: Optional[Mapping[str, Any]] = None,
    ) -> Finding:
        return cls(
            rule_id=rule.rule_id,
            title=rule.title,
            description=rule.description,
            severity=severity or rule.severity,
            confidence=confidence or rule.confidence,
            category=rule.category,
            location=location,
            evidence=evidence,
            impact=rule.impact,
            remediation=rule.remediation,
            verification=rule.verification,
            references=list(rule.references),
            metadata=dict(metadata or {}),
        )

    @property
    def fingerprint(self) -> str:
        material = "\x1f".join(
            (
                self.rule_id,
                self.location.uri,
                str(self.location.line or 0),
                self.evidence,
            )
        )
        return hashlib.sha256(material.encode("utf-8", "replace")).hexdigest()[:24]

    def to_dict(self) -> Dict[str, Any]:
        return {
            "rule_id": self.rule_id,
            "title": self.title,
            "description": self.description,
            "severity": self.severity.value,
            "confidence": self.confidence.value,
            "category": self.category,
            "location": self.location.to_dict(),
            "evidence": self.evidence,
            "impact": self.impact,
            "remediation": self.remediation,
            "verification": self.verification,
            "references": list(self.references),
            "metadata": dict(self.metadata),
            "fingerprint": self.fingerprint,
        }


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


@dataclass
class ScanReport:
    """Common result shape for source and public-URL scans."""

    target: str
    scanner: str
    completeness: ScanCompleteness = ScanCompleteness.COMPLETE
    findings: List[Finding] = field(default_factory=list)
    started_at: str = field(default_factory=utc_now)
    finished_at: Optional[str] = None
    files_scanned: int = 0
    pages_scanned: int = 0
    skipped: int = 0
    warnings: List[str] = field(default_factory=list)
    metadata: Dict[str, Any] = field(default_factory=dict)

    def mark_partial(self) -> ScanReport:
        """Record that some configured checks could not complete."""

        if self.completeness is ScanCompleteness.COMPLETE:
            self.completeness = ScanCompleteness.PARTIAL
        return self

    def mark_failed(self) -> ScanReport:
        """Record that the primary target could not be evaluated."""

        self.completeness = ScanCompleteness.FAILED
        return self

    def finish(self) -> ScanReport:
        if self.completeness is ScanCompleteness.COMPLETE and (self.warnings or self.skipped):
            self.completeness = ScanCompleteness.PARTIAL
        if self.finished_at is None:
            self.finished_at = utc_now()
        self.findings.sort(
            key=lambda finding: (
                -SEVERITY_RANK[finding.severity],
                finding.rule_id,
                finding.location.uri,
                finding.location.line or 0,
            )
        )
        return self

    def counts(self) -> Dict[str, int]:
        counts = {severity.value: 0 for severity in Severity}
        for finding in self.findings:
            counts[finding.severity.value] += 1
        return counts

    def to_dict(self) -> Dict[str, Any]:
        return {
            "schema_version": "1.0",
            "tool": {"name": "aisec", "version": __version__},
            "target": self.target,
            "scanner": self.scanner,
            "completeness": self.completeness.value,
            "started_at": self.started_at,
            "finished_at": self.finished_at,
            "summary": {
                "total_findings": len(self.findings),
                "by_severity": self.counts(),
                "files_scanned": self.files_scanned,
                "pages_scanned": self.pages_scanned,
                "skipped": self.skipped,
            },
            "findings": [finding.to_dict() for finding in self.findings],
            "warnings": list(self.warnings),
            "metadata": dict(self.metadata),
        }
