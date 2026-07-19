"""FastAPI application for Patchwork Security Lab.

The API intentionally imports only the public ``aisec.scan_source`` and
``aisec.scan_url`` functions. Network safety, including DNS resolution and SSRF
protection, stays inside the scanner instead of being duplicated in this web
adapter.
"""

from __future__ import annotations

import inspect
import json
import logging
import os
from collections import Counter, OrderedDict
from collections.abc import Mapping, Sequence
from dataclasses import asdict, is_dataclass
from datetime import datetime, timezone
from enum import Enum
from pathlib import Path
from threading import BoundedSemaphore, RLock
from time import perf_counter
from typing import Any, Literal, Optional, cast
from urllib.parse import urlsplit
from uuid import uuid4

from fastapi import FastAPI, HTTPException, Query
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse, JSONResponse, Response
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, Field, field_validator
from starlette.concurrency import run_in_threadpool

from patchwork_common import PROJECT_URL, __version__

Severity = Literal["critical", "high", "medium", "low", "info"]
TargetType = Literal["source", "url", "demo"]
ScanStatus = Literal["completed", "partial", "failed"]
ScanCompleteness = Literal["complete", "partial", "failed"]

logger = logging.getLogger(__name__)


class ScannerContractError(RuntimeError):
    """Raised when a core scanner returns an untrustworthy result shape."""


class SourceScanRequest(BaseModel):
    """A server-local source tree to inspect."""

    path: str = Field(min_length=1, max_length=4096)
    max_files: int = Field(default=5_000, ge=1, le=25_000)

    @field_validator("path")
    @classmethod
    def validate_path(cls, value: str) -> str:
        value = value.strip()
        if not value:
            raise ValueError("Enter a source path.")
        if "\x00" in value:
            raise ValueError("Source paths cannot contain null bytes.")
        return value


class UrlScanRequest(BaseModel):
    """A public HTTP(S) website for passive inspection."""

    url: str = Field(min_length=1, max_length=2048)
    timeout_seconds: float = Field(default=10.0, ge=1.0, le=30.0)

    @field_validator("url")
    @classmethod
    def validate_url(cls, value: str) -> str:
        value = value.strip()
        parsed = urlsplit(value)
        if parsed.scheme.lower() not in {"http", "https"} or not parsed.hostname:
            raise ValueError("Enter a complete public http:// or https:// URL.")
        if parsed.username or parsed.password:
            raise ValueError("URLs with embedded credentials are not supported.")
        return value


class EvidenceItem(BaseModel):
    label: str = "Observed"
    value: str
    code: Optional[str] = None


class FindingLocation(BaseModel):
    path: Optional[str] = None
    url: Optional[str] = None
    line: Optional[int] = None
    column: Optional[int] = None
    endpoint: Optional[str] = None


class SecurityFinding(BaseModel):
    id: str
    rule_id: str
    title: str
    severity: Severity
    confidence: str
    category: str
    description: str
    impact: str
    location: FindingLocation
    evidence: list[EvidenceItem]
    remediation: str
    verification: str
    references: list[str] = Field(default_factory=list)
    cwe: Optional[str] = None
    status: Literal["open", "accepted", "resolved"] = "open"


class ScanSummary(BaseModel):
    total: int
    critical: int
    high: int
    medium: int
    low: int
    info: int
    confirmed: int
    checks_run: Optional[int] = None
    files_scanned: Optional[int] = None
    pages_scanned: Optional[int] = None
    skipped: Optional[int] = None


class ScanCoverage(BaseModel):
    """How much of the requested target the core scanner evaluated."""

    completeness: ScanCompleteness
    files_scanned: Optional[int] = None
    pages_scanned: Optional[int] = None
    skipped: Optional[int] = None


class ScanResponse(BaseModel):
    id: str
    target_type: TargetType
    target: str
    status: ScanStatus = "completed"
    started_at: str
    completed_at: str
    duration_ms: int
    summary: ScanSummary
    coverage: ScanCoverage
    findings: list[SecurityFinding]
    limitations: list[str] = Field(default_factory=list)
    metadata: dict[str, Any] = Field(default_factory=dict)


_scan_source_impl: Any | None = None
_scan_url_impl: Any | None = None
MAX_STORED_SCANS = 100
DEFAULT_MAX_CONCURRENT_SCANS = 4
MAX_CONFIGURED_CONCURRENT_SCANS = 32
_SCANS: OrderedDict[str, ScanResponse] = OrderedDict()
_SCANS_LOCK = RLock()

_CONTENT_SECURITY_POLICY = "; ".join(
    (
        "default-src 'self'",
        "base-uri 'self'",
        "connect-src 'self'",
        "font-src 'self'",
        "form-action 'self'",
        "frame-ancestors 'none'",
        "img-src 'self' data:",
        "object-src 'none'",
        "script-src 'self'",
        "style-src 'self'",
    )
)
_PERMISSIONS_POLICY = ", ".join(
    (
        "accelerometer=()",
        "camera=()",
        "geolocation=()",
        "gyroscope=()",
        "magnetometer=()",
        "microphone=()",
        "payment=()",
        "usb=()",
    )
)


def _resolve_scanner(kind: Literal["source", "url"]) -> Any:
    global _scan_source_impl, _scan_url_impl

    current = _scan_source_impl if kind == "source" else _scan_url_impl
    if current is not None:
        return current

    try:
        from aisec import scan_source, scan_url
    except ImportError as exc:  # pragma: no cover - depends on packaging/install state
        raise HTTPException(
            status_code=503,
            detail="The security scanner is not installed in this environment.",
        ) from exc

    _scan_source_impl = scan_source
    _scan_url_impl = scan_url
    return _scan_source_impl if kind == "source" else _scan_url_impl


async def _invoke_scanner(scanner: Any, target: str, **options: Any) -> Any:
    """Call async scanners directly and keep synchronous work off the event loop."""

    if inspect.iscoroutinefunction(scanner):
        return await scanner(target, **options)

    result = await run_in_threadpool(scanner, target, **options)
    if inspect.isawaitable(result):
        return await result
    return result


async def _invoke_bounded_scanner(
    scanner: Any,
    slots: BoundedSemaphore,
    target: str,
    **options: Any,
) -> Any:
    """Run a scan only when capacity is immediately available."""

    if not slots.acquire(blocking=False):
        raise HTTPException(
            status_code=429,
            detail="The scanner is at capacity. Try again shortly.",
            headers={"Retry-After": "1"},
        )
    try:
        return await _invoke_scanner(scanner, target, **options)
    finally:
        slots.release()


def _jsonable(value: Any) -> Any:
    if value is None or isinstance(value, (str, int, float, bool)):
        return value
    if isinstance(value, Enum):
        return value.value
    if isinstance(value, datetime):
        return value.isoformat()
    if isinstance(value, Path):
        return str(value)
    if isinstance(value, Mapping):
        return {str(key): _jsonable(item) for key, item in value.items()}
    if isinstance(value, Sequence) and not isinstance(value, (str, bytes, bytearray)):
        return [_jsonable(item) for item in value]
    if hasattr(value, "to_dict"):
        return _jsonable(value.to_dict())
    if hasattr(value, "model_dump"):
        return _jsonable(value.model_dump(mode="json"))
    if is_dataclass(value):
        return _jsonable(asdict(cast(Any, value)))
    if hasattr(value, "__dict__"):
        return _jsonable(vars(value))
    return str(value)


def _text(value: Any, default: str = "") -> str:
    if value is None:
        return default
    if isinstance(value, str):
        return value
    if isinstance(value, (dict, list)):
        return json.dumps(_jsonable(value), ensure_ascii=False, sort_keys=True)
    return str(value)


def _normalize_severity(value: Any) -> Severity:
    severity = _text(value, "info").lower().strip()
    aliases = {
        "error": "high",
        "warning": "medium",
        "warn": "medium",
        "note": "info",
        "informational": "info",
    }
    severity = aliases.get(severity, severity)
    if severity not in {"critical", "high", "medium", "low", "info"}:
        return "info"
    return severity  # type: ignore[return-value]


def _normalize_location(raw: Any, target: str, target_type: TargetType) -> FindingLocation:
    location = raw if isinstance(raw, Mapping) else {}
    uri = location.get("uri")
    path = location.get("path") or location.get("file") or location.get("file_path")
    url = location.get("url")
    if uri and target_type == "url" and not url:
        url = uri
    elif uri and not path:
        path = uri
    if target_type == "url" and not url:
        url = target
    return FindingLocation(
        path=_text(path) or None,
        url=_text(url) or None,
        line=_positive_int(location.get("line") or location.get("start_line")),
        column=_positive_int(location.get("column") or location.get("start_column")),
        endpoint=_text(location.get("endpoint") or location.get("route")) or None,
    )


def _positive_int(value: Any) -> int | None:
    try:
        number = int(value)
    except (TypeError, ValueError):
        return None
    return number if number > 0 else None


def _nonnegative_int(value: Any) -> int | None:
    try:
        number = int(value)
    except (TypeError, ValueError):
        return None
    return number if number >= 0 else None


def _normalize_evidence(raw: Any) -> list[EvidenceItem]:
    if not raw:
        return []
    if isinstance(raw, str):
        return [EvidenceItem(value=raw)]
    if isinstance(raw, Mapping):
        if "value" in raw or "code" in raw:
            return [
                EvidenceItem(
                    label=_text(raw.get("label"), "Observed"),
                    value=_text(raw.get("value") or raw.get("message") or raw.get("code")),
                    code=_text(raw.get("code")) or None,
                )
            ]
        return [EvidenceItem(label=_text(key), value=_text(value)) for key, value in raw.items()]
    if isinstance(raw, Sequence):
        evidence: list[EvidenceItem] = []
        for item in raw:
            if isinstance(item, Mapping):
                evidence.append(
                    EvidenceItem(
                        label=_text(item.get("label") or item.get("type"), "Observed"),
                        value=_text(item.get("value") or item.get("message") or item.get("code")),
                        code=_text(item.get("code")) or None,
                    )
                )
            else:
                evidence.append(EvidenceItem(value=_text(item)))
        return evidence
    return [EvidenceItem(value=_text(raw))]


def _normalize_finding(
    raw_finding: Any,
    index: int,
    target: str,
    target_type: TargetType,
) -> SecurityFinding:
    raw = _jsonable(raw_finding)
    if not isinstance(raw, Mapping):
        raw = {"title": _text(raw)}

    rule_id = _text(raw.get("rule_id") or raw.get("rule") or raw.get("check_id"), "AISEC-UNKNOWN")
    title = _text(raw.get("title") or raw.get("name") or raw.get("message"), "Security finding")
    description = _text(
        raw.get("description") or raw.get("summary") or raw.get("message"),
        "The scanner observed a condition that needs review.",
    )
    location_raw = raw.get("location")
    if not isinstance(location_raw, Mapping):
        location_raw = {
            "path": raw.get("path") or raw.get("file") or raw.get("file_path"),
            "url": raw.get("url"),
            "line": raw.get("line"),
            "column": raw.get("column"),
            "endpoint": raw.get("endpoint"),
        }

    finding_id = _text(
        raw.get("id") or raw.get("finding_id") or raw.get("fingerprint"),
        f"{rule_id}-{index + 1}",
    )
    references_raw = raw.get("references") or raw.get("links") or []
    if isinstance(references_raw, str):
        references = [references_raw]
    elif isinstance(references_raw, Sequence):
        references = [_text(item) for item in references_raw if _text(item)]
    else:
        references = []

    return SecurityFinding(
        id=finding_id,
        rule_id=rule_id,
        title=title,
        severity=_normalize_severity(raw.get("severity")),
        confidence=_text(raw.get("confidence"), "heuristic").lower(),
        category=_text(raw.get("category") or raw.get("type"), "security"),
        description=description,
        impact=_text(
            raw.get("impact"),
            "Review the evidence and confirm whether the observed condition is "
            "reachable in this application.",
        ),
        location=_normalize_location(location_raw, target, target_type),
        evidence=_normalize_evidence(raw.get("evidence")),
        remediation=_text(
            raw.get("remediation") or raw.get("recommendation") or raw.get("fix"),
            "Review the affected code or response and apply the least-privilege "
            "safe pattern for this context.",
        ),
        verification=_text(
            raw.get("verification") or raw.get("verify"),
            "Repeat the scan after the change and add a focused regression test.",
        ),
        references=references,
        cwe=_text(raw.get("cwe") or raw.get("cwe_id")) or None,
    )


def _extract_report(report: Any) -> dict[str, Any]:
    raw = _jsonable(report)
    if not isinstance(raw, Mapping):
        raise ScannerContractError("scanner result must be an object")
    return dict(raw)


def _normalize_completeness(raw: Mapping[str, Any]) -> ScanCompleteness:
    metadata_value = raw.get("metadata")
    metadata: Mapping[str, Any] = metadata_value if isinstance(metadata_value, Mapping) else {}
    value = _text(raw.get("completeness") or raw.get("status") or metadata.get("completeness"))
    normalized = value.lower().strip()
    aliases = {"completed": "complete", "success": "complete", "error": "failed"}
    normalized = aliases.get(normalized, normalized)
    if normalized in {"complete", "partial", "failed"}:
        return cast(ScanCompleteness, normalized)
    raise ScannerContractError("scanner result has no recognized completeness value")


def _build_coverage(raw: Mapping[str, Any]) -> ScanCoverage:
    summary_value = raw.get("summary")
    metadata_value = raw.get("metadata")
    raw_summary: Mapping[str, Any] = summary_value if isinstance(summary_value, Mapping) else {}
    metadata: Mapping[str, Any] = metadata_value if isinstance(metadata_value, Mapping) else {}

    def value(name: str) -> Any:
        summary_item = raw_summary.get(name)
        return summary_item if summary_item is not None else metadata.get(name)

    return ScanCoverage(
        completeness=_normalize_completeness(raw),
        files_scanned=_nonnegative_int(value("files_scanned")),
        pages_scanned=_nonnegative_int(value("pages_scanned")),
        skipped=_nonnegative_int(value("skipped")),
    )


def _build_summary(
    findings: list[SecurityFinding],
    raw: Mapping[str, Any],
    coverage: ScanCoverage,
) -> ScanSummary:
    counts = Counter(finding.severity for finding in findings)
    summary_value = raw.get("summary")
    metadata_value = raw.get("metadata")
    raw_summary: Mapping[str, Any] = summary_value if isinstance(summary_value, Mapping) else {}
    metadata: Mapping[str, Any] = metadata_value if isinstance(metadata_value, Mapping) else {}
    confirmed = sum(
        1 for finding in findings if finding.confidence.lower() in {"confirmed", "certain", "high"}
    )
    return ScanSummary(
        total=len(findings),
        critical=counts["critical"],
        high=counts["high"],
        medium=counts["medium"],
        low=counts["low"],
        info=counts["info"],
        confirmed=confirmed,
        checks_run=_nonnegative_int(raw_summary.get("checks_run") or metadata.get("checks_run")),
        files_scanned=coverage.files_scanned,
        pages_scanned=coverage.pages_scanned,
        skipped=coverage.skipped,
    )


def _normalize_report(
    report: Any,
    *,
    target: str,
    target_type: TargetType,
    started_at: datetime,
    duration_ms: int,
) -> ScanResponse:
    raw = _extract_report(report)
    if "findings" not in raw:
        raise ScannerContractError("scanner result is missing its findings array")
    raw_findings = raw.get("findings")
    if not isinstance(raw_findings, Sequence) or isinstance(raw_findings, (str, bytes)):
        raise ScannerContractError("scanner findings must be an array")
    findings = [
        _normalize_finding(finding, index, target, target_type)
        for index, finding in enumerate(raw_findings)
    ]
    completed_at = datetime.now(timezone.utc)
    limitations_raw = raw.get("limitations") or raw.get("warnings") or []
    if isinstance(limitations_raw, str):
        limitations = [limitations_raw]
    elif isinstance(limitations_raw, Sequence):
        limitations = [_text(item) for item in limitations_raw if _text(item)]
    else:
        limitations = []

    metadata_raw = raw.get("metadata") if isinstance(raw.get("metadata"), Mapping) else {}
    metadata = dict(_jsonable(metadata_raw))
    metadata.setdefault(
        "report_schema", raw.get("schema_version") or raw.get("version") or "normalized-v1"
    )
    coverage = _build_coverage(raw)
    status: ScanStatus = (
        "completed" if coverage.completeness == "complete" else coverage.completeness
    )

    return ScanResponse(
        id=str(uuid4()),
        target_type=target_type,
        target=target,
        started_at=started_at.isoformat(),
        completed_at=completed_at.isoformat(),
        duration_ms=max(0, duration_ms),
        status=status,
        summary=_build_summary(findings, raw, coverage),
        coverage=coverage,
        findings=findings,
        limitations=limitations,
        metadata=metadata,
    )


def _demo_report() -> dict[str, Any]:
    """Clearly labeled sample data used for a zero-setup product tour."""

    return {
        "completeness": "complete",
        "metadata": {"sample_data": True, "checks_run": 18, "files_scanned": 42},
        "limitations": [
            "This is sample evidence for exploring the interface. It is not a "
            "scan of your application."
        ],
        "findings": [
            {
                "id": "demo-prompt-1",
                "rule_id": "AISEC-PROMPT-001",
                "title": "Untrusted text reaches a privileged system prompt",
                "severity": "high",
                "confidence": "high",
                "category": "Prompt injection",
                "description": (
                    "A support-ticket field is concatenated into a system-level "
                    "instruction before the model call."
                ),
                "impact": (
                    "A crafted ticket could alter tool instructions or influence "
                    "privileged model behavior."
                ),
                "location": {"path": "src/agents/triage.py", "line": 84, "column": 19},
                "evidence": [
                    {
                        "label": "Data flow",
                        "value": (
                            "ticket.body is interpolated into system_message without "
                            "a trust boundary."
                        ),
                        "code": 'system_message = POLICY + f"\\nTicket: {ticket.body}"',
                    }
                ],
                "remediation": (
                    "Keep untrusted content in a user message, delimit it explicitly, "
                    "and enforce tool permissions outside the model prompt."
                ),
                "verification": (
                    "Add an adversarial ticket fixture and assert that system "
                    "instructions and allowed tools remain unchanged."
                ),
                "cwe": "CWE-74",
                "references": [
                    "https://owasp.org/www-project-top-10-for-large-language-model-applications/"
                ],
            },
            {
                "id": "demo-secret-1",
                "rule_id": "AISEC-SECRET-002",
                "title": "Model provider token committed in a test fixture",
                "severity": "critical",
                "confidence": "confirmed",
                "category": "Secrets",
                "description": (
                    "A provider credential matching a live-token format appears in "
                    "a committed fixture."
                ),
                "impact": (
                    "Anyone with repository access could use the credential until it is revoked."
                ),
                "location": {"path": "tests/fixtures/provider.env", "line": 3, "column": 15},
                "evidence": [
                    {
                        "label": "Matched value",
                        "value": "Provider token pattern (redacted): sk-live-...7Qm",
                    }
                ],
                "remediation": (
                    "Revoke the token, remove it from Git history, and load a scoped "
                    "test credential from the environment."
                ),
                "verification": (
                    "Confirm revocation with the provider, scan repository history, "
                    "and rerun the secret check."
                ),
                "cwe": "CWE-798",
            },
            {
                "id": "demo-cors-1",
                "rule_id": "AISEC-WEB-006",
                "title": "Credentialed CORS response reflects arbitrary origins",
                "severity": "medium",
                "confidence": "high",
                "category": "Web configuration",
                "description": (
                    "The sample response reflects the Origin header while allowing credentials."
                ),
                "impact": (
                    "A hostile origin may be able to read authenticated responses "
                    "in a victim's browser."
                ),
                "location": {"url": "https://demo.invalid/api/profile", "endpoint": "/api/profile"},
                "evidence": [
                    {
                        "label": "Response header",
                        "value": "Access-Control-Allow-Origin: https://untrusted.invalid",
                    },
                    {"label": "Response header", "value": "Access-Control-Allow-Credentials: true"},
                ],
                "remediation": (
                    "Use an explicit origin allowlist and return the credential header "
                    "only for trusted origins."
                ),
                "verification": (
                    "Repeat the preflight with an untrusted origin and confirm that "
                    "no allow-origin header is returned."
                ),
                "cwe": "CWE-942",
            },
            {
                "id": "demo-output-1",
                "rule_id": "AISEC-OUTPUT-003",
                "title": "Model output is rendered as HTML without sanitization",
                "severity": "high",
                "confidence": "medium",
                "category": "Insecure output handling",
                "description": (
                    "Generated markdown is converted to HTML and inserted into the "
                    "page with raw HTML enabled."
                ),
                "impact": (
                    "If an attacker controls model context, generated content could "
                    "execute script in a user's session."
                ),
                "location": {"path": "apps/web/src/components/Answer.tsx", "line": 47},
                "evidence": [
                    {
                        "label": "Sink",
                        "value": "dangerouslySetInnerHTML receives renderMarkdown(answer)",
                    }
                ],
                "remediation": (
                    "Disable raw HTML in markdown and sanitize the rendered output "
                    "with a restrictive policy."
                ),
                "verification": (
                    "Render script, event-handler, and javascript URL payloads and "
                    "assert they remain inert."
                ),
                "cwe": "CWE-79",
            },
            {
                "id": "demo-header-1",
                "rule_id": "AISEC-WEB-011",
                "title": "Content Security Policy is not present",
                "severity": "low",
                "confidence": "confirmed",
                "category": "Browser hardening",
                "description": (
                    "The sampled HTML response does not include a Content-Security-Policy header."
                ),
                "impact": (
                    "The browser has fewer constraints if an injection flaw is "
                    "introduced elsewhere."
                ),
                "location": {"url": "https://demo.invalid/"},
                "evidence": [
                    {"label": "Observed", "value": "Header absent on the final HTML response."}
                ],
                "remediation": (
                    "Introduce a report-only policy, review reports, then enforce a "
                    "minimal allowlist without unsafe-inline."
                ),
                "verification": (
                    "Request the page again and confirm that the enforced policy "
                    "matches the expected resource inventory."
                ),
                "cwe": "CWE-693",
            },
        ],
    }


def _to_sarif(scan: ScanResponse) -> dict[str, Any]:
    unique_rules: dict[str, SecurityFinding] = {}
    for finding in scan.findings:
        unique_rules.setdefault(finding.rule_id, finding)

    rules = []
    for rule_id, finding in unique_rules.items():
        rule: dict[str, Any] = {
            "id": rule_id,
            "name": finding.title,
            "shortDescription": {"text": finding.title},
            "fullDescription": {"text": finding.description},
            "properties": {
                "category": finding.category,
                "defaultSeverity": finding.severity,
                "confidence": finding.confidence,
            },
        }
        if finding.references:
            rule["helpUri"] = finding.references[0]
        rules.append(rule)

    level = {
        "critical": "error",
        "high": "error",
        "medium": "warning",
        "low": "note",
        "info": "note",
    }
    results = []
    for finding in scan.findings:
        location_uri = finding.location.path or finding.location.url or scan.target
        physical_location: dict[str, Any] = {
            "artifactLocation": {"uri": location_uri},
        }
        if finding.location.line:
            region: dict[str, int] = {"startLine": finding.location.line}
            if finding.location.column:
                region["startColumn"] = finding.location.column
            physical_location["region"] = region
        results.append(
            {
                "ruleId": finding.rule_id,
                "level": level[finding.severity],
                "message": {"text": finding.description},
                "locations": [{"physicalLocation": physical_location}],
                "properties": {
                    "findingId": finding.id,
                    "severity": finding.severity,
                    "confidence": finding.confidence,
                    "category": finding.category,
                    "impact": finding.impact,
                    "remediation": finding.remediation,
                    "verification": finding.verification,
                    "evidence": [item.model_dump(exclude_none=True) for item in finding.evidence],
                },
            }
        )

    return {
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "Patchwork Sentinel",
                        "informationUri": PROJECT_URL,
                        "rules": rules,
                    }
                },
                "invocations": [
                    {
                        "executionSuccessful": scan.status != "failed",
                        "startTimeUtc": scan.started_at,
                        "endTimeUtc": scan.completed_at,
                        "properties": {
                            "scanId": scan.id,
                            "status": scan.status,
                            "completeness": scan.coverage.completeness,
                            "filesScanned": scan.coverage.files_scanned,
                            "pagesScanned": scan.coverage.pages_scanned,
                            "skipped": scan.coverage.skipped,
                            "targetType": scan.target_type,
                            "sampleData": bool(scan.metadata.get("sample_data")),
                        },
                    }
                ],
                "results": results,
            }
        ],
    }


def _store(scan: ScanResponse) -> ScanResponse:
    with _SCANS_LOCK:
        _SCANS[scan.id] = scan
        _SCANS.move_to_end(scan.id)
        while len(_SCANS) > MAX_STORED_SCANS:
            _SCANS.popitem(last=False)
    return scan


def _resolve_source_target(raw_path: str) -> Path:
    """Resolve a source target without allowing it to escape the configured root."""

    configured_root = os.getenv("PATCHWORK_WORKSPACE_ROOT")
    try:
        workspace_root = (
            Path(configured_root).expanduser()
            if configured_root and configured_root.strip()
            else Path.cwd()
        )
    except OSError as exc:
        raise HTTPException(
            status_code=503,
            detail="The configured source workspace is not available.",
        ) from exc
    try:
        workspace_root = workspace_root.resolve(strict=True)
    except (FileNotFoundError, OSError) as exc:
        raise HTTPException(
            status_code=503,
            detail="The configured source workspace is not available.",
        ) from exc
    if not workspace_root.is_dir():
        raise HTTPException(
            status_code=503,
            detail="The configured source workspace is not a directory.",
        )

    supplied = Path(raw_path).expanduser()
    candidate = supplied if supplied.is_absolute() else workspace_root / supplied
    try:
        candidate = candidate.resolve(strict=True)
    except FileNotFoundError as exc:
        raise HTTPException(status_code=422, detail="The source target does not exist.") from exc
    except OSError as exc:
        raise HTTPException(
            status_code=422, detail="The source target could not be resolved."
        ) from exc

    if candidate != workspace_root and workspace_root not in candidate.parents:
        raise HTTPException(
            status_code=403,
            detail="The source target must stay inside PATCHWORK_WORKSPACE_ROOT.",
        )
    if not candidate.is_file() and not candidate.is_dir():
        raise HTTPException(
            status_code=422,
            detail="The source target must be a regular file or directory.",
        )
    if not os.access(candidate, os.R_OK):
        raise HTTPException(status_code=403, detail="The source target is not readable.")
    return candidate


def _get_scan(scan_id: str) -> ScanResponse:
    with _SCANS_LOCK:
        scan = _SCANS.get(scan_id)
    if scan is None:
        raise HTTPException(status_code=404, detail="Scan not found in this server session.")
    return scan


def _error_from_scanner(exc: Exception) -> HTTPException:
    if isinstance(exc, HTTPException):
        return exc
    if isinstance(exc, (ValueError, FileNotFoundError, NotADirectoryError, PermissionError)):
        return HTTPException(
            status_code=422, detail=str(exc) or "The scan target could not be read."
        )
    error_id = uuid4().hex
    logger.exception("Unexpected scanner failure (error_id=%s)", error_id)
    return HTTPException(
        status_code=502,
        detail=(
            "The scanner could not complete this request. "
            f"Review the server log with error ID {error_id}."
        ),
        headers={"X-Patchwork-Error-ID": error_id},
    )


def _configured_concurrency(environ: Mapping[str, str] | None = None) -> int:
    environment = os.environ if environ is None else environ
    raw_value = environment.get("PATCHWORK_MAX_CONCURRENT_SCANS", str(DEFAULT_MAX_CONCURRENT_SCANS))
    try:
        configured = int(raw_value)
    except ValueError:
        logger.warning(
            "Ignoring invalid PATCHWORK_MAX_CONCURRENT_SCANS=%r; using %d.",
            raw_value,
            DEFAULT_MAX_CONCURRENT_SCANS,
        )
        return DEFAULT_MAX_CONCURRENT_SCANS
    return max(1, min(configured, MAX_CONFIGURED_CONCURRENT_SCANS))


def _resolve_dashboard_dist(
    *,
    environ: Mapping[str, str] | None = None,
    repo_root: Path | None = None,
    package_root: Path | None = None,
) -> Path | None:
    """Return the first complete dashboard build in release-preference order."""

    environment = os.environ if environ is None else environ
    source_root = Path(__file__).resolve().parents[2] if repo_root is None else repo_root
    installed_root = Path(__file__).resolve().parent if package_root is None else package_root
    candidates: list[Path] = []
    configured = environment.get("PATCHWORK_DASHBOARD_DIST", "").strip()
    if configured:
        candidates.append(Path(configured).expanduser())
    candidates.extend(
        (
            source_root / "apps" / "dashboard" / "dist",
            installed_root / "dashboard",
        )
    )

    for candidate in candidates:
        try:
            if candidate.is_dir() and (candidate / "index.html").is_file():
                return candidate.resolve()
        except OSError:
            continue
    return None


def create_app() -> FastAPI:
    application = FastAPI(
        title="Patchwork Security Lab API",
        version=__version__,
        description="Evidence-first source and public website security scanning.",
    )
    max_concurrent_scans = _configured_concurrency()
    scan_slots = BoundedSemaphore(max_concurrent_scans)
    application.state.max_concurrent_scans = max_concurrent_scans

    cors_origins = [
        origin.strip()
        for origin in os.getenv(
            "PATCHWORK_CORS_ORIGINS",
            "http://localhost:5173,http://127.0.0.1:5173",
        ).split(",")
        if origin.strip()
    ]
    application.add_middleware(
        CORSMiddleware,
        allow_origins=cors_origins,
        allow_credentials=False,
        allow_methods=["GET", "POST"],
        allow_headers=["Content-Type", "Accept"],
        expose_headers=["X-Patchwork-Error-ID", "Retry-After"],
    )

    @application.middleware("http")
    async def security_headers(request: Any, call_next: Any) -> Response:
        response = await call_next(request)
        response.headers.setdefault("X-Content-Type-Options", "nosniff")
        response.headers.setdefault("Referrer-Policy", "no-referrer")
        response.headers.setdefault("Permissions-Policy", _PERMISSIONS_POLICY)
        response.headers.setdefault("X-Frame-Options", "DENY")
        path = request.url.path
        if not path.startswith(("/api/", "/docs", "/redoc", "/openapi.json")):
            response.headers.setdefault("Content-Security-Policy", _CONTENT_SECURITY_POLICY)
        return response

    @application.get("/api/health", tags=["system"])
    def health() -> dict[str, str]:
        return {"status": "ok", "service": "patchwork-api"}

    @application.post("/api/scans/source", response_model=ScanResponse, tags=["scans"])
    async def scan_source_endpoint(request: SourceScanRequest) -> ScanResponse:
        scanner = _resolve_scanner("source")
        source_target = _resolve_source_target(request.path)
        started_at = datetime.now(timezone.utc)
        timer = perf_counter()
        try:
            report = await _invoke_bounded_scanner(
                scanner,
                scan_slots,
                str(source_target),
                max_files=request.max_files,
            )
            duration_ms = round((perf_counter() - timer) * 1_000)
            normalized = _normalize_report(
                report,
                target=str(source_target),
                target_type="source",
                started_at=started_at,
                duration_ms=duration_ms,
            )
        except Exception as exc:  # scanners expose domain errors through this boundary
            raise _error_from_scanner(exc) from exc
        return _store(normalized)

    @application.post("/api/scans/url", response_model=ScanResponse, tags=["scans"])
    async def scan_url_endpoint(request: UrlScanRequest) -> ScanResponse:
        """Delegate a passive public-URL scan to the SSRF-safe core scanner."""

        scanner = _resolve_scanner("url")
        started_at = datetime.now(timezone.utc)
        timer = perf_counter()
        try:
            report = await _invoke_bounded_scanner(
                scanner,
                scan_slots,
                request.url,
                timeout=request.timeout_seconds,
            )
            duration_ms = round((perf_counter() - timer) * 1_000)
            normalized = _normalize_report(
                report,
                target=request.url,
                target_type="url",
                started_at=started_at,
                duration_ms=duration_ms,
            )
        except Exception as exc:
            raise _error_from_scanner(exc) from exc
        return _store(normalized)

    @application.post("/api/scans/demo", response_model=ScanResponse, tags=["scans"])
    def demo_scan_endpoint() -> ScanResponse:
        started_at = datetime.now(timezone.utc)
        return _store(
            _normalize_report(
                _demo_report(),
                target="Sample AI support application",
                target_type="demo",
                started_at=started_at,
                duration_ms=236,
            )
        )

    @application.get("/api/scans", response_model=list[ScanResponse], tags=["scans"])
    def list_scans(limit: int = Query(default=10, ge=1, le=50)) -> list[ScanResponse]:
        with _SCANS_LOCK:
            scans = list(reversed(_SCANS.values()))
        return scans[:limit]

    @application.get("/api/scans/{scan_id}", response_model=ScanResponse, tags=["scans"])
    def get_scan(scan_id: str) -> ScanResponse:
        return _get_scan(scan_id)

    @application.get("/api/scans/{scan_id}/export/json", tags=["exports"])
    def export_json(scan_id: str) -> Response:
        scan = _get_scan(scan_id)
        payload = json.dumps(scan.model_dump(mode="json"), indent=2, ensure_ascii=False)
        return Response(
            content=payload,
            media_type="application/json",
            headers={"Content-Disposition": f'attachment; filename="patchwork-{scan.id}.json"'},
        )

    @application.get("/api/scans/{scan_id}/export/sarif", tags=["exports"])
    def export_sarif(scan_id: str) -> Response:
        scan = _get_scan(scan_id)
        payload = json.dumps(_to_sarif(scan), indent=2, ensure_ascii=False)
        return Response(
            content=payload,
            media_type="application/sarif+json",
            headers={"Content-Disposition": f'attachment; filename="patchwork-{scan.id}.sarif"'},
        )

    dashboard_dist = _resolve_dashboard_dist()
    if dashboard_dist is not None:
        assets_dir = dashboard_dist / "assets"
        if assets_dir.is_dir():
            application.mount("/assets", StaticFiles(directory=assets_dir), name="dashboard-assets")

        @application.get("/{full_path:path}", include_in_schema=False)
        def dashboard(full_path: str) -> Response:
            if full_path.startswith("api/"):
                raise HTTPException(status_code=404, detail="API route not found.")
            candidate = (dashboard_dist / full_path).resolve()
            if candidate.is_file() and dashboard_dist in candidate.parents:
                return FileResponse(candidate)
            index = dashboard_dist / "index.html"
            if index.is_file():
                return FileResponse(index)
            return JSONResponse({"service": "Patchwork Security Lab API"})
    else:

        @application.get("/", include_in_schema=False)
        def api_root() -> dict[str, str]:
            return {
                "service": "Patchwork Security Lab API",
                "docs": "/docs",
                "dashboard": "Build apps/dashboard to serve the web interface here.",
            }

    return application


app = create_app()


__all__ = [
    "ScanResponse",
    "SourceScanRequest",
    "UrlScanRequest",
    "app",
    "create_app",
]
