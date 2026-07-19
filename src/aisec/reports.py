# ruff: noqa: E501, UP006, UP035 -- Long embedded HTML/CSS and Python 3.9 typing.
"""Human text, JSON, accessible standalone HTML, and SARIF report rendering."""

from __future__ import annotations

import html
import json
from pathlib import Path
from typing import Any, Dict, List
from urllib.parse import urlsplit

from patchwork_common import PROJECT_URL, __version__

from .models import ScanCompleteness, ScanReport, Severity
from .rules import get_rule


def json_report(report: ScanReport, *, pretty: bool = True) -> str:
    """Return a stable JSON representation of a scan."""

    return (
        json.dumps(
            report.to_dict(),
            indent=2 if pretty else None,
            sort_keys=False,
            ensure_ascii=False,
        )
        + "\n"
    )


def text_report(report: ScanReport) -> str:
    """Return a concise, terminal-friendly report without ANSI control codes."""

    counts = report.counts()
    lines = [
        "aisec security review",
        f"Target: {report.target}",
        f"Scanner: {report.scanner}",
        f"Completeness: {report.completeness.value.upper()}",
        (
            "Coverage: "
            f"{report.files_scanned} files, {report.pages_scanned} pages, "
            f"{report.skipped} skipped"
        ),
        (
            "Findings: "
            f"{len(report.findings)} total "
            f"(critical {counts['critical']}, high {counts['high']}, "
            f"medium {counts['medium']}, low {counts['low']}, info {counts['info']})"
        ),
    ]
    if report.completeness is not ScanCompleteness.COMPLETE:
        lines.extend(
            [
                "",
                "INCOMPLETE RESULT: Some or all configured checks did not run. "
                "Do not interpret zero findings as a clean result.",
            ]
        )
    if report.warnings:
        lines.extend(["", "Incomplete checks:"])
        lines.extend(f"  - {warning}" for warning in report.warnings)
    lines.extend(["", "Findings:"])
    if not report.findings:
        if report.completeness is ScanCompleteness.COMPLETE:
            lines.append(
                "  None detected by the configured checks. This does not guarantee the target is secure."
            )
        else:
            lines.append("  None reported from the checks that ran; the scan was not complete.")
    for index, finding in enumerate(report.findings, start=1):
        location = finding.location.uri
        if finding.location.line is not None:
            location += f":{finding.location.line}"
            if finding.location.column is not None:
                location += f":{finding.location.column}"
        lines.extend(
            [
                "",
                f"{index}. [{finding.severity.value.upper()}] {finding.rule_id} — {finding.title}",
                f"   Location: {location}",
                f"   Confidence: {finding.confidence.value}",
                f"   Evidence: {finding.evidence}",
                f"   Impact: {finding.impact}",
                f"   Fix: {finding.remediation}",
                f"   Verify: {finding.verification}",
            ]
        )
    return "\n".join(lines) + "\n"


def _safe(value: object) -> str:
    return html.escape(str(value), quote=True)


def html_report(report: ScanReport) -> str:
    """Return a self-contained, script-free HTML report."""

    counts = report.counts()
    count_items = "".join(
        f"<li><strong>{_safe(severity.value.title())}</strong><span>{counts[severity.value]}</span></li>"
        for severity in reversed(list(Severity))
    )
    finding_items: List[str] = []
    for finding in report.findings:
        location = finding.location.uri
        if finding.location.line:
            location += f":{finding.location.line}"
        references = "".join(
            f'<li><a href="{_safe(reference)}" rel="noreferrer">{_safe(reference)}</a></li>'
            for reference in finding.references
            if urlsplit(reference).scheme in {"http", "https"}
        )
        finding_items.append(
            """
            <article class="finding severity-{severity}" id="finding-{fingerprint}">
              <header>
                <div class="badges"><span class="severity">{severity}</span><code>{rule}</code><span>{confidence} confidence</span></div>
                <h3>{title}</h3>
                <p class="location">{location}</p>
              </header>
              <dl>
                <div><dt>Observation</dt><dd>{description}</dd></div>
                <div><dt>Evidence</dt><dd><pre><code>{evidence}</code></pre></dd></div>
                <div><dt>Impact</dt><dd>{impact}</dd></div>
                <div><dt>Recommended action</dt><dd>{remediation}</dd></div>
                <div><dt>Verify the fix</dt><dd>{verification}</dd></div>
              </dl>
              {references}
            </article>
            """.format(
                severity=_safe(finding.severity.value),
                fingerprint=_safe(finding.fingerprint),
                rule=_safe(finding.rule_id),
                confidence=_safe(finding.confidence.value),
                title=_safe(finding.title),
                location=_safe(location),
                description=_safe(finding.description),
                evidence=_safe(finding.evidence),
                impact=_safe(finding.impact),
                remediation=_safe(finding.remediation),
                verification=_safe(finding.verification),
                references=(
                    f'<ul class="references" aria-label="References">{references}</ul>'
                    if references
                    else ""
                ),
            )
        )
    warnings = "".join(f"<li>{_safe(item)}</li>" for item in report.warnings)
    if finding_items:
        findings_markup = "".join(finding_items)
    elif report.completeness is ScanCompleteness.COMPLETE:
        findings_markup = (
            '<div class="empty"><h3>No findings</h3><p>The configured checks did not find '
            "evidence to report. This does not establish that the target is secure.</p></div>"
        )
    else:
        findings_markup = (
            '<div class="incomplete"><h3>No clean conclusion</h3><p>Some or all configured '
            "checks did not run. Zero findings must not be interpreted as a clean result.</p></div>"
        )
    return """<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>aisec security review</title>
  <style>
    :root {{ color-scheme: light; --ink:#18202b; --muted:#5c6673; --line:#d7dde5; --surface:#f5f7fa; --accent:#315bd6; --critical:#9b1c1c; --high:#b54708; --medium:#735c0f; --low:#315bd6; }}
    * {{ box-sizing:border-box; }}
    body {{ margin:0; background:#fff; color:var(--ink); font:15px/1.55 ui-sans-serif,system-ui,-apple-system,BlinkMacSystemFont,"Segoe UI",sans-serif; }}
    main {{ width:min(980px,calc(100% - 32px)); margin:0 auto; padding:48px 0 80px; }}
    h1 {{ margin:0 0 8px; font-size:clamp(28px,5vw,44px); letter-spacing:-.03em; }}
    h2 {{ margin:48px 0 16px; font-size:20px; }} h3 {{ margin:8px 0 4px; font-size:18px; }}
    p {{ max-width:74ch; }} code,pre {{ font-family:ui-monospace,SFMono-Regular,Consolas,monospace; }}
    .eyebrow,.location,.meta {{ color:var(--muted); }} .eyebrow {{ margin:0; font-weight:700; text-transform:uppercase; letter-spacing:.08em; font-size:12px; }}
    .summary {{ display:grid; grid-template-columns:2fr 1fr; gap:24px; padding:24px; margin-top:28px; background:var(--surface); border:1px solid var(--line); }}
    .summary ul {{ list-style:none; padding:0; margin:0; display:grid; grid-template-columns:repeat(2,minmax(90px,1fr)); gap:8px; }}
    .summary li {{ display:flex; justify-content:space-between; border-bottom:1px solid var(--line); }}
    .finding {{ border-top:4px solid var(--line); border-right:1px solid var(--line); border-bottom:1px solid var(--line); border-left:1px solid var(--line); padding:24px; margin:0 0 16px; }}
    .severity-critical {{ border-top-color:var(--critical); }} .severity-high {{ border-top-color:var(--high); }} .severity-medium {{ border-top-color:var(--medium); }} .severity-low {{ border-top-color:var(--low); }}
    .badges {{ display:flex; flex-wrap:wrap; align-items:center; gap:8px; color:var(--muted); font-size:13px; }}
    .severity {{ color:var(--ink); font-weight:800; text-transform:uppercase; }}
    dl {{ margin:20px 0 0; }} dl div {{ display:grid; grid-template-columns:150px 1fr; gap:16px; padding:12px 0; border-top:1px solid var(--line); }} dt {{ font-weight:700; }} dd {{ margin:0; min-width:0; }}
    pre {{ margin:0; padding:12px; overflow:auto; white-space:pre-wrap; overflow-wrap:anywhere; background:var(--surface); border:1px solid var(--line); }}
    a {{ color:var(--accent); }} a:focus-visible {{ outline:3px solid var(--accent); outline-offset:3px; }}
    .warnings,.empty,.incomplete {{ padding:20px; border:1px solid var(--line); background:var(--surface); }}
    .status {{ display:inline-block; margin-top:8px; padding:3px 8px; border:1px solid var(--line); font-weight:800; letter-spacing:.05em; }}
    .status-partial,.status-failed,.incomplete {{ border-color:var(--high); background:#fff8ed; }}
    @media (max-width:680px) {{ .summary,dl div {{ grid-template-columns:1fr; }} main {{ padding-top:28px; }} }}
    @media print {{ main {{ width:100%; padding:0; }} .finding {{ break-inside:avoid; }} }}
    @media (prefers-reduced-motion:reduce) {{ *,*::before,*::after {{ scroll-behavior:auto!important; transition:none!important; animation:none!important; }} }}
  </style>
</head>
<body>
<main>
  <header>
    <p class="eyebrow">Passive security review</p>
    <h1>aisec report</h1>
    <p>Evidence from deterministic checks. Review findings in context; this report is not a penetration test or a guarantee of security.</p>
    <div class="summary">
      <div><strong>Target</strong><p>{target}</p><span class="meta">Scanner: {scanner} · Finished: {finished}</span><br><span class="status status-{completeness}">{completeness}</span></div>
      <ul aria-label="Findings by severity">{counts}</ul>
    </div>
  </header>
  {completeness_section}
  {warning_section}
  <section aria-labelledby="findings-title">
    <h2 id="findings-title">Findings ({total})</h2>
    {findings}
  </section>
</main>
</body>
</html>
""".format(
        target=_safe(report.target),
        scanner=_safe(report.scanner),
        finished=_safe(report.finished_at or "in progress"),
        completeness=_safe(report.completeness.value),
        counts=count_items,
        completeness_section=(
            '<section class="incomplete" aria-labelledby="completeness-title">'
            '<h2 id="completeness-title">Incomplete result</h2><p>Some or all configured '
            "checks did not run. Do not interpret this report as a clean result.</p></section>"
            if report.completeness is not ScanCompleteness.COMPLETE
            else ""
        ),
        warning_section=(
            f'<section aria-labelledby="warnings-title"><h2 id="warnings-title">Incomplete checks</h2><ul class="warnings">{warnings}</ul></section>'
            if warnings
            else ""
        ),
        total=len(report.findings),
        findings=findings_markup,
    )


_SARIF_LEVEL = {
    Severity.CRITICAL: "error",
    Severity.HIGH: "error",
    Severity.MEDIUM: "warning",
    Severity.LOW: "note",
    Severity.INFO: "note",
}
_SECURITY_SEVERITY = {
    Severity.CRITICAL: "9.5",
    Severity.HIGH: "8.0",
    Severity.MEDIUM: "5.0",
    Severity.LOW: "2.0",
    Severity.INFO: "0.0",
}


def sarif_report(report: ScanReport, *, pretty: bool = True) -> str:
    """Return GitHub-compatible SARIF 2.1.0 JSON."""

    used_rule_ids = sorted({finding.rule_id for finding in report.findings})
    rules: List[Dict[str, Any]] = []
    for rule_id in used_rule_ids:
        rule = get_rule(rule_id)
        entry: Dict[str, Any] = {
            "id": rule.rule_id,
            "name": rule.title.replace(" ", ""),
            "shortDescription": {"text": rule.title},
            "fullDescription": {"text": rule.description},
            "defaultConfiguration": {"level": _SARIF_LEVEL[rule.severity]},
            "properties": {
                "category": rule.category,
                "precision": rule.confidence.value,
                "security-severity": _SECURITY_SEVERITY[rule.severity],
                "tags": ["security", "ai-security", rule.category],
            },
        }
        if rule.references:
            entry["helpUri"] = rule.references[0]
        entry["help"] = {
            "text": (
                f"{rule.description}\n\nImpact: {rule.impact}\n\n"
                f"Recommended action: {rule.remediation}\n\nVerification: {rule.verification}"
            )
        }
        rules.append(entry)
    results: List[Dict[str, Any]] = []
    for finding in report.findings:
        physical: Dict[str, Any] = {"artifactLocation": {"uri": finding.location.uri}}
        if finding.location.line is not None:
            region: Dict[str, int] = {"startLine": max(1, finding.location.line)}
            if finding.location.column is not None:
                region["startColumn"] = max(1, finding.location.column)
            if finding.location.end_line is not None:
                region["endLine"] = max(region["startLine"], finding.location.end_line)
            physical["region"] = region
        results.append(
            {
                "ruleId": finding.rule_id,
                "level": _SARIF_LEVEL[finding.severity],
                "message": {
                    "text": (
                        f"{finding.description} Evidence: {finding.evidence} "
                        f"Impact: {finding.impact} Recommended action: {finding.remediation} "
                        f"Verification: {finding.verification}"
                    )
                },
                "locations": [{"physicalLocation": physical}],
                "partialFingerprints": {"primaryLocationLineHash": finding.fingerprint},
                "properties": {
                    "confidence": finding.confidence.value,
                    "severity": finding.severity.value,
                    "category": finding.category,
                },
            }
        )
    document = {
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "aisec",
                        "version": __version__,
                        "informationUri": PROJECT_URL,
                        "rules": rules,
                    }
                },
                "results": results,
                "invocations": [
                    {
                        "executionSuccessful": report.completeness is not ScanCompleteness.FAILED,
                        "properties": {
                            "scanner": report.scanner,
                            "completeness": report.completeness.value,
                            "warnings": list(report.warnings),
                        },
                    }
                ],
            }
        ],
    }
    return json.dumps(document, indent=2 if pretty else None, ensure_ascii=False) + "\n"


def render_report(report: ScanReport, output_format: str) -> str:
    normalized = output_format.lower()
    if normalized == "text":
        return text_report(report)
    if normalized == "json":
        return json_report(report)
    if normalized == "html":
        return html_report(report)
    if normalized == "sarif":
        return sarif_report(report)
    raise ValueError(f"unknown report format: {output_format}")


def write_report(report: ScanReport, filename: str, output_format: str) -> None:
    Path(filename).write_text(render_report(report, output_format), encoding="utf-8")
