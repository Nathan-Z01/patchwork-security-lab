from __future__ import annotations

import json
from pathlib import Path

from aisec import Confidence, Finding, Location, ScanCompleteness, ScanReport, Severity
from aisec.cli import main
from aisec.reports import html_report, json_report, sarif_report, text_report


def example_report() -> ScanReport:
    report = ScanReport("demo.py", "source")
    report.findings.append(
        Finding(
            rule_id="AISEC101",
            title="Model output reaches dynamic code execution",
            description="An unsafe sink was observed.",
            severity=Severity.CRITICAL,
            confidence=Confidence.HIGH,
            category="ai-code-execution",
            location=Location("demo.py", 7, 3),
            evidence='eval(value) </code><script>alert("x")</script>',
            impact="Arbitrary code could execute with application privileges.",
            remediation="Use a constrained operation schema.",
            verification="Confirm code-like model output is rejected before the sink.",
        )
    )
    return report.finish()


def test_all_report_formats_are_structured_and_escape_html() -> None:
    report = example_report()

    json_payload = json.loads(json_report(report))
    sarif_payload = json.loads(sarif_report(report))
    html_payload = html_report(report)
    text_payload = text_report(report)

    assert json_payload["summary"]["total_findings"] == 1
    assert sarif_payload["version"] == "2.1.0"
    assert sarif_payload["runs"][0]["results"][0]["ruleId"] == "AISEC101"
    assert "<script>alert" not in html_payload
    assert "&lt;script&gt;alert" in html_payload
    assert 'aria-labelledby="findings-title"' in html_payload
    assert "Completeness: COMPLETE" in text_payload
    assert "Impact: Arbitrary code" in text_payload
    assert "Verify: Confirm code-like" in text_payload


def test_incomplete_reports_never_present_zero_findings_as_clean() -> None:
    report = ScanReport("https://example.com/", "url")
    report.warnings.append("Could not fetch the root page.")
    report.mark_failed().finish()
    assert report.completeness is ScanCompleteness.FAILED

    json_payload = json.loads(json_report(report))
    sarif_payload = json.loads(sarif_report(report))

    assert json_payload["completeness"] == "failed"
    assert sarif_payload["runs"][0]["invocations"][0]["executionSuccessful"] is False
    assert "Do not interpret zero findings as a clean result" in text_report(report)
    assert "No clean conclusion" in html_report(report)


def test_cli_succeeds_by_default_and_fail_on_is_opt_in(tmp_path: Path, capsys) -> None:
    source = tmp_path / "unsafe.py"
    source.write_text(
        "response = client.responses.create(input='x')\n"
        "model_output = response.output_text\n"
        "eval(model_output)\n",
        encoding="utf-8",
    )

    assert main(["source", str(source), "--format", "sarif"]) == 0
    first = json.loads(capsys.readouterr().out)
    assert first["version"] == "2.1.0"

    assert (
        main(
            [
                "source",
                str(source),
                "--format",
                "json",
                "--fail-on",
                "high",
            ]
        )
        == 1
    )
    second = json.loads(capsys.readouterr().out)
    assert second["summary"]["total_findings"] >= 1


def test_cli_writes_report_and_rejects_private_url(tmp_path: Path, capsys) -> None:
    source = tmp_path / "safe.py"
    source.write_text("answer = 42\n", encoding="utf-8")
    destination = tmp_path / "reports" / "nested" / "report.html"

    assert main(["source", str(source), "-o", str(destination), "--format", "html"]) == 0
    assert destination.read_text(encoding="utf-8").startswith("<!doctype html>")

    assert main(["url", "http://127.0.0.1/"]) == 2
    assert "non-public" in capsys.readouterr().err


def test_cli_defaults_to_text_and_requires_partial_opt_in(tmp_path: Path, capsys) -> None:
    (tmp_path / "a.py").write_text("answer = 42\n", encoding="utf-8")
    (tmp_path / "b.py").write_text("answer = 43\n", encoding="utf-8")

    assert main(["source", str(tmp_path), "--max-files", "1"]) == 2
    output = capsys.readouterr().out
    assert "aisec security review" in output
    assert "Completeness: PARTIAL" in output

    assert (
        main(
            [
                "source",
                str(tmp_path),
                "--max-files",
                "1",
                "--allow-partial",
            ]
        )
        == 0
    )
    assert "INCOMPLETE RESULT" in capsys.readouterr().out


def test_cli_exposes_resource_limits_and_rejects_suppression_typos(tmp_path: Path, capsys) -> None:
    source = tmp_path / "unsafe.py"
    source.write_text(
        'password = "production-password"\nverify = False\n',
        encoding="utf-8",
    )

    assert (
        main(
            [
                "source",
                str(source),
                "--max-findings",
                "1",
                "--max-total-bytes",
                "1000",
                "--allow-partial",
                "--format",
                "json",
            ]
        )
        == 0
    )
    payload = json.loads(capsys.readouterr().out)
    assert payload["metadata"]["max_findings"] == 1
    assert payload["metadata"]["max_total_bytes"] == 1000
    assert payload["completeness"] == "partial"

    assert main(["source", str(source), "--suppress", "AISEC999"]) == 2
    assert "unknown suppression rule ID 'AISEC999'" in capsys.readouterr().err
