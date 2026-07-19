from __future__ import annotations

import os
from pathlib import Path

import pytest

from aisec import ScanCompleteness, scan_source
from aisec.rules import iter_rules


def _rule_ids(report) -> set[str]:
    return {finding.rule_id for finding in report.findings}


def test_source_scan_finds_ai_taint_secrets_and_supply_chain(tmp_path: Path) -> None:
    source = tmp_path / "service.py"
    source.write_text(
        """
import subprocess
import torch

api_key = "sk-abcdefghijklmnopqrstuvwxyz123456"
response = client.chat.completions.create(model="example", messages=[])
model_text = response.choices[0].message.content
eval(model_text)
subprocess.run(model_text, shell=True)
model = torch.load("untrusted-model.pt")
""",
        encoding="utf-8",
    )

    report = scan_source(str(tmp_path))

    assert report.files_scanned == 1
    assert {"AISEC001", "AISEC101", "AISEC102", "AISEC104"} <= _rule_ids(report)
    assert "abcdefghijklmnopqrstuvwxyz123456" not in str(report.to_dict())
    taint = next(finding for finding in report.findings if finding.rule_id == "AISEC101")
    assert taint.metadata["analysis"] == "python-ast-taint"
    assert [step["kind"] for step in taint.metadata["trace"]] == ["source", "sink"]
    assert taint.impact != taint.description
    assert taint.verification != taint.remediation
    assert taint.location.line is not None


def test_python_taint_tracks_await_transforms_and_subprocess_keyword_args(
    tmp_path: Path,
) -> None:
    source = tmp_path / "async_agent.py"
    source.write_text(
        """
import subprocess

async def run_agent():
    response = await client.responses.create(input="hello")
    model_text = response.output_text.strip().replace("prefix:", "")
    subprocess.run(args=model_text, shell=False)
""",
        encoding="utf-8",
    )

    report = scan_source(str(source))

    command = next(finding for finding in report.findings if finding.rule_id == "AISEC102")
    assert command.metadata["sink"] == "subprocess.run"
    assert command.metadata["shell"] is False
    assert command.metadata["trace"][0]["kind"] == "source"
    assert command.metadata["trace"][-1] == {
        "kind": "sink",
        "line": command.location.line,
        "symbol": "subprocess.run",
    }


def test_inline_and_global_suppressions_are_applied(tmp_path: Path) -> None:
    source = tmp_path / "accepted.py"
    source.write_text(
        """
response = client.responses.create(input="hello")
model_output = response.output_text
# aisec: ignore[AISEC101] -- reviewed constrained fixture
eval(model_output)
password = "a-real-looking-password"
""",
        encoding="utf-8",
    )

    report = scan_source(str(tmp_path), suppressed_rules=["AISEC001"])

    assert "AISEC101" not in _rule_ids(report)
    assert "AISEC001" not in _rule_ids(report)


def test_aisecignore_supports_excludes_and_scoped_rules(tmp_path: Path) -> None:
    ignored = tmp_path / "fixtures" / "unsafe.py"
    ignored.parent.mkdir()
    ignored.write_text('password = "fixture-password"\n', encoding="utf-8")
    kept = tmp_path / "app.py"
    kept.write_text(
        'password = "production-looking-password"\nmodel = torch.load("m.pt")\n',
        encoding="utf-8",
    )
    (tmp_path / ".aisecignore").write_text("fixtures/**\nAISEC104 app.py\n", encoding="utf-8")

    report = scan_source(str(tmp_path))

    assert report.files_scanned == 1
    assert "AISEC001" in _rule_ids(report)
    assert "AISEC104" not in _rule_ids(report)


def test_repeatable_exclude_patterns_skip_matching_paths(tmp_path: Path) -> None:
    (tmp_path / "safe.py").write_text("value = 1\n", encoding="utf-8")
    generated = tmp_path / "generated"
    generated.mkdir()
    (generated / "unsafe.py").write_text(
        'secret_key = "this-is-only-a-fixture"\n', encoding="utf-8"
    )

    report = scan_source(str(tmp_path), exclude_patterns=["generated/**"])

    assert report.files_scanned == 1
    assert not report.findings


def test_default_excludes_skip_local_dependency_caches(tmp_path: Path) -> None:
    (tmp_path / "app.py").write_text("value = 1\n", encoding="utf-8")
    cached = tmp_path / ".cache" / "uv" / "archive"
    cached.mkdir(parents=True)
    (cached / "unsafe.py").write_text(
        'model = torch.load("third-party-model.pt")\n', encoding="utf-8"
    )

    report = scan_source(str(tmp_path))

    assert report.files_scanned == 1
    assert not report.findings


def test_source_scan_is_bounded_by_file_count(tmp_path: Path) -> None:
    for name in ("a.py", "b.py", "c.py"):
        (tmp_path / name).write_text("value = 1\n", encoding="utf-8")

    report = scan_source(str(tmp_path), max_files=2)

    assert report.files_scanned == 2
    assert any("max_files=2" in warning for warning in report.warnings)
    assert report.completeness is ScanCompleteness.PARTIAL


def test_source_scan_stops_at_aggregate_byte_limit(tmp_path: Path) -> None:
    first = b"answer = 1\n"
    (tmp_path / "a.py").write_bytes(first)
    (tmp_path / "b.py").write_bytes(b"answer = 2\n")

    report = scan_source(str(tmp_path), max_total_bytes=len(first))

    assert report.files_scanned == 1
    assert report.metadata["max_total_bytes"] == len(first)
    assert report.metadata["total_bytes_scanned"] == len(first)
    assert report.completeness is ScanCompleteness.PARTIAL
    assert any("max_total_bytes" in warning for warning in report.warnings)


def test_source_scan_stops_at_finding_limit(tmp_path: Path) -> None:
    (tmp_path / "unsafe.py").write_text(
        'password = "production-password"\nverify = False\ninnerHTML = model_output\n',
        encoding="utf-8",
    )

    report = scan_source(str(tmp_path), max_findings=2)

    assert len(report.findings) == 2
    assert report.metadata["max_findings"] == 2
    assert report.completeness is ScanCompleteness.PARTIAL
    assert any("max_findings=2" in warning for warning in report.warnings)


def test_suppression_rule_ids_are_validated_for_every_explicit_source(
    tmp_path: Path,
) -> None:
    source = tmp_path / "app.py"
    source.write_text('password = "production-password"\n', encoding="utf-8")

    with pytest.raises(ValueError, match="unknown suppression rule ID.*AISEC999"):
        scan_source(str(source), suppressed_rules=["AISEC999"])

    suppression_file = tmp_path / "suppressions.txt"
    suppression_file.write_text("AISEC998 app.py\n", encoding="utf-8")
    with pytest.raises(ValueError, match="unknown suppression rule ID.*AISEC998"):
        scan_source(str(source), suppression_file=str(suppression_file))

    suppression_file.write_text("AISEC001 app.py\n", encoding="utf-8")
    assert "AISEC001" not in _rule_ids(
        scan_source(str(source), suppression_file=str(suppression_file))
    )

    (tmp_path / ".aisecignore").write_text("AISEC997 app.py\n", encoding="utf-8")
    with pytest.raises(ValueError, match="unknown suppression rule ID.*AISEC997"):
        scan_source(str(tmp_path))


def test_non_regular_special_files_are_skipped_without_opening(tmp_path: Path) -> None:
    pipe = tmp_path / "events.py"
    os.mkfifo(pipe)

    report = scan_source(str(tmp_path))

    assert report.files_scanned == 0
    assert report.skipped == 1
    assert report.completeness is ScanCompleteness.FAILED
    assert any("not a regular file" in warning for warning in report.warnings)


def test_unsupported_explicit_file_is_not_reported_as_a_complete_scan(tmp_path: Path) -> None:
    target = tmp_path / "artifact.bin"
    target.write_bytes(b"not source text")

    report = scan_source(str(target))

    assert report.files_scanned == 0
    assert report.completeness is ScanCompleteness.FAILED
    assert any("not a supported regular text file" in warning for warning in report.warnings)


def test_directory_with_no_supported_files_is_a_failed_scan(tmp_path: Path) -> None:
    (tmp_path / "artifact.bin").write_bytes(b"not source text")

    report = scan_source(str(tmp_path))

    assert report.files_scanned == 0
    assert report.completeness is ScanCompleteness.FAILED
    assert any("no supported regular text files" in warning for warning in report.warnings)


def test_directory_symlinks_are_accounted_for_without_following(tmp_path: Path) -> None:
    outside = tmp_path.parent / f"{tmp_path.name}-outside"
    outside.mkdir()
    (outside / "unsafe.py").write_text('password = "production-password"\n', encoding="utf-8")
    (tmp_path / "linked").symlink_to(outside, target_is_directory=True)

    report = scan_source(str(tmp_path))

    assert report.files_scanned == 0
    assert report.skipped == 1
    assert report.completeness is ScanCompleteness.FAILED
    assert any("symbolic link directory" in warning for warning in report.warnings)


def test_every_rule_has_specific_impact_and_verification_guidance() -> None:
    rules = list(iter_rules())

    assert len(rules) >= 13
    assert len({rule.impact for rule in rules}) == len(rules)
    assert len({rule.verification for rule in rules}) == len(rules)
    for rule in rules:
        assert len(rule.impact) >= 80
        assert len(rule.verification) >= 80
        assert rule.impact != rule.description
        assert rule.verification != rule.remediation


def test_common_extensionless_credential_files_are_scanned_and_redacted(
    tmp_path: Path,
) -> None:
    npm_token = "npm_abcdefghijklmnopqrstuvwxyz1234567890"
    pypi_token = "pypi-abcdefghijklmnopqrstuvwxyz1234567890"
    (tmp_path / "id_ed25519").write_text(
        "-----BEGIN OPENSSH PRIVATE KEY-----\nfixture-key-material\n",
        encoding="utf-8",
    )
    (tmp_path / ".npmrc").write_text(
        f"//registry.npmjs.org/:_authToken={npm_token}\n",
        encoding="utf-8",
    )
    (tmp_path / ".pypirc").write_text(
        f"[pypi]\nusername = __token__\npassword = {pypi_token}\n",
        encoding="utf-8",
    )

    report = scan_source(str(tmp_path))

    assert report.files_scanned == 3
    assert {"AISEC001", "AISEC002"} <= _rule_ids(report)
    serialized = str(report.to_dict())
    assert npm_token not in serialized
    assert pypi_token not in serialized


def test_credential_file_environment_placeholders_are_not_reported(tmp_path: Path) -> None:
    (tmp_path / ".npmrc").write_text(
        "//registry.npmjs.org/:_authToken=${NPM_TOKEN}\n",
        encoding="utf-8",
    )
    (tmp_path / ".pypirc").write_text(
        "[pypi]\npassword = ${PYPI_TOKEN}\n",
        encoding="utf-8",
    )

    report = scan_source(str(tmp_path))

    assert report.files_scanned == 2
    assert "AISEC001" not in _rule_ids(report)
