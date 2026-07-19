# ruff: noqa: UP045 -- PEP 604 unions are not valid syntax on supported Python 3.9.
"""Command-line interface for the source and passive URL scanners."""

from __future__ import annotations

import argparse
import json
import sys
from collections.abc import Sequence
from pathlib import Path
from typing import Optional

from . import __version__
from .models import SEVERITY_RANK, ScanCompleteness, ScanReport, Severity
from .reports import render_report
from .rules import iter_rules
from .source import scan_source
from .urlscan import TargetValidationError, scan_url

FORMATS = ("text", "json", "html", "sarif")
FAIL_LEVELS = tuple(severity.value for severity in Severity)


def _report_arguments(parser: argparse.ArgumentParser) -> None:
    parser.add_argument(
        "--format",
        choices=FORMATS,
        default="text",
        help="report format (default: text)",
    )
    parser.add_argument(
        "-o",
        "--output",
        default="-",
        metavar="PATH",
        help="write to PATH, or - for stdout (default: -)",
    )
    parser.add_argument(
        "--suppress",
        action="append",
        default=[],
        metavar="RULE_ID",
        help="suppress a rule; may be repeated",
    )
    parser.add_argument(
        "--suppress-file",
        metavar="PATH",
        help="load RULE_ID [GLOB] suppressions from a file",
    )
    parser.add_argument(
        "--allow-partial",
        action="store_true",
        help="return policy status for a partial scan instead of status 2",
    )
    parser.add_argument(
        "--fail-on",
        choices=FAIL_LEVELS,
        metavar="SEVERITY",
        help="return exit status 1 when a finding meets this severity (off by default)",
    )


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="aisec",
        description=(
            "Deterministic AI security checks for local source and bounded, "
            "passive public-website surfaces."
        ),
    )
    parser.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    subparsers = parser.add_subparsers(dest="command", required=True)

    source_parser = subparsers.add_parser(
        "source", help="scan a local source file or tree without modifying it"
    )
    source_parser.add_argument("path", help="source file or directory")
    source_parser.add_argument(
        "--max-files", type=int, default=10_000, help="file limit (default: 10000)"
    )
    source_parser.add_argument(
        "--max-file-bytes",
        type=int,
        default=1_000_000,
        help="per-file byte limit (default: 1000000)",
    )
    source_parser.add_argument(
        "--max-total-bytes",
        type=int,
        default=50_000_000,
        help="aggregate bytes read limit (default: 50000000)",
    )
    source_parser.add_argument(
        "--max-findings",
        type=int,
        default=1_000,
        help="reported finding limit (default: 1000)",
    )
    source_parser.add_argument(
        "--exclude",
        action="append",
        default=[],
        metavar="GLOB",
        help="exclude a relative path glob; may be repeated",
    )
    source_parser.add_argument(
        "--ignore-file",
        metavar="PATH",
        help="load excludes and suppressions from PATH (default: discover .aisecignore)",
    )
    _report_arguments(source_parser)

    url_parser = subparsers.add_parser(
        "url", help="passively review a public website with same-origin GET requests"
    )
    url_parser.add_argument("url", help="public http or https URL")
    url_parser.add_argument(
        "--max-pages", type=int, default=8, help="page limit, 1-50 (default: 8)"
    )
    url_parser.add_argument("--max-depth", type=int, default=1, help="link depth, 0-3 (default: 1)")
    url_parser.add_argument(
        "--max-redirects",
        type=int,
        default=3,
        help="same-origin redirect limit, 0-5 (default: 3)",
    )
    url_parser.add_argument(
        "--max-response-bytes",
        type=int,
        default=1_000_000,
        help="per-response byte limit, up to 5000000",
    )
    url_parser.add_argument("--timeout", type=float, default=8.0, help="request timeout in seconds")
    _report_arguments(url_parser)

    rules_parser = subparsers.add_parser("rules", help="print the structured rule catalog as JSON")
    rules_parser.add_argument("--compact", action="store_true", help="emit compact JSON")
    return parser


def _write_output(text: str, destination: str) -> None:
    if destination == "-":
        sys.stdout.write(text)
        return
    output_path = Path(destination)
    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(text, encoding="utf-8")


def _fails_policy(report: ScanReport, threshold: Optional[str]) -> bool:
    if threshold is None:
        return False
    required = SEVERITY_RANK[Severity(threshold)]
    return any(SEVERITY_RANK[finding.severity] >= required for finding in report.findings)


def main(argv: Optional[Sequence[str]] = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    if args.command == "rules":
        payload = {
            "schema_version": "1.0",
            "rules": [rule.to_dict() for rule in iter_rules()],
        }
        sys.stdout.write(
            json.dumps(
                payload,
                indent=None if args.compact else 2,
                ensure_ascii=False,
            )
            + "\n"
        )
        return 0
    try:
        if args.command == "source":
            report = scan_source(
                args.path,
                suppressed_rules=args.suppress,
                suppression_file=args.suppress_file,
                max_files=args.max_files,
                max_file_bytes=args.max_file_bytes,
                max_total_bytes=args.max_total_bytes,
                max_findings=args.max_findings,
                exclude_patterns=args.exclude,
                ignore_file=args.ignore_file,
            )
        elif args.command == "url":
            report = scan_url(
                args.url,
                suppressed_rules=args.suppress,
                suppression_file=args.suppress_file,
                max_pages=args.max_pages,
                max_depth=args.max_depth,
                max_redirects=args.max_redirects,
                max_response_bytes=args.max_response_bytes,
                timeout=args.timeout,
            )
        else:  # pragma: no cover - argparse enforces commands.
            parser.error("a command is required")
            return 2
        _write_output(render_report(report, args.format), args.output)
        if report.completeness is ScanCompleteness.FAILED:
            return 2
        if report.completeness is ScanCompleteness.PARTIAL and not args.allow_partial:
            return 2
        return 1 if _fails_policy(report, args.fail_on) else 0
    except (FileNotFoundError, OSError, TargetValidationError, ValueError) as exc:
        print(f"aisec: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
