"""Aggregate FreshPatch results into reviewable JSON or Markdown evidence."""

from __future__ import annotations

import json
import math
import statistics
from collections.abc import Iterable, Mapping, Sequence
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from .errors import SchemaError
from .evaluator import EvaluationResult, EvaluationStatus

REPORT_SCHEMA_VERSION = "1.1"


@dataclass(frozen=True)
class ResultSummary:
    total: int
    passed: int
    failed: int
    timed_out: int
    errors: int
    pass_rate: float
    mean_duration_seconds: float
    median_duration_seconds: float
    p95_duration_seconds: float

    def to_dict(self) -> dict[str, Any]:
        return {
            "total": self.total,
            "passed": self.passed,
            "failed": self.failed,
            "timed_out": self.timed_out,
            "errors": self.errors,
            "pass_rate": round(self.pass_rate, 6),
            "mean_duration_seconds": round(self.mean_duration_seconds, 6),
            "median_duration_seconds": round(self.median_duration_seconds, 6),
            "p95_duration_seconds": round(self.p95_duration_seconds, 6),
        }


def _task_bindings(results: Sequence[EvaluationResult]) -> tuple[tuple[str, str], ...]:
    """Return stable task identities and reject stale/mixed evidence."""

    bindings: dict[str, str] = {}
    for result in results:
        existing = bindings.get(result.task_id)
        if existing is not None and existing != result.task_sha256:
            raise SchemaError(
                "result set mixes task digests for "
                f"{result.task_id!r}: {existing} and {result.task_sha256}"
            )
        bindings[result.task_id] = result.task_sha256
    return tuple(sorted(bindings.items()))


def summarize(results: Sequence[EvaluationResult]) -> ResultSummary:
    """Calculate transparent, task-level benchmark metrics."""

    _task_bindings(results)
    total = len(results)
    counts = {status: 0 for status in EvaluationStatus}
    for result in results:
        counts[result.status] += 1
    durations = sorted(result.duration_seconds for result in results)
    if durations:
        p95_index = max(0, math.ceil(0.95 * len(durations)) - 1)
        mean = statistics.fmean(durations)
        median = statistics.median(durations)
        p95 = durations[p95_index]
    else:
        mean = median = p95 = 0.0
    passed = counts[EvaluationStatus.PASSED]
    return ResultSummary(
        total=total,
        passed=passed,
        failed=counts[EvaluationStatus.FAILED],
        timed_out=counts[EvaluationStatus.TIMEOUT],
        errors=counts[EvaluationStatus.ERROR],
        pass_rate=(passed / total) if total else 0.0,
        mean_duration_seconds=mean,
        median_duration_seconds=median,
        p95_duration_seconds=p95,
    )


def report_dict(results: Sequence[EvaluationResult]) -> dict[str, Any]:
    bindings = _task_bindings(results)
    return {
        "report_schema_version": REPORT_SCHEMA_VERSION,
        "task_bindings": [
            {"task_id": task_id, "task_sha256": digest} for task_id, digest in bindings
        ],
        "summary": summarize(results).to_dict(),
        "results": [result.to_dict() for result in results],
    }


def render_json(results: Sequence[EvaluationResult]) -> str:
    return json.dumps(report_dict(results), indent=2, sort_keys=True, ensure_ascii=False) + "\n"


def _cell(value: Any) -> str:
    return str(value).replace("|", "\\|").replace("\n", " ")


def _code_block(value: str) -> str:
    # Four-space indentation avoids choosing a fence that might occur in tool output.
    if not value:
        return "    (no output)"
    return "\n".join(f"    {line}" for line in value.splitlines())


def _runner(result: EvaluationResult) -> str:
    if result.environment.image is not None:
        return result.environment.image
    controller = result.environment
    return (
        f"unsafe local ({controller.controller_os}/{controller.controller_architecture}; "
        f"Python {controller.controller_python})"
    )


def render_markdown(
    results: Sequence[EvaluationResult],
    *,
    title: str = "FreshPatch evaluation report",
) -> str:
    """Render evidence with both aggregate metrics and per-task failure details."""

    summary = summarize(results)
    bindings = _task_bindings(results)
    summary_row = (
        f"| {summary.total} | {summary.passed} | {summary.failed} | "
        f"{summary.timed_out} | {summary.errors} | {summary.pass_rate:.1%} | "
        f"{summary.mean_duration_seconds:.3f}s | {summary.p95_duration_seconds:.3f}s |"
    )
    lines = [
        f"# {title}",
        "",
        "This report summarizes execution-based repair checks. A pass means the "
        "configured test command exited with code 0; it does not prove the repair "
        "is complete or secure.",
        "",
        "## Summary",
        "",
        "| Tasks | Passed | Failed | Timed out | Errors | Pass rate | "
        "Mean duration | P95 duration |",
        "| ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: |",
        summary_row,
        "",
        "## Task bindings",
        "",
        "Each task ID is bound to the canonical SHA-256 of the exact task artifact.",
        "",
        "| Task | Task SHA-256 |",
        "| --- | --- |",
        *(
            [f"| `{_cell(task_id)}` | `{digest}` |" for task_id, digest in bindings]
            or ["| — | No task evidence |"]
        ),
        "",
        "## Results",
        "",
        "| Task | Status | Patch | Backend | Runner | Exit | Duration |",
        "| --- | --- | --- | --- | --- | ---: | ---: |",
    ]
    if results:
        for result in results:
            exit_code = "—" if result.exit_code is None else result.exit_code
            lines.append(
                f"| `{_cell(result.task_id)}` | **{result.status.value}** | "
                f"{_cell(result.patch_kind)} | {_cell(result.backend)} | "
                f"`{_cell(_runner(result))}` | {exit_code} | {result.duration_seconds:.3f}s |"
            )
    else:
        lines.append("| — | No results | — | — | — | — | — |")

    non_passing = [result for result in results if result.status != EvaluationStatus.PASSED]
    if non_passing:
        lines.extend(("", "## Non-passing evidence", ""))
        for result in non_passing:
            command_json = json.dumps(list(result.command), ensure_ascii=False)
            environment_json = json.dumps(result.environment.to_dict(), ensure_ascii=False)
            lines.extend(
                (
                    f"### `{result.task_id}` — {result.status.value}",
                    "",
                    f"Command (argument array): `{_cell(command_json)}`",
                    "",
                    f"Environment: `{_cell(environment_json)}`",
                    "",
                    "Standard output:",
                    "",
                    _code_block(result.stdout),
                    "",
                    "Standard error:",
                    "",
                    _code_block(result.stderr),
                    "",
                )
            )
    return "\n".join(lines).rstrip() + "\n"


def _parse_result_value(value: Any, source: Path) -> list[EvaluationResult]:
    if isinstance(value, list):
        return [EvaluationResult.from_dict(item) for item in value]
    if isinstance(value, Mapping) and "results" in value:
        results = value.get("results")
        if not isinstance(results, list):
            raise SchemaError(f"{source}: report results must be an array")
        return [EvaluationResult.from_dict(item) for item in results]
    if isinstance(value, Mapping):
        return [EvaluationResult.from_dict(value)]
    raise SchemaError(f"{source}: expected a result, result array, or report")


def load_results(paths: Iterable[Path]) -> tuple[EvaluationResult, ...]:
    """Load individual result files, arrays, reports, or JSON Lines files."""

    loaded: list[EvaluationResult] = []
    for path_value in paths:
        path = Path(path_value)
        try:
            content = path.read_text(encoding="utf-8")
        except OSError as exc:
            raise SchemaError(f"could not read result {path}: {exc}") from exc
        try:
            value = json.loads(content)
        except json.JSONDecodeError:
            for line_number, line in enumerate(content.splitlines(), start=1):
                if not line.strip():
                    continue
                try:
                    loaded.extend(_parse_result_value(json.loads(line), path))
                except (json.JSONDecodeError, SchemaError) as exc:
                    raise SchemaError(f"{path}:{line_number}: invalid JSON result: {exc}") from exc
        else:
            loaded.extend(_parse_result_value(value, path))
    results = tuple(loaded)
    _task_bindings(results)
    return results
