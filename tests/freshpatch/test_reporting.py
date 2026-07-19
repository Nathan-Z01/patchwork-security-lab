import hashlib
import json
import tempfile
import unittest
from dataclasses import replace
from pathlib import Path

from freshpatch.errors import SchemaError
from freshpatch.evaluator import (
    EffectiveResourcePolicy,
    EvaluationResult,
    EvaluationStatus,
    ExecutionEnvironment,
)
from freshpatch.reporting import load_results, render_json, render_markdown, summarize
from freshpatch.schema import DEFAULT_RUNNER_IMAGE


def environment():
    return ExecutionEnvironment(
        backend="docker",
        image=DEFAULT_RUNNER_IMAGE,
        unsafe_local=False,
        controller_os="linux",
        controller_architecture="x86_64",
        controller_python="3.12.0",
        policy=EffectiveResourcePolicy(
            timeout_seconds=30,
            output_limit=200_000,
            network="none",
            read_only_root=True,
            cap_drop=("ALL",),
            no_new_privileges=True,
            cpus="1.0",
            memory="1g",
            pids_limit=256,
            tmpfs_size="128m",
        ),
    )


def result(task_id, status, duration, stderr="", task_sha256=None):
    return EvaluationResult(
        task_id=task_id,
        task_sha256=task_sha256 or hashlib.sha256(task_id.encode("utf-8")).hexdigest(),
        status=status,
        backend="docker",
        duration_seconds=duration,
        started_at="2025-01-01T00:00:00Z",
        patch_kind="candidate",
        patch_sha256="a" * 64,
        patch_applied=True,
        exit_code=0 if status == EvaluationStatus.PASSED else 1,
        stdout="",
        stderr=stderr,
        command=("python", "-m", "unittest"),
        environment=environment(),
    )


class ReportingTests(unittest.TestCase):
    def test_summary_and_reports(self):
        results = (
            result("passes", EvaluationStatus.PASSED, 1.0),
            result("fails", EvaluationStatus.FAILED, 3.0, "assertion failed"),
        )
        summary = summarize(results)
        self.assertEqual(summary.total, 2)
        self.assertEqual(summary.pass_rate, 0.5)
        self.assertEqual(summary.mean_duration_seconds, 2.0)
        self.assertIn("50.0%", render_markdown(results))
        self.assertIn("assertion failed", render_markdown(results))
        document = json.loads(render_json(results))
        self.assertEqual(document["summary"]["failed"], 1)
        self.assertEqual(
            document["task_bindings"],
            [
                {
                    "task_id": "fails",
                    "task_sha256": hashlib.sha256(b"fails").hexdigest(),
                },
                {
                    "task_id": "passes",
                    "task_sha256": hashlib.sha256(b"passes").hexdigest(),
                },
            ],
        )
        self.assertIn("Task bindings", render_markdown(results))

    def test_loads_report_and_json_lines(self):
        first = result("one", EvaluationStatus.PASSED, 1.0)
        second = result("two", EvaluationStatus.FAILED, 2.0)
        with tempfile.TemporaryDirectory() as temporary:
            report_path = Path(temporary) / "report.json"
            report_path.write_text(render_json((first,)), encoding="utf-8")
            lines_path = Path(temporary) / "results.jsonl"
            lines_path.write_text(
                json.dumps(first.to_dict()) + "\n" + json.dumps(second.to_dict()) + "\n",
                encoding="utf-8",
            )
            report_results = load_results((report_path,))
            line_results = load_results((lines_path,))

        self.assertEqual([item.task_id for item in report_results], ["one"])
        self.assertEqual([item.task_id for item in line_results], ["one", "two"])

    def test_aggregation_rejects_one_task_id_with_mixed_task_digests(self):
        first = result("same", EvaluationStatus.PASSED, 1.0, task_sha256="a" * 64)
        stale = replace(first, task_sha256="b" * 64)

        with self.assertRaisesRegex(SchemaError, "mixes task digests"):
            summarize((first, stale))
        with self.assertRaisesRegex(SchemaError, "mixes task digests"):
            render_json((first, stale))


if __name__ == "__main__":
    unittest.main()
