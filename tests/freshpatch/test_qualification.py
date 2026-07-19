import json
import sys
import tempfile
import unittest
from dataclasses import replace
from pathlib import Path

from support import create_repository

from freshpatch.errors import SchemaError, UnsafeExecutionError
from freshpatch.evaluator import EvaluationStatus
from freshpatch.qualification import (
    QualificationStatus,
    dumps_qualification,
    loads_qualification,
    qualify,
)
from freshpatch.schema import TestSpec as FreshPatchTestSpec


class QualificationTests(unittest.TestCase):
    def test_qualification_proves_baseline_fails_and_reference_passes(self):
        with tempfile.TemporaryDirectory() as temporary:
            task, _, _ = create_repository(Path(temporary) / "repository")
            artifact = qualify(task, backend="local", allow_unsafe_local=True)

        self.assertEqual(artifact.status, QualificationStatus.QUALIFIED)
        self.assertTrue(artifact.qualified)
        self.assertEqual(artifact.baseline.status, EvaluationStatus.FAILED)
        self.assertEqual(artifact.reference.status, EvaluationStatus.PASSED)
        self.assertEqual(artifact.baseline.command, task.test.command)
        self.assertEqual(artifact.reference.command, task.test.command)
        self.assertEqual(artifact.task_sha256, task.sha256)
        self.assertEqual(artifact.baseline.task_sha256, task.sha256)
        self.assertEqual(artifact.reference.task_sha256, task.sha256)
        self.assertTrue(artifact.environment.unsafe_local)
        self.assertEqual(
            loads_qualification(dumps_qualification(artifact)).to_dict(),
            artifact.to_dict(),
        )

    def test_qualification_rejects_a_baseline_that_already_passes(self):
        with tempfile.TemporaryDirectory() as temporary:
            task, _, _ = create_repository(Path(temporary) / "repository")
            task = replace(
                task,
                test=FreshPatchTestSpec(
                    command=(sys.executable, "-c", "raise SystemExit(0)"),
                    timeout_seconds=10,
                ),
            )
            artifact = qualify(task, backend="local", allow_unsafe_local=True)

        self.assertEqual(artifact.status, QualificationStatus.REJECTED)
        self.assertFalse(artifact.qualified)
        self.assertIn("baseline must fail", artifact.reason)

    def test_qualification_rejects_missing_or_mismatched_task_bindings(self):
        with tempfile.TemporaryDirectory() as temporary:
            task, _, _ = create_repository(Path(temporary) / "repository")
            artifact = qualify(task, backend="local", allow_unsafe_local=True)

        missing = artifact.to_dict()
        del missing["task_sha256"]
        with self.assertRaisesRegex(SchemaError, r"\$\.task_sha256 is required"):
            loads_qualification(json.dumps(missing))

        stale_reference = replace(artifact.reference, task_sha256="b" * 64)
        with self.assertRaisesRegex(SchemaError, "match qualification task_sha256"):
            replace(artifact, reference=stale_reference)

    def test_qualification_local_backend_requires_explicit_acknowledgement(self):
        with tempfile.TemporaryDirectory() as temporary:
            task, _, _ = create_repository(Path(temporary) / "repository")
            with self.assertRaisesRegex(UnsafeExecutionError, "arbitrary"):
                qualify(task, backend="local")


if __name__ == "__main__":
    unittest.main()
