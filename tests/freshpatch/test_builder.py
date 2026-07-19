import tempfile
import unittest
from pathlib import Path

from support import create_repository

from freshpatch.builder import build_task


class BuilderTests(unittest.TestCase):
    def test_builds_task_from_local_commits(self):
        with tempfile.TemporaryDirectory() as temporary:
            repository = Path(temporary) / "repository"
            task, buggy, fixed = create_repository(repository)

        self.assertEqual(task.repository.buggy_revision, buggy)
        self.assertEqual(task.repository.fixed_revision, fixed)
        self.assertEqual(task.repository.changed_files, ("calculator.py",))
        self.assertIn("return total / count", task.reference_patch.diff)
        self.assertEqual(task.provenance.fixed_commit_subject, "Preserve fractional averages")
        self.assertEqual(task.task_id, "average-repair")
        self.assertIn("@sha256:", task.runner.image)
        self.assertEqual(task.runner.network, "none")

    def test_default_identifier_uses_repo_and_fixed_commit(self):
        with tempfile.TemporaryDirectory() as temporary:
            repository = Path(temporary) / "Example Repository"
            task, buggy, fixed = create_repository(repository)
            generated = build_task(repository, buggy, fixed, ("python", "-m", "unittest"))

        self.assertEqual(generated.task_id, f"example-repository-{fixed[:12]}")


if __name__ == "__main__":
    unittest.main()
