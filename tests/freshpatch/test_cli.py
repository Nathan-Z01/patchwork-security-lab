import contextlib
import io
import json
import tempfile
import unittest
from pathlib import Path

from support import create_repository

from freshpatch.cli import main
from freshpatch.schema import load_task


class CliTests(unittest.TestCase):
    def test_build_and_validate_commands(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            repository = root / "repository"
            _, buggy, fixed = create_repository(repository)
            task_path = root / "task.json"
            stdout = io.StringIO()
            with contextlib.redirect_stdout(stdout):
                build_status = main(
                    (
                        "build",
                        "--repo",
                        str(repository),
                        "--buggy",
                        buggy,
                        "--fixed",
                        fixed,
                        "--test-command",
                        "python3 -m unittest -q",
                        "--id",
                        "cli-repair",
                        "--output",
                        str(task_path),
                    )
                )
            validation = io.StringIO()
            with contextlib.redirect_stdout(validation):
                validate_status = main(("validate", str(task_path)))

            task = load_task(task_path)

        self.assertEqual(build_status, 0)
        self.assertEqual(validate_status, 0)
        self.assertEqual(task.task_id, "cli-repair")
        self.assertEqual(json.loads(validation.getvalue())["id"], "cli-repair")

    def test_local_evaluation_without_acknowledgement_is_rejected(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            task, _, _ = create_repository(root / "repository")
            task_path = root / "task.json"
            task_path.write_text(
                json.dumps(task.to_dict()),
                encoding="utf-8",
            )
            stderr = io.StringIO()
            with contextlib.redirect_stderr(stderr):
                status = main(("evaluate", "--task", str(task_path), "--backend", "local"))

        self.assertEqual(status, 2)
        self.assertIn("arbitrary repository code", stderr.getvalue())

    def test_docker_command_is_a_dry_plan(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            task, _, _ = create_repository(root / "repository")
            task_path = root / "task.json"
            task_path.write_text(json.dumps(task.to_dict()), encoding="utf-8")
            stdout = io.StringIO()
            with contextlib.redirect_stdout(stdout):
                status = main(
                    (
                        "docker-command",
                        "--task",
                        str(task_path),
                        "--workspace",
                        str(root / "workspace"),
                    )
                )

        self.assertEqual(status, 0)
        self.assertIn("--network none", stdout.getvalue())
        self.assertIn("--pull never", stdout.getvalue())
        self.assertIn("@sha256:", stdout.getvalue())

    def test_verify_writes_qualification_evidence(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            task, _, _ = create_repository(root / "repository")
            task_path = root / "task.json"
            output_path = root / "qualification.json"
            task_path.write_text(json.dumps(task.to_dict()), encoding="utf-8")
            status = main(
                (
                    "verify",
                    "--task",
                    str(task_path),
                    "--backend",
                    "local",
                    "--allow-unsafe-local",
                    "--output",
                    str(output_path),
                )
            )
            artifact = json.loads(output_path.read_text(encoding="utf-8"))

        self.assertEqual(status, 0)
        self.assertTrue(artifact["qualified"])
        self.assertEqual(artifact["checks"]["baseline"]["status"], "failed")
        self.assertEqual(artifact["checks"]["reference"]["status"], "passed")
        self.assertTrue(artifact["environment"]["unsafe_local"])


if __name__ == "__main__":
    unittest.main()
