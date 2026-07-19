import json
import os
import stat
import sys
import tempfile
import time
import unittest
from dataclasses import replace
from pathlib import Path
from unittest import mock

from support import create_repository

from freshpatch.errors import EvaluationError, SchemaError, UnsafeExecutionError
from freshpatch.evaluator import (
    CONTAINER_BOOTSTRAP,
    DockerConfig,
    EvaluationStatus,
    _is_test_harness_path,
    _local_test_environment,
    _write_docker_environment,
    build_docker_command,
    dumps_result,
    evaluate,
    loads_result,
)
from freshpatch.schema import TestSpec as FreshPatchTestSpec


class EvaluatorTests(unittest.TestCase):
    def test_local_backend_requires_explicit_unsafe_opt_in(self):
        with tempfile.TemporaryDirectory() as temporary:
            task, _, _ = create_repository(Path(temporary) / "repository")
            with self.assertRaisesRegex(UnsafeExecutionError, "arbitrary"):
                evaluate(task, backend="local")

    def test_baseline_fails_and_reference_patch_passes(self):
        with tempfile.TemporaryDirectory() as temporary:
            task, _, _ = create_repository(Path(temporary) / "repository")
            baseline = evaluate(task, backend="local", allow_unsafe_local=True)
            repaired = evaluate(
                task,
                candidate_patch=task.reference_patch.diff,
                patch_kind="reference",
                backend="local",
                allow_unsafe_local=True,
            )

        self.assertEqual(baseline.status, EvaluationStatus.FAILED)
        self.assertEqual(repaired.status, EvaluationStatus.PASSED)
        self.assertTrue(repaired.patch_applied)
        self.assertEqual(repaired.patch_sha256, task.reference_patch.sha256)
        self.assertEqual(baseline.task_sha256, task.sha256)
        self.assertEqual(repaired.task_sha256, task.sha256)

    def test_invalid_patch_returns_structured_error(self):
        with tempfile.TemporaryDirectory() as temporary:
            task, _, _ = create_repository(Path(temporary) / "repository")
            result = evaluate(
                task,
                candidate_patch="this is not a patch\n",
                backend="local",
                allow_unsafe_local=True,
            )

        self.assertEqual(result.status, EvaluationStatus.ERROR)
        self.assertFalse(result.patch_applied)
        self.assertIn("could not prepare evaluation", result.stderr)

    def test_docker_command_has_read_only_seed_bounded_workspace_and_constant_bootstrap(self):
        with tempfile.TemporaryDirectory() as temporary:
            task, _, _ = create_repository(Path(temporary) / "repository")
            command = build_docker_command(Path(temporary) / "workspace", task.test)

        self.assertEqual(command[:2], ("docker", "run"))
        self.assertIn("none", command)
        self.assertIn("ALL", command)
        self.assertIn("no-new-privileges:true", command)
        self.assertIn("never", command)
        self.assertIn("none", command[command.index("--log-driver") + 1])
        self.assertIn(
            "dst=/freshpatch-source,readonly",
            command[command.index("--mount") + 1],
        )
        tmpfs_values = [
            command[index + 1]
            for index, item in enumerate(command)
            if item == "--tmpfs"
        ]
        self.assertEqual(len(tmpfs_values), 2)
        self.assertTrue(any(value.startswith("/tmp:") for value in tmpfs_values))
        self.assertTrue(any(value.startswith("/workspace:") for value in tmpfs_values))
        self.assertTrue(all("size=128m" in value for value in tmpfs_values))
        self.assertEqual(command[command.index("--entrypoint") + 1], "/bin/sh")
        self.assertIn(CONTAINER_BOOTSTRAP, command)
        self.assertNotIn(" ".join(task.test.command), CONTAINER_BOOTSTRAP)
        self.assertRegex(task.runner.image, r"@sha256:[0-9a-f]{64}$")
        self.assertIn(task.runner.image, command)
        self.assertEqual(command[-len(task.test.command) :], task.test.command)

    def test_candidate_patch_cannot_modify_test_harness_even_inside_recorded_surface(self):
        test_tampering_patch = """\
diff --git a/tests/test_calculator.py b/tests/test_calculator.py
--- a/tests/test_calculator.py
+++ b/tests/test_calculator.py
@@ -6,2 +6,2 @@ class TestAverage(unittest.TestCase):
     def test_fraction(self):
-        self.assertEqual(average(5, 2), 2.5)
+        self.assertEqual(average(5, 2), 2)
"""
        with tempfile.TemporaryDirectory() as temporary:
            task, _, _ = create_repository(Path(temporary) / "repository")
            task = replace(
                task,
                repository=replace(
                    task.repository,
                    changed_files=("calculator.py", "tests/test_calculator.py"),
                ),
            )
            result = evaluate(
                task,
                candidate_patch=test_tampering_patch,
                backend="local",
                allow_unsafe_local=True,
            )
            trusted_reference = evaluate(
                task,
                candidate_patch=test_tampering_patch,
                patch_kind="reference",
                backend="local",
                allow_unsafe_local=True,
            )

        self.assertEqual(result.status, EvaluationStatus.ERROR)
        self.assertFalse(result.patch_applied)
        self.assertIn("protected test-harness paths", result.stderr)
        self.assertIn("tests/test_calculator.py", result.stderr)
        self.assertEqual(trusted_reference.status, EvaluationStatus.PASSED)
        self.assertTrue(trusted_reference.patch_applied)

    def test_test_harness_matcher_covers_directories_names_and_runner_configuration(self):
        for path in (
            "fixtures/input.json",
            "snapshots/render.snap",
            "goldens/expected.txt",
            "src/widget.spec.ts",
            "conftest.py",
        ):
            with self.subTest(path=path):
                self.assertTrue(_is_test_harness_path(path, ("python", "-m", "unittest")))

        self.assertTrue(_is_test_harness_path("pyproject.toml", ("python", "-m", "pytest")))
        self.assertTrue(_is_test_harness_path("package.json", ("npm", "test")))
        self.assertTrue(_is_test_harness_path("Makefile", ("make", "test")))
        self.assertFalse(_is_test_harness_path("src/calculator.py", ("python", "-m", "pytest")))

    def test_candidate_patch_cannot_escape_recorded_changed_file_surface(self):
        outside_patch = """\
diff --git a/notes.txt b/notes.txt
new file mode 100644
--- /dev/null
+++ b/notes.txt
@@ -0,0 +1 @@
+not part of the repair surface
"""
        with tempfile.TemporaryDirectory() as temporary:
            task, _, _ = create_repository(Path(temporary) / "repository")
            result = evaluate(
                task,
                candidate_patch=outside_patch,
                backend="local",
                allow_unsafe_local=True,
            )

        self.assertEqual(result.status, EvaluationStatus.ERROR)
        self.assertFalse(result.patch_applied)
        self.assertIn("outside repository.changed_files", result.stderr)
        self.assertIn("notes.txt", result.stderr)

    def test_docker_runner_rejects_mutable_image_tags(self):
        with self.assertRaisesRegex(ValueError, "immutable"):
            DockerConfig(image="python:3.12-slim")

    def test_result_records_effective_digest_pinned_docker_policy(self):
        with tempfile.TemporaryDirectory() as temporary:
            task, _, _ = create_repository(Path(temporary) / "repository")
            with mock.patch(
                "freshpatch.evaluator._execute_process",
                return_value=(EvaluationStatus.FAILED, 1, "", "tests failed"),
            ):
                result = evaluate(task)

        self.assertEqual(result.environment.image, task.runner.image)
        self.assertFalse(result.environment.unsafe_local)
        self.assertEqual(result.environment.policy.network, "none")
        self.assertTrue(result.environment.policy.read_only_root)
        self.assertEqual(result.environment.policy.cpus, task.runner.cpus)
        self.assertEqual(result.environment.policy.memory, task.runner.memory)
        self.assertEqual(result.environment.policy.pids_limit, task.runner.pids_limit)

    def test_docker_command_never_places_task_environment_values_in_argv(self):
        path_override = "/malicious/task/bin"
        docker_host_override = "tcp://attacker.invalid:2375"
        test = FreshPatchTestSpec(
            command=("python3", "-m", "unittest"),
            environment=(("PATH", path_override), ("DOCKER_HOST", docker_host_override)),
        )

        dry_run = build_docker_command(Path("/tmp/workspace"), test)
        env_file_run = build_docker_command(
            Path("/tmp/workspace"),
            test,
            environment_file=Path("/tmp/private-task-environment"),
        )

        argv = "\x00".join((*dry_run, *env_file_run))
        self.assertNotIn(path_override, argv)
        self.assertNotIn(docker_host_override, argv)
        self.assertNotIn("DOCKER_HOST", argv)
        self.assertIn("--env-file", dry_run)
        self.assertIn("--env-file", env_file_run)

    def test_docker_environment_file_is_private(self):
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "task-environment"
            _write_docker_environment(path, (("TASK_MODE", "fixture"),))

            self.assertEqual(stat.S_IMODE(path.stat().st_mode), 0o600)
            self.assertEqual(path.read_text(encoding="utf-8"), "TASK_MODE=fixture\n")

    def test_docker_environment_writer_defensively_rejects_multiline_values(self):
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "task-environment"
            with self.assertRaisesRegex(EvaluationError, "newline"):
                _write_docker_environment(path, (("MODE", "first\nsecond"),))

    def test_durable_result_redacts_explicit_environment_values(self):
        private_value = "freshpatch-private-fixture-value"
        script = (
            "import os, sys; value = os.environ['FIXTURE_PAYLOAD']; "
            "print(value); print(value, file=sys.stderr)"
        )
        with tempfile.TemporaryDirectory() as temporary:
            task, _, _ = create_repository(Path(temporary) / "repository")
            task = replace(
                task,
                test=FreshPatchTestSpec(
                    command=(sys.executable, "-c", script),
                    timeout_seconds=10,
                    environment=(("FIXTURE_PAYLOAD", private_value),),
                ),
            )
            result = evaluate(
                task,
                backend="local",
                allow_unsafe_local=True,
            )

        serialized = dumps_result(result)
        self.assertEqual(result.status, EvaluationStatus.PASSED)
        self.assertNotIn(private_value, serialized)
        self.assertIn("[REDACTED]", result.stdout)
        self.assertIn("[REDACTED]", result.stderr)

    def test_output_is_bounded_while_timed_out_process_is_running(self):
        script = (
            "import os, time; "
            "[(os.write(1, b'x' * 4096), os.write(2, b'y' * 4096)) "
            "for _ in range(512)]; time.sleep(10)"
        )
        with tempfile.TemporaryDirectory() as temporary:
            task, _, _ = create_repository(Path(temporary) / "repository")
            task = replace(
                task,
                test=FreshPatchTestSpec(
                    command=(sys.executable, "-c", script),
                    timeout_seconds=1,
                ),
            )
            started = time.monotonic()
            result = evaluate(
                task,
                backend="local",
                allow_unsafe_local=True,
                output_limit=1024,
            )
            duration = time.monotonic() - started

        self.assertEqual(result.status, EvaluationStatus.TIMEOUT)
        self.assertLess(duration, 4)
        self.assertLessEqual(len(result.stdout), 1100)
        self.assertLessEqual(len(result.stderr), 1100)
        self.assertIn("discarded", result.stdout)
        self.assertIn("discarded", result.stderr)

    def test_local_environment_does_not_inherit_secrets_or_coverage_hooks(self):
        original_secret = os.environ.get("OPENAI_API_KEY")
        original_coverage = os.environ.get("COVERAGE_PROCESS_START")
        try:
            os.environ["OPENAI_API_KEY"] = "should-not-reach-test-code"
            os.environ["COVERAGE_PROCESS_START"] = "stale-coverage-config"
            environment = _local_test_environment({"TASK_MODE": "fixture"})
        finally:
            if original_secret is None:
                os.environ.pop("OPENAI_API_KEY", None)
            else:
                os.environ["OPENAI_API_KEY"] = original_secret
            if original_coverage is None:
                os.environ.pop("COVERAGE_PROCESS_START", None)
            else:
                os.environ["COVERAGE_PROCESS_START"] = original_coverage

        self.assertNotIn("OPENAI_API_KEY", environment)
        self.assertNotIn("COVERAGE_PROCESS_START", environment)
        self.assertEqual(environment["TASK_MODE"], "fixture")
        self.assertEqual(environment["PYTHONDONTWRITEBYTECODE"], "1")

    def test_result_records_effective_local_policy_and_round_trips(self):
        with tempfile.TemporaryDirectory() as temporary:
            task, _, _ = create_repository(Path(temporary) / "repository")
            result = evaluate(task, backend="local", allow_unsafe_local=True)

        loaded = loads_result(dumps_result(result))
        self.assertEqual(loaded.to_dict(), result.to_dict())
        self.assertTrue(result.environment.unsafe_local)
        self.assertIsNone(result.environment.image)
        self.assertEqual(result.environment.policy.network, "host")
        self.assertFalse(result.environment.policy.read_only_root)
        self.assertEqual(result.environment.policy.timeout_seconds, task.test.timeout_seconds)

    def test_result_rejects_nonfinite_duration_and_invalid_timestamp(self):
        with tempfile.TemporaryDirectory() as temporary:
            task, _, _ = create_repository(Path(temporary) / "repository")
            result = evaluate(task, backend="local", allow_unsafe_local=True)

        for duration in (float("nan"), float("inf"), -0.1):
            with self.subTest(duration=duration), self.assertRaisesRegex(
                SchemaError,
                "finite and nonnegative",
            ):
                replace(result, duration_seconds=duration)
        for timestamp in (
            "2025-01-01",
            "2025-01-01T00:00:00",
            "not-a-timestamp",
            "2025-13-01T00:00:00Z",
        ):
            with self.subTest(timestamp=timestamp), self.assertRaisesRegex(
                SchemaError,
                "RFC3339|valid",
            ):
                replace(result, started_at=timestamp)

    def test_result_status_and_exit_code_must_agree(self):
        with tempfile.TemporaryDirectory() as temporary:
            task, _, _ = create_repository(Path(temporary) / "repository")
            failed = evaluate(task, backend="local", allow_unsafe_local=True)
            passed = evaluate(
                task,
                candidate_patch=task.reference_patch.diff,
                patch_kind="reference",
                backend="local",
                allow_unsafe_local=True,
            )

        with self.assertRaisesRegex(SchemaError, "passed result"):
            replace(passed, exit_code=1)
        with self.assertRaisesRegex(SchemaError, "failed result"):
            replace(failed, exit_code=0)

    def test_result_reader_rejects_unknown_nested_properties(self):
        with tempfile.TemporaryDirectory() as temporary:
            task, _, _ = create_repository(Path(temporary) / "repository")
            result = evaluate(task, backend="local", allow_unsafe_local=True)
        data = result.to_dict()
        data["environment"]["policy"]["cpu_shares"] = 100
        with self.assertRaisesRegex(
            SchemaError,
            r"\$\.environment\.policy\.cpu_shares is not allowed",
        ):
            loads_result(json.dumps(data))

    def test_result_reader_requires_a_valid_task_digest(self):
        with tempfile.TemporaryDirectory() as temporary:
            task, _, _ = create_repository(Path(temporary) / "repository")
            result = evaluate(task, backend="local", allow_unsafe_local=True)

        missing = result.to_dict()
        del missing["task_sha256"]
        with self.assertRaisesRegex(SchemaError, r"\$\.task_sha256 is required"):
            loads_result(json.dumps(missing))

        invalid = result.to_dict()
        invalid["task_sha256"] = "not-a-digest"
        with self.assertRaisesRegex(SchemaError, "lowercase SHA-256"):
            loads_result(json.dumps(invalid))


if __name__ == "__main__":
    unittest.main()
