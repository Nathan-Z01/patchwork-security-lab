import json
import re
import unittest

from freshpatch.errors import SchemaError
from freshpatch.schema import (
    Provenance,
    ReferencePatch,
    RepositorySpec,
    RunnerSpec,
    Task,
    dumps_task,
    loads_task,
    task_digest,
)
from freshpatch.schema import (
    TestSpec as FreshPatchTestSpec,
)


def example_task():
    patch = "diff --git a/a.py b/a.py\n--- a/a.py\n+++ b/a.py\n@@ -1 +1 @@\n-x=1\n+x=2\n"
    return Task(
        task_id="example-repair",
        title="Repair example",
        description="A deterministic fixture.",
        labels=("python",),
        repository=RepositorySpec(
            source=".",
            buggy_revision="a" * 40,
            fixed_revision="b" * 40,
            changed_files=("a.py",),
        ),
        test=FreshPatchTestSpec(
            command=("python", "-m", "unittest"), environment=(("MODE", "test"),)
        ),
        reference_patch=ReferencePatch(diff=patch),
        provenance=Provenance(
            fixed_commit_subject="Repair example",
            fixed_commit_timestamp="2025-01-01T00:00:00+00:00",
        ),
    )


class TaskSchemaTests(unittest.TestCase):
    def test_round_trip_is_deterministic(self):
        task = example_task()
        serialized = dumps_task(task)
        self.assertEqual(loads_task(serialized), task)
        self.assertEqual(dumps_task(loads_task(serialized)), serialized)
        self.assertEqual(task.sha256, task_digest(task))
        self.assertRegex(task.sha256, r"^[0-9a-f]{64}$")

    def test_task_digest_binds_every_canonical_task_field(self):
        task = example_task()
        changed = Task.from_dict({**task.to_dict(), "description": "Different context."})

        self.assertNotEqual(task.sha256, changed.sha256)
        self.assertEqual(task.sha256, loads_task(dumps_task(task)).sha256)

    def test_patch_digest_detects_tampering(self):
        data = example_task().to_dict()
        data["reference_patch"]["diff"] += "tampered\n"
        with self.assertRaisesRegex(SchemaError, "does not match"):
            loads_task(json.dumps(data))

    def test_test_directory_cannot_escape_repository(self):
        with self.assertRaisesRegex(SchemaError, "within the repository"):
            FreshPatchTestSpec(command=("python",), working_directory="../outside")

    def test_test_command_must_be_argument_array(self):
        data = example_task().to_dict()
        data["test"]["command"] = "python -m unittest"
        with self.assertRaisesRegex(SchemaError, "JSON array"):
            loads_task(json.dumps(data))

    def test_unknown_properties_are_rejected_with_exact_paths(self):
        cases = (
            (("typo",), "$.typo"),
            (("repository", "branch"), "$.repository.branch"),
            (("test", "shell"), "$.test.shell"),
            (("reference_patch", "encoding"), "$.reference_patch.encoding"),
            (("provenance", "author"), "$.provenance.author"),
            (("runner", "policy", "gpus"), "$.runner.policy.gpus"),
        )
        for path, expected in cases:
            data = example_task().to_dict()
            target = data
            for part in path[:-1]:
                target = target[part]
            target[path[-1]] = "unexpected"
            with self.subTest(path=path), self.assertRaisesRegex(
                SchemaError,
                rf"{re.escape(expected)} is not allowed",
            ):
                loads_task(json.dumps(data))

    def test_required_properties_are_not_silently_defaulted(self):
        data = example_task().to_dict()
        del data["test"]["timeout_seconds"]
        with self.assertRaisesRegex(SchemaError, r"\$\.test\.timeout_seconds is required"):
            loads_task(json.dumps(data))

    def test_changed_files_must_not_be_empty(self):
        data = example_task().to_dict()
        data["repository"]["changed_files"] = []
        with self.assertRaisesRegex(SchemaError, "at least one path"):
            loads_task(json.dumps(data))

    def test_runner_image_must_be_digest_pinned(self):
        with self.assertRaisesRegex(SchemaError, "immutable"):
            RunnerSpec(image="python:3.12-slim")

    def test_runner_resource_limits_must_be_positive_docker_quantities(self):
        for field, value in (
            ("cpus", "0"),
            ("cpus", "many"),
            ("memory", "-1g"),
            ("tmpfs_size", "128 gigabytes"),
        ):
            with self.subTest(field=field, value=value), self.assertRaises(SchemaError):
                RunnerSpec(**{field: value})

    def test_test_environment_rejects_credential_like_names(self):
        names = (
            "API_TOKEN",
            "SERVICE_API_KEY",
            "DB_SECRET",
            "DB_PASSWORD",
            "AWS_CREDENTIALS_FILE",
            "AUTH_TOKEN",
        )
        for name in names:
            with self.subTest(name=name), self.assertRaisesRegex(SchemaError, "credential-like"):
                FreshPatchTestSpec(command=("python",), environment=((name, "value"),))

        allowed = FreshPatchTestSpec(
            command=("python",),
            environment=(("TOKENIZERS_PARALLELISM", "false"),),
        )
        self.assertEqual(allowed.environment, (("TOKENIZERS_PARALLELISM", "false"),))

    def test_test_environment_rejects_obvious_secret_values(self):
        values = (
            # aisec: ignore[AISEC002] -- validator fixture for recognizable key material
            "-----BEGIN PRIVATE KEY-----\nnot-a-real-key",
            # aisec: ignore[AISEC001] -- validator fixture for recognizable token material
            "ghp_abcdefghijklmnopqrstuvwxyz0123456789",
            "eyJabcdefgh.abcdefghijkl.abcdefghijkl",
        )
        for value in values:
            with (
                self.subTest(value=value[:8]),
                self.assertRaisesRegex(SchemaError, "appears to contain a credential"),
            ):
                FreshPatchTestSpec(
                    command=("python",),
                    environment=(("FIXTURE_VALUE", value),),
                )

    def test_test_environment_rejects_carriage_returns_and_newlines(self):
        for value in ("first\nsecond", "first\rsecond", "first\r\nsecond"):
            with self.subTest(value=repr(value)), self.assertRaisesRegex(
                SchemaError,
                "carriage returns or newlines",
            ):
                FreshPatchTestSpec(command=("python",), environment=(("MODE", value),))


if __name__ == "__main__":
    unittest.main()
