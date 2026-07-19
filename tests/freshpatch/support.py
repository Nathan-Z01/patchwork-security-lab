from __future__ import annotations

# Test-only Git fixture construction uses argv arrays and never enables a shell.
# ruff: noqa: S404, S603, S607
import os
import subprocess
import sys
from pathlib import Path

from freshpatch.builder import build_task
from freshpatch.schema import Task

BUGGY_SOURCE = """def average(total, count):
    return total // count
"""
FIXED_SOURCE = """def average(total, count):
    return total / count
"""
TEST_SOURCE = """import unittest
from calculator import average


class TestAverage(unittest.TestCase):
    def test_fraction(self):
        self.assertEqual(average(5, 2), 2.5)
"""


def _environment(timestamp: str) -> dict[str, str]:
    environment = os.environ.copy()
    environment.update(
        {
            "GIT_AUTHOR_NAME": "FreshPatch Tests",
            "GIT_AUTHOR_EMAIL": "tests@freshpatch.invalid",
            "GIT_AUTHOR_DATE": timestamp,
            "GIT_COMMITTER_NAME": "FreshPatch Tests",
            "GIT_COMMITTER_EMAIL": "tests@freshpatch.invalid",
            "GIT_COMMITTER_DATE": timestamp,
            "GIT_CONFIG_NOSYSTEM": "1",
            "GIT_CONFIG_GLOBAL": os.devnull,
        }
    )
    return environment


def _git(repository: Path, *arguments: str, timestamp: str = "2025-01-01T00:00:00+00:00") -> str:
    completed = subprocess.run(
        ("git",) + arguments,
        cwd=str(repository),
        check=True,
        capture_output=True,
        text=True,
        encoding="utf-8",
        env=_environment(timestamp),
    )
    return completed.stdout.strip()


def create_repository(path: Path) -> tuple[Task, str, str]:
    path.mkdir()
    (path / "tests").mkdir()
    (path / "calculator.py").write_text(BUGGY_SOURCE, encoding="utf-8")
    (path / "tests" / "test_calculator.py").write_text(TEST_SOURCE, encoding="utf-8")
    _git(path, "init", "--quiet")
    _git(path, "add", "calculator.py", "tests/test_calculator.py")
    _git(path, "commit", "--quiet", "-m", "Add buggy implementation")
    buggy = _git(path, "rev-parse", "HEAD")
    (path / "calculator.py").write_text(FIXED_SOURCE, encoding="utf-8")
    _git(path, "add", "calculator.py", timestamp="2025-01-02T00:00:00+00:00")
    _git(
        path,
        "commit",
        "--quiet",
        "-m",
        "Preserve fractional averages",
        timestamp="2025-01-02T00:00:00+00:00",
    )
    fixed = _git(path, "rev-parse", "HEAD")
    task = build_task(
        path,
        buggy,
        fixed,
        (sys.executable, "-m", "unittest", "discover", "-s", "tests", "-q"),
        task_id="average-repair",
        timeout_seconds=10,
        labels=("python",),
    )
    return task, buggy, fixed
