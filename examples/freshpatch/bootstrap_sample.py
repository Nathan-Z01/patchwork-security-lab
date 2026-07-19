"""Create the deterministic two-commit repository used in FreshPatch examples."""

# Subprocess calls use argv arrays and never enable a shell.
# ruff: noqa: S404, S603, S607

from __future__ import annotations

import argparse
import os
import shutil
import subprocess
from pathlib import Path
from typing import Dict, Sequence

from freshpatch.builder import build_task
from freshpatch.schema import write_task


EXAMPLE_AUTHOR = "FreshPatch Example"
EXAMPLE_EMAIL = "example@freshpatch.invalid"


def _git_environment(timestamp: str) -> Dict[str, str]:
    environment = os.environ.copy()
    environment.update(
        {
            "GIT_AUTHOR_NAME": EXAMPLE_AUTHOR,
            "GIT_AUTHOR_EMAIL": EXAMPLE_EMAIL,
            "GIT_AUTHOR_DATE": timestamp,
            "GIT_COMMITTER_NAME": EXAMPLE_AUTHOR,
            "GIT_COMMITTER_EMAIL": EXAMPLE_EMAIL,
            "GIT_COMMITTER_DATE": timestamp,
            "GIT_CONFIG_NOSYSTEM": "1",
            "GIT_CONFIG_GLOBAL": os.devnull,
        }
    )
    return environment


def _run(command: Sequence[str], repository: Path, timestamp: str) -> None:
    subprocess.run(
        list(command),
        cwd=str(repository),
        check=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        env=_git_environment(timestamp),
    )


def bootstrap(destination: Path) -> Path:
    destination = destination.resolve()
    if destination.exists():
        raise FileExistsError("destination already exists: {}".format(destination))
    seed = Path(__file__).with_name("sample_seed")
    shutil.copytree(str(seed), str(destination))

    first_date = "2025-01-01T00:00:00+00:00"
    second_date = "2025-01-02T00:00:00+00:00"
    _run(("git", "init", "--quiet"), destination, first_date)
    _run(("git", "add", "calculator.py", "test_calculator.py"), destination, first_date)
    _run(("git", "commit", "--quiet", "-m", "Add buggy average implementation"), destination, first_date)
    buggy = subprocess.check_output(("git", "rev-parse", "HEAD"), cwd=str(destination), text=True).strip()

    patch = Path(__file__).with_name("reference.patch")
    _run(("git", "apply", str(patch)), destination, second_date)
    _run(("git", "add", "calculator.py"), destination, second_date)
    _run(("git", "commit", "--quiet", "-m", "Preserve fractional averages"), destination, second_date)
    fixed = subprocess.check_output(("git", "rev-parse", "HEAD"), cwd=str(destination), text=True).strip()

    task = build_task(
        destination,
        buggy,
        fixed,
        ("python3", "-m", "unittest", "-q"),
        task_id="tiny-average-repair",
        title="Preserve fractional averages",
        description="Repair integer truncation in a tiny arithmetic function.",
        timeout_seconds=30,
        labels=("python", "correctness"),
        published_source=".",
    )
    output = destination / "freshpatch-task.json"
    write_task(task, output)
    return output


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("destination", type=Path)
    arguments = parser.parse_args()
    output = bootstrap(arguments.destination)
    print(output)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
