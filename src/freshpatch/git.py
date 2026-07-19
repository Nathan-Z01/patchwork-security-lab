"""Small, defensive Git adapter used by the task builder."""

# Subprocess calls use argv arrays and never enable a shell.
# ruff: noqa: S404, S603, S607

from __future__ import annotations

import os
import re
import subprocess
from collections.abc import Sequence
from pathlib import Path

from .errors import RepositoryError

_COMMIT_RE = re.compile(r"^[0-9a-f]{40,64}$")


def _safe_revision(value: str) -> str:
    if (
        not value
        or value.startswith("-")
        or "\x00" in value
        or any(character.isspace() for character in value)
    ):
        raise RepositoryError(f"invalid Git revision: {value!r}")
    return value


class GitRepository:
    """Read-only operations against one local Git worktree."""

    def __init__(self, path: Path) -> None:
        candidate = Path(path).expanduser().resolve()
        if not candidate.exists():
            raise RepositoryError(f"repository path does not exist: {candidate}")
        discovered = self._run_at(candidate, ("rev-parse", "--show-toplevel"))
        self.root = Path(discovered.strip()).resolve()

    @staticmethod
    def _environment() -> dict:
        environment = os.environ.copy()
        environment.update(
            {
                "GIT_CONFIG_NOSYSTEM": "1",
                "GIT_CONFIG_GLOBAL": os.devnull,
                "GIT_TERMINAL_PROMPT": "0",
                "LC_ALL": "C.UTF-8",
            }
        )
        return environment

    @classmethod
    def _run_at(cls, path: Path, arguments: Sequence[str], *, check: bool = True) -> str:
        command = ["git", "-C", str(path)] + list(arguments)
        try:
            completed = subprocess.run(
                command,
                check=False,
                capture_output=True,
                text=True,
                encoding="utf-8",
                errors="strict",
                timeout=30,
                env=cls._environment(),
            )
        except FileNotFoundError as exc:
            raise RepositoryError("Git is required but was not found on PATH") from exc
        except (OSError, subprocess.TimeoutExpired, UnicodeError) as exc:
            raise RepositoryError(f"Git command failed: {exc}") from exc
        if check and completed.returncode != 0:
            detail = completed.stderr.strip() or f"exit code {completed.returncode}"
            raise RepositoryError(f"Git command failed: {detail}")
        return completed.stdout

    def run(self, *arguments: str, check: bool = True) -> str:
        return self._run_at(self.root, arguments, check=check)

    def resolve_commit(self, revision: str) -> str:
        safe = _safe_revision(revision)
        commit = self.run("rev-parse", "--verify", f"{safe}^{{commit}}").strip()
        if not _COMMIT_RE.fullmatch(commit):
            raise RepositoryError(f"Git returned an invalid commit id for {revision!r}")
        return commit

    def require_ancestor(self, older: str, newer: str) -> None:
        command = ["git", "-C", str(self.root), "merge-base", "--is-ancestor", older, newer]
        try:
            completed = subprocess.run(
                command,
                check=False,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.PIPE,
                text=True,
                encoding="utf-8",
                errors="replace",
                timeout=30,
                env=self._environment(),
            )
        except (OSError, subprocess.TimeoutExpired) as exc:
            raise RepositoryError(f"could not compare Git revisions: {exc}") from exc
        if completed.returncode == 1:
            raise RepositoryError("buggy revision must be an ancestor of the fixed revision")
        if completed.returncode != 0:
            raise RepositoryError(f"could not compare Git revisions: {completed.stderr.strip()}")

    def reference_patch(self, buggy: str, fixed: str) -> str:
        patch = self.run(
            "-c",
            "diff.external=",
            "diff",
            "--binary",
            "--full-index",
            "--no-ext-diff",
            "--no-color",
            buggy,
            fixed,
            "--",
        )
        if not patch:
            raise RepositoryError("the selected commits do not contain a patch")
        return patch

    def changed_files(self, buggy: str, fixed: str) -> tuple[str, ...]:
        output = self.run("diff", "--name-only", "-z", "--no-ext-diff", buggy, fixed, "--")
        files = tuple(item for item in output.split("\x00") if item)
        if not files:
            raise RepositoryError("the selected commits do not change any files")
        return files

    def commit_metadata(self, commit: str) -> tuple[str, str]:
        output = self.run("show", "-s", "--format=%s%x00%cI", commit).rstrip("\n")
        parts = output.split("\x00", 1)
        if len(parts) != 2 or not parts[0] or not parts[1]:
            raise RepositoryError("could not read fixed commit metadata")
        return parts[0], parts[1]
