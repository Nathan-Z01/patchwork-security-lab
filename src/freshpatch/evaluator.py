"""Execution-based repair evaluation with a container-first safety policy."""

# Host subprocesses use argv arrays with ``shell=False``. Docker uses one fixed
# in-container ``/bin/sh -c`` bootstrap; task-controlled values remain positional.
# ruff: noqa: S404, S603, S607

from __future__ import annotations

import hashlib
import json
import math
import os
import platform
import re
import signal
import subprocess
import sys
import tempfile
import time
import uuid
from collections import deque
from collections.abc import Mapping, Sequence
from contextlib import suppress
from dataclasses import dataclass
from datetime import datetime, timezone
from enum import Enum
from pathlib import Path
from threading import Lock, Thread
from typing import Any, BinaryIO
from urllib.parse import unquote, urlparse

from .errors import EvaluationError, SchemaError, UnsafeExecutionError
from .schema import DEFAULT_RUNNER_IMAGE, RunnerSpec, Task, TestSpec, task_digest

RESULT_SCHEMA_VERSION = "1.2"
MAX_PATCH_BYTES = 10 * 1024 * 1024
DEFAULT_OUTPUT_LIMIT = 200_000
_SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
_IMAGE_DIGEST_RE = re.compile(r"^[^@\s]+@sha256:[0-9a-f]{64}$")
_RFC3339_RE = re.compile(
    r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:\d{2})$"
)

# This script is product code, never task or patch input. Arguments remain separate
# positional values so neither the working directory nor test argv is shell-parsed.
CONTAINER_BOOTSTRAP = """\
if ! /bin/cp -R /freshpatch-source/. /workspace/; then
  exit 125
fi
if ! cd "$1"; then
  exit 125
fi
shift
exec "$@"
"""

_TEST_DIRECTORY_NAMES = frozenset(
    {
        "__tests__",
        "fixture",
        "fixtures",
        "golden",
        "goldens",
        "snapshot",
        "snapshots",
        "spec",
        "specs",
        "test",
        "testdata",
        "testing",
        "tests",
    }
)
_TEST_FILE_NAMES = frozenset(
    {
        ".coveragerc",
        "conftest.py",
        "jest.config.js",
        "jest.config.mjs",
        "jest.config.ts",
        "karma.conf.js",
        "nose2.cfg",
        "noxfile.py",
        "phpunit.xml",
        "phpunit.xml.dist",
        "playwright.config.js",
        "playwright.config.ts",
        "pytest.ini",
        "testng.xml",
        "tox.ini",
        "vitest.config.js",
        "vitest.config.mjs",
        "vitest.config.ts",
    }
)


def _is_test_harness_path(path: str, command: Sequence[str]) -> bool:
    """Conservatively identify tests and configuration that can redefine the oracle."""

    normalized = path.replace("\\", "/").strip("/").lower()
    parts = tuple(part for part in normalized.split("/") if part)
    if not parts:
        return True
    basename = parts[-1]
    stem = basename.rsplit(".", 1)[0]
    if any(part in _TEST_DIRECTORY_NAMES for part in parts[:-1]):
        return True
    if basename in _TEST_FILE_NAMES:
        return True
    if basename in {"test.py", "tests.py"} or stem.startswith("test_") or stem.endswith("_test"):
        return True
    if ".test." in basename or ".spec." in basename or basename.endswith((".snap", ".golden")):
        return True

    command_text = " ".join(command).lower()
    if basename in {"pyproject.toml", "setup.cfg"} and any(
        marker in command_text for marker in ("pytest", "unittest", "nose")
    ):
        return True
    if basename in {"package.json", "pnpm-workspace.yaml"} and any(
        marker in command_text
        for marker in ("npm", "pnpm", "yarn", "bun", "jest", "vitest")
    ):
        return True
    if (
        command
        and Path(command[0]).name.lower() in {"make", "gmake"}
        and basename in {"gnumakefile", "makefile"}
    ):
        return True
    return (
        basename == "pom.xml"
        or basename.startswith(("build.gradle", "settings.gradle"))
    ) and any(marker in command_text for marker in ("mvn", "gradle"))


def _strict_object(value: Any, path: str, required: frozenset[str]) -> Mapping[str, Any]:
    if not isinstance(value, Mapping):
        raise SchemaError(f"{path} must be a JSON object")
    for key in value:
        if not isinstance(key, str):
            raise SchemaError(f"{path} contains a non-string property name")
    unknown = sorted(set(value).difference(required))
    if unknown:
        raise SchemaError(f"{path}.{unknown[0]} is not allowed")
    missing = sorted(required.difference(value))
    if missing:
        raise SchemaError(f"{path}.{missing[0]} is required")
    return value


def _validate_rfc3339(value: Any, path: str) -> str:
    if not isinstance(value, str) or not _RFC3339_RE.fullmatch(value):
        raise SchemaError(f"{path} must be an RFC3339 timestamp with a timezone")
    try:
        parsed = datetime.fromisoformat(value[:-1] + "+00:00" if value.endswith("Z") else value)
        if parsed.utcoffset() is None:
            raise ValueError("timezone is missing")
    except ValueError as exc:
        raise SchemaError(f"{path} must be a valid RFC3339 timestamp") from exc
    return value


class EvaluationStatus(str, Enum):
    PASSED = "passed"
    FAILED = "failed"
    TIMEOUT = "timeout"
    ERROR = "error"


@dataclass(frozen=True)
class DockerConfig:
    """Bounded defaults for Docker-based execution.

    Images are never pulled implicitly. Users must deliberately make the selected
    image available to Docker before evaluation. ``tmpfs_size`` is enforced
    independently for both ``/tmp`` and the writable ``/workspace`` copy.
    """

    image: str = DEFAULT_RUNNER_IMAGE
    cpus: str = "1.0"
    memory: str = "1g"
    pids_limit: int = 256
    tmpfs_size: str = "128m"

    def __post_init__(self) -> None:
        for name, value in (
            ("image", self.image),
            ("cpus", self.cpus),
            ("memory", self.memory),
            ("tmpfs_size", self.tmpfs_size),
        ):
            if not isinstance(value, str) or not value or "\x00" in value:
                raise ValueError(f"{name} must not be empty or contain NUL bytes")
        try:
            RunnerSpec(
                image=self.image,
                cpus=self.cpus,
                memory=self.memory,
                pids_limit=self.pids_limit,
                tmpfs_size=self.tmpfs_size,
            )
        except SchemaError as exc:
            raise ValueError(str(exc)) from exc

    @classmethod
    def from_runner(cls, runner: RunnerSpec) -> DockerConfig:
        return cls(
            image=runner.image,
            cpus=runner.cpus,
            memory=runner.memory,
            pids_limit=runner.pids_limit,
            tmpfs_size=runner.tmpfs_size,
        )


@dataclass(frozen=True)
class EffectiveResourcePolicy:
    """The limits and isolation controls that actually governed one run."""

    timeout_seconds: int
    output_limit: int
    network: str
    read_only_root: bool
    cap_drop: tuple[str, ...]
    no_new_privileges: bool
    cpus: str | None = None
    memory: str | None = None
    pids_limit: int | None = None
    tmpfs_size: str | None = None

    def __post_init__(self) -> None:
        if isinstance(self.timeout_seconds, bool) or not isinstance(self.timeout_seconds, int):
            raise SchemaError("result environment.policy.timeout_seconds must be an integer")
        if self.timeout_seconds < 1:
            raise SchemaError("result environment.policy.timeout_seconds must be positive")
        if isinstance(self.output_limit, bool) or not isinstance(self.output_limit, int):
            raise SchemaError("result environment.policy.output_limit must be an integer")
        if self.output_limit < 1:
            raise SchemaError("result environment.policy.output_limit must be positive")
        if self.network not in ("none", "host"):
            raise SchemaError("result environment.policy.network must be 'none' or 'host'")
        if not isinstance(self.read_only_root, bool):
            raise SchemaError("result environment.policy.read_only_root must be a boolean")
        if not isinstance(self.no_new_privileges, bool):
            raise SchemaError(
                "result environment.policy.no_new_privileges must be a boolean"
            )
        if not isinstance(self.cap_drop, tuple) or not all(
            isinstance(item, str) for item in self.cap_drop
        ):
            raise SchemaError("result environment.policy.cap_drop must be strings")
        for name, value in (
            ("cpus", self.cpus),
            ("memory", self.memory),
            ("tmpfs_size", self.tmpfs_size),
        ):
            if value is not None and (not isinstance(value, str) or not value):
                raise SchemaError(f"result environment.policy.{name} must be a string or null")
        if self.pids_limit is not None and (
            isinstance(self.pids_limit, bool) or not isinstance(self.pids_limit, int)
        ):
            raise SchemaError(
                "result environment.policy.pids_limit must be an integer or null"
            )
        if self.pids_limit is not None and not 16 <= self.pids_limit <= 4096:
            raise SchemaError(
                "result environment.policy.pids_limit must be between 16 and 4096"
            )

    def to_dict(self) -> dict[str, Any]:
        return {
            "cap_drop": list(self.cap_drop),
            "cpus": self.cpus,
            "memory": self.memory,
            "network": self.network,
            "no_new_privileges": self.no_new_privileges,
            "output_limit": self.output_limit,
            "pids_limit": self.pids_limit,
            "read_only_root": self.read_only_root,
            "timeout_seconds": self.timeout_seconds,
            "tmpfs_size": self.tmpfs_size,
        }

    @classmethod
    def from_dict(cls, value: Any) -> EffectiveResourcePolicy:
        data = _strict_object(
            value,
            "$.environment.policy",
            frozenset(
                {
                    "cap_drop",
                    "cpus",
                    "memory",
                    "network",
                    "no_new_privileges",
                    "output_limit",
                    "pids_limit",
                    "read_only_root",
                    "timeout_seconds",
                    "tmpfs_size",
                }
            ),
        )
        cap_drop = data.get("cap_drop")
        if not isinstance(cap_drop, list) or not all(isinstance(item, str) for item in cap_drop):
            raise SchemaError("result environment.policy.cap_drop must be an array of strings")
        no_new_privileges = data.get("no_new_privileges")
        if not isinstance(no_new_privileges, bool):
            raise SchemaError(
                "result environment.policy.no_new_privileges must be a boolean"
            )
        output_limit = data.get("output_limit")
        if isinstance(output_limit, bool) or not isinstance(output_limit, int):
            raise SchemaError("result environment.policy.output_limit must be an integer")
        read_only_root = data.get("read_only_root")
        if not isinstance(read_only_root, bool):
            raise SchemaError("result environment.policy.read_only_root must be a boolean")
        timeout_seconds = data.get("timeout_seconds")
        if isinstance(timeout_seconds, bool) or not isinstance(timeout_seconds, int):
            raise SchemaError("result environment.policy.timeout_seconds must be an integer")
        return cls(
            cap_drop=tuple(cap_drop),
            cpus=data.get("cpus"),
            memory=data.get("memory"),
            network=data.get("network", ""),
            no_new_privileges=no_new_privileges,
            output_limit=output_limit,
            pids_limit=data.get("pids_limit"),
            read_only_root=read_only_root,
            timeout_seconds=timeout_seconds,
            tmpfs_size=data.get("tmpfs_size"),
        )


@dataclass(frozen=True)
class ExecutionEnvironment:
    """Stable runner identity plus controller facts needed to reproduce a run."""

    backend: str
    image: str | None
    unsafe_local: bool
    controller_os: str
    controller_architecture: str
    controller_python: str
    policy: EffectiveResourcePolicy

    def __post_init__(self) -> None:
        if self.backend not in ("docker", "local"):
            raise SchemaError("result environment.backend must be 'docker' or 'local'")
        if not isinstance(self.unsafe_local, bool):
            raise SchemaError("result environment.unsafe_local must be a boolean")
        for name, value in (
            ("controller_os", self.controller_os),
            ("controller_architecture", self.controller_architecture),
            ("controller_python", self.controller_python),
        ):
            if not isinstance(value, str) or not value:
                raise SchemaError(f"result environment.{name} must not be empty")
        if self.backend == "docker":
            if not isinstance(self.image, str) or not _IMAGE_DIGEST_RE.fullmatch(self.image):
                raise SchemaError("result Docker image must be digest-pinned")
            if self.unsafe_local:
                raise SchemaError("result Docker environment cannot be marked unsafe_local")
            if (
                self.policy.network != "none"
                or not self.policy.read_only_root
                or self.policy.cap_drop != ("ALL",)
                or not self.policy.no_new_privileges
            ):
                raise SchemaError("result Docker policy is missing required isolation controls")
            if (
                self.policy.cpus is None
                or self.policy.memory is None
                or self.policy.pids_limit is None
                or self.policy.tmpfs_size is None
            ):
                raise SchemaError("result Docker policy must record all resource limits")
            try:
                DockerConfig(
                    image=self.image,
                    cpus=self.policy.cpus,
                    memory=self.policy.memory,
                    pids_limit=self.policy.pids_limit,
                    tmpfs_size=self.policy.tmpfs_size,
                )
            except ValueError as exc:
                raise SchemaError(f"invalid result Docker policy: {exc}") from exc
        else:
            if self.image is not None:
                raise SchemaError("result local environment must not record a container image")
            if not self.unsafe_local:
                raise SchemaError("result local environment must be explicitly marked unsafe_local")
            if self.policy.network != "host" or self.policy.read_only_root:
                raise SchemaError("result local policy must describe host access accurately")
            if any(
                value is not None
                for value in (
                    self.policy.cpus,
                    self.policy.memory,
                    self.policy.pids_limit,
                    self.policy.tmpfs_size,
                )
            ):
                raise SchemaError("result local policy must not claim Docker resource limits")

    def to_dict(self) -> dict[str, Any]:
        return {
            "backend": self.backend,
            "controller": {
                "architecture": self.controller_architecture,
                "os": self.controller_os,
                "python": self.controller_python,
            },
            "image": self.image,
            "policy": self.policy.to_dict(),
            "unsafe_local": self.unsafe_local,
        }

    @classmethod
    def from_dict(cls, value: Any) -> ExecutionEnvironment:
        data = _strict_object(
            value,
            "$.environment",
            frozenset({"backend", "controller", "image", "policy", "unsafe_local"}),
        )
        controller = _strict_object(
            data.get("controller"),
            "$.environment.controller",
            frozenset({"architecture", "os", "python"}),
        )
        unsafe_local = data.get("unsafe_local")
        if not isinstance(unsafe_local, bool):
            raise SchemaError("result environment.unsafe_local must be a boolean")
        return cls(
            backend=data.get("backend", ""),
            image=data.get("image"),
            unsafe_local=unsafe_local,
            controller_os=controller.get("os", ""),
            controller_architecture=controller.get("architecture", ""),
            controller_python=controller.get("python", ""),
            policy=EffectiveResourcePolicy.from_dict(data.get("policy")),
        )


@dataclass(frozen=True)
class EvaluationResult:
    """Machine-readable evidence from one task execution."""

    task_id: str
    task_sha256: str
    status: EvaluationStatus
    backend: str
    duration_seconds: float
    started_at: str
    patch_kind: str
    patch_sha256: str | None
    patch_applied: bool
    exit_code: int | None
    stdout: str
    stderr: str
    command: tuple[str, ...]
    environment: ExecutionEnvironment
    result_schema_version: str = RESULT_SCHEMA_VERSION

    def __post_init__(self) -> None:
        if self.result_schema_version != RESULT_SCHEMA_VERSION:
            raise SchemaError("unsupported result schema version")
        if not isinstance(self.task_id, str) or not self.task_id:
            raise SchemaError("result task_id must not be empty")
        if not isinstance(self.task_sha256, str) or not _SHA256_RE.fullmatch(
            self.task_sha256
        ):
            raise SchemaError("result task_sha256 must be a lowercase SHA-256 value")
        if self.backend not in ("docker", "local"):
            raise SchemaError("result backend must be 'docker' or 'local'")
        if isinstance(self.duration_seconds, bool) or not isinstance(
            self.duration_seconds, (int, float)
        ):
            raise SchemaError("result duration must be numeric")
        if not math.isfinite(float(self.duration_seconds)) or self.duration_seconds < 0:
            raise SchemaError("result duration must be finite and nonnegative")
        _validate_rfc3339(self.started_at, "result started_at")
        if self.patch_kind not in ("none", "candidate", "reference"):
            raise SchemaError("invalid patch_kind")
        if self.patch_kind == "none" and self.patch_sha256 is not None:
            raise SchemaError("an unpatched result must not have a patch digest")
        if self.patch_kind != "none" and self.patch_sha256 is None:
            raise SchemaError("a patched result must include a patch digest")
        if self.patch_sha256 is not None and not _SHA256_RE.fullmatch(self.patch_sha256):
            raise SchemaError("result patch digest must be a lowercase SHA-256 value")
        if not isinstance(self.patch_applied, bool):
            raise SchemaError("result patch.applied must be a boolean")
        if self.exit_code is not None and (
            isinstance(self.exit_code, bool) or not isinstance(self.exit_code, int)
        ):
            raise SchemaError("result exit code must be an integer or null")
        if not isinstance(self.stdout, str) or not isinstance(self.stderr, str):
            raise SchemaError("result output streams must be strings")
        if not isinstance(self.command, tuple) or not all(
            isinstance(argument, str) for argument in self.command
        ):
            raise SchemaError("result command must be a tuple of strings")
        if not isinstance(self.status, EvaluationStatus):
            raise SchemaError("invalid evaluation status")
        if self.environment.backend != self.backend:
            raise SchemaError("result backend must match result environment.backend")
        if self.status == EvaluationStatus.PASSED and self.exit_code != 0:
            raise SchemaError("a passed result must have exit code 0")
        if self.status == EvaluationStatus.FAILED and (
            self.exit_code is None or self.exit_code == 0
        ):
            raise SchemaError("a failed result must have a nonzero exit code")
        if self.status == EvaluationStatus.ERROR and self.exit_code == 0:
            raise SchemaError("an error result must not have exit code 0")
        if self.status in (
            EvaluationStatus.PASSED,
            EvaluationStatus.FAILED,
            EvaluationStatus.TIMEOUT,
        ) and not self.command:
            raise SchemaError("a started test result must record its process command")
        if (
            self.status != EvaluationStatus.ERROR
            and self.patch_kind != "none"
            and not self.patch_applied
        ):
            raise SchemaError("a patched test result must report successful patch application")
        if self.patch_kind == "none" and self.patch_applied:
            raise SchemaError("an unpatched result cannot report patch application")

    def to_dict(self) -> dict[str, Any]:
        return {
            "result_schema_version": self.result_schema_version,
            "task_id": self.task_id,
            "task_sha256": self.task_sha256,
            "status": self.status.value,
            "backend": self.backend,
            "duration_seconds": round(self.duration_seconds, 6),
            "started_at": self.started_at,
            "environment": self.environment.to_dict(),
            "patch": {
                "kind": self.patch_kind,
                "sha256": self.patch_sha256,
                "applied": self.patch_applied,
            },
            "process": {
                "exit_code": self.exit_code,
                "command": list(self.command),
                "stdout": self.stdout,
                "stderr": self.stderr,
            },
        }

    @classmethod
    def from_dict(cls, value: Any) -> EvaluationResult:
        data = _strict_object(
            value,
            "$",
            frozenset(
                {
                    "result_schema_version",
                    "task_id",
                    "task_sha256",
                    "status",
                    "backend",
                    "duration_seconds",
                    "started_at",
                    "environment",
                    "patch",
                    "process",
                }
            ),
        )
        patch = _strict_object(
            data.get("patch"),
            "$.patch",
            frozenset({"kind", "sha256", "applied"}),
        )
        process = _strict_object(
            data.get("process"),
            "$.process",
            frozenset({"exit_code", "command", "stdout", "stderr"}),
        )
        try:
            status = EvaluationStatus(data.get("status"))
            command_value = process.get("command")
            if not isinstance(command_value, list) or not all(
                isinstance(item, str) for item in command_value
            ):
                raise SchemaError("result process.command must be an array of strings")
            duration_value = data.get("duration_seconds")
            if isinstance(duration_value, bool) or not isinstance(duration_value, (int, float)):
                raise SchemaError("result duration_seconds must be numeric")
            patch_applied = patch.get("applied")
            if not isinstance(patch_applied, bool):
                raise SchemaError("result patch.applied must be a boolean")
            return cls(
                result_schema_version=data.get("result_schema_version", ""),
                task_id=data.get("task_id", ""),
                task_sha256=data.get("task_sha256", ""),
                status=status,
                backend=data.get("backend", ""),
                duration_seconds=float(duration_value),
                started_at=data.get("started_at", ""),
                patch_kind=patch.get("kind", ""),
                patch_sha256=patch.get("sha256"),
                patch_applied=patch_applied,
                exit_code=process.get("exit_code"),
                command=tuple(command_value),
                stdout=process.get("stdout", ""),
                stderr=process.get("stderr", ""),
                environment=ExecutionEnvironment.from_dict(data.get("environment")),
            )
        except (TypeError, ValueError) as exc:
            if isinstance(exc, SchemaError):
                raise
            raise SchemaError(f"invalid result: {exc}") from exc


def dumps_result(result: EvaluationResult) -> str:
    return json.dumps(result.to_dict(), indent=2, sort_keys=True, ensure_ascii=False) + "\n"


def loads_result(content: str) -> EvaluationResult:
    try:
        value = json.loads(content)
    except (TypeError, json.JSONDecodeError) as exc:
        raise SchemaError(f"invalid result JSON: {exc}") from exc
    return EvaluationResult.from_dict(value)


def load_result(path: Path) -> EvaluationResult:
    try:
        return loads_result(Path(path).read_text(encoding="utf-8"))
    except OSError as exc:
        raise SchemaError(f"could not read result {path}: {exc}") from exc


def _container_working_directory(test: TestSpec) -> str:
    suffix = test.working_directory.strip("/")
    return "/workspace" if suffix in ("", ".") else f"/workspace/{suffix}"


def build_docker_command(
    workspace: Path,
    test: TestSpec,
    config: DockerConfig | None = None,
    *,
    container_name: str | None = None,
    environment_file: Path | None = None,
) -> tuple[str, ...]:
    """Generate a bounded Docker argv with a constant, non-interpolated bootstrap."""

    selected = config or DockerConfig()
    source = Path(workspace).resolve()
    name = container_name or "freshpatch-plan"
    workdir = _container_working_directory(test)
    command = [
        "docker",
        "run",
        "--rm",
        "--name",
        name,
        "--pull",
        "never",
        "--log-driver",
        "none",
        "--network",
        "none",
        "--cap-drop",
        "ALL",
        "--security-opt",
        "no-new-privileges:true",
        "--pids-limit",
        str(selected.pids_limit),
        "--cpus",
        selected.cpus,
        "--memory",
        selected.memory,
        "--read-only",
        "--tmpfs",
        f"/tmp:rw,nosuid,nodev,mode=1777,size={selected.tmpfs_size}",  # noqa: S108
        "--tmpfs",
        f"/workspace:rw,nosuid,nodev,mode=1777,size={selected.tmpfs_size}",
        "--mount",
        f"type=bind,src={source},dst=/freshpatch-source,readonly",
        "--workdir",
        "/workspace",
        "--entrypoint",
        "/bin/sh",
        "--env",
        "HOME=/tmp",
        "--env",
        "PYTHONDONTWRITEBYTECODE=1",
    ]
    if os.name == "posix":
        command.extend(("--user", f"{os.getuid()}:{os.getgid()}"))
    if test.environment:
        environment_argument = (
            str(Path(environment_file).resolve())
            if environment_file is not None
            else "<private-task-environment-file>"
        )
        command.extend(("--env-file", environment_argument))
    command.append(selected.image)
    command.extend(
        (
            "-c",
            CONTAINER_BOOTSTRAP,
            "freshpatch-bootstrap",
            workdir,
            *test.command,
        )
    )
    return tuple(command)


def _git_environment() -> dict[str, str]:
    environment = os.environ.copy()
    environment.update(
        {
            "GIT_CONFIG_NOSYSTEM": "1",
            "GIT_CONFIG_GLOBAL": os.devnull,
            "GIT_TERMINAL_PROMPT": "0",
        }
    )
    return environment


def _local_test_environment(overrides: Mapping[str, str]) -> dict[str, str]:
    """Build a narrow environment for explicitly authorized local test runs.

    Besides reducing accidental credential exposure to test code, this prevents
    parent-process instrumentation (for example pytest-cov hooks) from leaking
    into the temporary benchmark repository and corrupting the caller's data.
    """

    inherited = (
        "LANG",
        "LC_ALL",
        "PATH",
        "PATHEXT",
        "SYSTEMROOT",
        "TEMP",
        "TMP",
        "TMPDIR",
        "TZ",
        "VIRTUAL_ENV",
        "WINDIR",
    )
    environment = {key: os.environ[key] for key in inherited if key in os.environ}
    environment["PYTHONDONTWRITEBYTECODE"] = "1"
    environment.update(overrides)
    return environment


def _run_setup(command: Sequence[str], *, cwd: Path | None = None) -> str:
    try:
        completed = subprocess.run(
            list(command),
            cwd=str(cwd) if cwd is not None else None,
            check=False,
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=60,
            env=_git_environment(),
        )
    except FileNotFoundError as exc:
        raise EvaluationError("Git is required to prepare an evaluation") from exc
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise EvaluationError(f"could not prepare evaluation: {exc}") from exc
    if completed.returncode != 0:
        detail = (
            completed.stderr.strip()
            or completed.stdout.strip()
            or f"exit code {completed.returncode}"
        )
        raise EvaluationError(f"could not prepare evaluation: {detail}")
    return completed.stdout


def _resolve_repository_source(
    task: Task, repository_override: Path | None, task_base_directory: Path | None
) -> Path:
    if repository_override is not None:
        source = Path(repository_override).expanduser()
    else:
        raw = task.repository.source
        parsed = urlparse(raw)
        if parsed.scheme == "file":
            source = Path(unquote(parsed.path))
        elif parsed.scheme or raw.startswith("git@"):
            raise EvaluationError(
                "remote repository sources are not cloned automatically; "
                "pass a trusted local repository override"
            )
        else:
            source = Path(raw).expanduser()
            if not source.is_absolute() and task_base_directory is not None:
                source = Path(task_base_directory) / source
    resolved = source.resolve()
    if not resolved.is_dir():
        raise EvaluationError(f"local repository source does not exist: {resolved}")
    return resolved


def _prepare_workspace(source: Path, revision: str, destination: Path) -> None:
    _run_setup(
        (
            "git",
            "-c",
            f"core.hooksPath={os.devnull}",
            "clone",
            "--quiet",
            "--no-checkout",
            "--no-hardlinks",
            "--",
            str(source),
            str(destination),
        )
    )
    _run_setup(
        (
            "git",
            "-c",
            f"core.hooksPath={os.devnull}",
            "-c",
            "filter.lfs.smudge=",
            "-c",
            "filter.lfs.required=false",
            "checkout",
            "--quiet",
            "--detach",
            revision,
        ),
        cwd=destination,
    )


def _apply_patch(
    workspace: Path,
    patch: str,
    patch_file: Path,
    *,
    allowed_paths: Sequence[str],
    protect_test_harness: bool,
    test_command: Sequence[str],
) -> tuple[str, ...]:
    encoded = patch.encode("utf-8")
    if len(encoded) > MAX_PATCH_BYTES:
        raise EvaluationError(f"candidate patch exceeds the {MAX_PATCH_BYTES} byte limit")
    patch_file.write_bytes(encoded)
    _run_setup(
        (
            "git",
            "-c",
            f"core.hooksPath={os.devnull}",
            "apply",
            "--index",
            "--recount",
            "--whitespace=nowarn",
            str(patch_file),
        ),
        cwd=workspace,
    )
    changed_output = _run_setup(
        (
            "git",
            "diff",
            "--cached",
            "--name-only",
            "--no-renames",
            "-z",
            "HEAD",
            "--",
        ),
        cwd=workspace,
    )
    changed_paths = tuple(path for path in changed_output.split("\x00") if path)
    if not changed_paths:
        raise EvaluationError("candidate patch did not change any repository paths")
    allowed = frozenset(allowed_paths)
    outside_surface = sorted(set(changed_paths).difference(allowed))
    if outside_surface:
        rendered = ", ".join(repr(path) for path in outside_surface[:10])
        if len(outside_surface) > 10:
            rendered += f", and {len(outside_surface) - 10} more"
        raise EvaluationError(
            "patch changes paths outside repository.changed_files: " + rendered
        )
    if protect_test_harness:
        protected = sorted(
            path for path in changed_paths if _is_test_harness_path(path, test_command)
        )
        if protected:
            rendered = ", ".join(repr(path) for path in protected[:10])
            if len(protected) > 10:
                rendered += f", and {len(protected) - 10} more"
            raise EvaluationError(
                "candidate patch changes protected test-harness paths: " + rendered
            )
    return changed_paths


def _truncate(value: str, limit: int) -> str:
    if len(value) <= limit:
        return value
    removed = len(value) - limit
    return (
        f"[FreshPatch discarded {removed} earlier characters; showing bounded tail]\n"
        + value[-limit:]
    )


class _BoundedCapture:
    """Continuously drain a byte stream while retaining only its bounded tail."""

    def __init__(self, limit: int) -> None:
        self._limit = limit
        self._chunks: deque[bytes] = deque()
        self._retained = 0
        self._total = 0
        self._lock = Lock()

    def consume(self, stream: BinaryIO) -> None:
        try:
            while True:
                chunk = stream.read(64 * 1024)
                if not chunk:
                    return
                with self._lock:
                    self._total += len(chunk)
                    self._chunks.append(chunk)
                    self._retained += len(chunk)
                    while self._retained > self._limit:
                        overflow = self._retained - self._limit
                        first = self._chunks[0]
                        if overflow >= len(first):
                            self._chunks.popleft()
                            self._retained -= len(first)
                        else:
                            self._chunks[0] = first[overflow:]
                            self._retained -= overflow
        except (OSError, ValueError):
            # The parent may close a pipe after the wall-clock deadline to ensure
            # a descendant cannot keep the capture thread alive indefinitely.
            return
        finally:
            with suppress(OSError):
                stream.close()

    def render(self) -> str:
        with self._lock:
            content = b"".join(self._chunks)
            omitted = self._total - self._retained
        decoded = content.decode("utf-8", errors="replace")
        if omitted:
            return (
                f"[FreshPatch discarded {omitted} earlier bytes; showing bounded tail]\n{decoded}"
            )
        return decoded


def _terminate_process_group(process: subprocess.Popen[bytes]) -> None:
    if os.name == "posix":
        with suppress(ProcessLookupError):
            os.killpg(process.pid, signal.SIGKILL)
    else:
        with suppress(OSError):
            process.kill()
    with suppress(OSError, subprocess.TimeoutExpired):
        process.wait(timeout=2)


def _close_capture_pipes(process: subprocess.Popen[bytes]) -> None:
    for stream in (process.stdout, process.stderr):
        if stream is not None:
            with suppress(OSError):
                stream.close()


def _execute_process(
    command: Sequence[str],
    *,
    cwd: Path | None,
    timeout_seconds: int,
    output_limit: int,
    environment: Mapping[str, str] | None = None,
) -> tuple[EvaluationStatus, int | None, str, str]:
    try:
        process = subprocess.Popen(
            list(command),
            cwd=str(cwd) if cwd is not None else None,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            env=dict(environment) if environment is not None else None,
            start_new_session=(os.name == "posix"),
        )
    except OSError as exc:
        return EvaluationStatus.ERROR, None, "", f"could not start process: {exc}"

    if process.stdout is None or process.stderr is None:  # pragma: no cover - Popen contract
        _terminate_process_group(process)
        return EvaluationStatus.ERROR, process.returncode, "", "process pipes were unavailable"

    stdout_capture = _BoundedCapture(output_limit)
    stderr_capture = _BoundedCapture(output_limit)
    readers = (
        Thread(
            target=stdout_capture.consume,
            args=(process.stdout,),
            name="freshpatch-stdout",
            daemon=True,
        ),
        Thread(
            target=stderr_capture.consume,
            args=(process.stderr,),
            name="freshpatch-stderr",
            daemon=True,
        ),
    )
    for reader in readers:
        reader.start()

    deadline = time.monotonic() + timeout_seconds
    timed_out = False
    try:
        process.wait(timeout=timeout_seconds)
    except subprocess.TimeoutExpired:
        timed_out = True
        _terminate_process_group(process)

    if not timed_out:
        for reader in readers:
            reader.join(timeout=max(0.0, deadline - time.monotonic()))
        if any(reader.is_alive() for reader in readers):
            timed_out = True
            _terminate_process_group(process)

    if timed_out:
        # A killed process group normally closes both pipes. The bounded grace
        # period also covers platforms where only the direct child can be killed.
        for reader in readers:
            reader.join(timeout=0.5)
        if any(reader.is_alive() for reader in readers):
            _close_capture_pipes(process)
            for reader in readers:
                reader.join(timeout=0.5)

    stdout = stdout_capture.render()
    stderr = stderr_capture.render()
    if timed_out:
        return EvaluationStatus.TIMEOUT, process.returncode, stdout, stderr
    status = EvaluationStatus.PASSED if process.returncode == 0 else EvaluationStatus.FAILED
    return status, process.returncode, stdout, stderr


def _redact_task_environment(value: str, environment: Sequence[tuple[str, str]]) -> str:
    """Remove explicit task environment values before evidence is persisted."""

    redacted = value
    secrets = sorted(
        {secret for _name, secret in environment if secret},
        key=len,
        reverse=True,
    )
    for secret in secrets:
        redacted = redacted.replace(secret, "[REDACTED]")
    return redacted


def _write_docker_environment(path: Path, environment: Sequence[tuple[str, str]]) -> None:
    """Write task values to a private, short-lived Docker env file."""

    lines = []
    for name, value in environment:
        if "\n" in value or "\r" in value:
            raise EvaluationError(
                f"Docker environment value {name!r} contains a newline and cannot be "
                "forwarded safely"
            )
        lines.append(f"{name}={value}")
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")
    path.chmod(0o600)


def _local_working_directory(workspace: Path, test: TestSpec) -> Path:
    candidate = (workspace / test.working_directory).resolve()
    try:
        candidate.relative_to(workspace.resolve())
    except ValueError as exc:
        raise EvaluationError(
            "test working directory resolves outside the temporary repository"
        ) from exc
    if not candidate.is_dir():
        raise EvaluationError(f"test working directory does not exist: {test.working_directory}")
    return candidate


def _started_at() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


def _execution_environment(
    backend: str,
    test: TestSpec,
    output_limit: int,
    docker_config: DockerConfig | None,
) -> ExecutionEnvironment:
    controller_os = sys.platform
    controller_architecture = platform.machine() or "unknown"
    controller_python = platform.python_version()
    if backend == "docker":
        if docker_config is None:  # pragma: no cover - internal contract
            raise EvaluationError("Docker execution requires a runner configuration")
        policy = EffectiveResourcePolicy(
            timeout_seconds=test.timeout_seconds,
            output_limit=output_limit,
            network="none",
            read_only_root=True,
            cap_drop=("ALL",),
            no_new_privileges=True,
            cpus=docker_config.cpus,
            memory=docker_config.memory,
            pids_limit=docker_config.pids_limit,
            tmpfs_size=docker_config.tmpfs_size,
        )
        return ExecutionEnvironment(
            backend="docker",
            image=docker_config.image,
            unsafe_local=False,
            controller_os=controller_os,
            controller_architecture=controller_architecture,
            controller_python=controller_python,
            policy=policy,
        )
    policy = EffectiveResourcePolicy(
        timeout_seconds=test.timeout_seconds,
        output_limit=output_limit,
        network="host",
        read_only_root=False,
        cap_drop=tuple(),
        no_new_privileges=False,
    )
    return ExecutionEnvironment(
        backend="local",
        image=None,
        unsafe_local=True,
        controller_os=controller_os,
        controller_architecture=controller_architecture,
        controller_python=controller_python,
        policy=policy,
    )


def _remove_timed_out_container(container_name: str) -> None:
    try:
        subprocess.run(
            ("docker", "rm", "--force", container_name),
            check=False,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            timeout=15,
        )
    except (OSError, subprocess.SubprocessError):
        # The original timeout remains the most useful result. A unique generated
        # name keeps any manual cleanup narrowly scoped.
        return


def evaluate(
    task: Task,
    *,
    candidate_patch: str | None = None,
    patch_kind: str = "candidate",
    backend: str = "docker",
    allow_unsafe_local: bool = False,
    repository_override: Path | None = None,
    task_base_directory: Path | None = None,
    docker_config: DockerConfig | None = None,
    output_limit: int = DEFAULT_OUTPUT_LIMIT,
) -> EvaluationResult:
    """Evaluate a repair against the buggy revision.

    Docker is the default. The local backend executes repository code directly on
    the host and therefore raises :class:`UnsafeExecutionError` unless the caller
    opts in with ``allow_unsafe_local=True``.
    """

    if backend not in ("docker", "local"):
        raise EvaluationError("backend must be 'docker' or 'local'")
    if backend == "local" and not allow_unsafe_local:
        raise UnsafeExecutionError(
            "local execution can run arbitrary repository code; set "
            "allow_unsafe_local=True only for trusted tasks"
        )
    if output_limit < 1:
        raise EvaluationError("output_limit must be positive")
    selected_docker_config = (
        docker_config or DockerConfig.from_runner(task.runner) if backend == "docker" else None
    )
    environment_identity = _execution_environment(
        backend,
        task.test,
        output_limit,
        selected_docker_config,
    )
    if candidate_patch is None:
        selected_patch_kind = "none"
        patch_sha256 = None
    else:
        if patch_kind not in ("candidate", "reference"):
            raise EvaluationError("patch_kind must be 'candidate' or 'reference'")
        selected_patch_kind = patch_kind
        patch_sha256 = hashlib.sha256(candidate_patch.encode("utf-8")).hexdigest()

    started_at = _started_at()
    started_clock = time.monotonic()
    task_sha256 = task_digest(task)
    patch_applied = False
    process_command: tuple[str, ...] = tuple()
    container_name: str | None = None
    try:
        source = _resolve_repository_source(task, repository_override, task_base_directory)
        with tempfile.TemporaryDirectory(prefix="freshpatch-") as temporary:
            temporary_path = Path(temporary)
            workspace = temporary_path / "workspace"
            _prepare_workspace(source, task.repository.buggy_revision, workspace)
            if candidate_patch is not None:
                _apply_patch(
                    workspace,
                    candidate_patch,
                    temporary_path / "candidate.patch",
                    allowed_paths=task.repository.changed_files,
                    protect_test_harness=selected_patch_kind == "candidate",
                    test_command=task.test.command,
                )
                patch_applied = True

            if backend == "docker":
                container_name = f"freshpatch-{uuid.uuid4().hex[:16]}"
                environment_file = temporary_path / "task-environment"
                if task.test.environment:
                    _write_docker_environment(environment_file, task.test.environment)
                process_command = build_docker_command(
                    workspace,
                    task.test,
                    selected_docker_config,
                    container_name=container_name,
                    environment_file=environment_file,
                )
                status, exit_code, stdout, stderr = _execute_process(
                    process_command,
                    cwd=None,
                    timeout_seconds=task.test.timeout_seconds,
                    output_limit=output_limit,
                )
                if status == EvaluationStatus.TIMEOUT:
                    _remove_timed_out_container(container_name)
                elif exit_code in (125, 126, 127):
                    status = EvaluationStatus.ERROR
            else:
                process_command = tuple(task.test.command)
                local_environment = _local_test_environment(dict(task.test.environment))
                status, exit_code, stdout, stderr = _execute_process(
                    process_command,
                    cwd=_local_working_directory(workspace, task.test),
                    timeout_seconds=task.test.timeout_seconds,
                    output_limit=output_limit,
                    environment=local_environment,
                )
    except EvaluationError as exc:
        status = EvaluationStatus.ERROR
        exit_code = None
        stdout = ""
        stderr = str(exc)
    except (OSError, subprocess.SubprocessError) as exc:
        status = EvaluationStatus.ERROR
        exit_code = None
        stdout = ""
        stderr = f"evaluation infrastructure failed: {exc}"

    durable_stdout = _truncate(
        _redact_task_environment(stdout, task.test.environment),
        output_limit,
    )
    durable_stderr = _truncate(
        _redact_task_environment(stderr, task.test.environment),
        output_limit,
    )
    durable_command = tuple(
        _redact_task_environment(argument, task.test.environment) for argument in process_command
    )
    return EvaluationResult(
        task_id=task.task_id,
        task_sha256=task_sha256,
        status=status,
        backend=backend,
        duration_seconds=time.monotonic() - started_clock,
        started_at=started_at,
        patch_kind=selected_patch_kind,
        patch_sha256=patch_sha256,
        patch_applied=patch_applied,
        exit_code=exit_code,
        stdout=durable_stdout,
        stderr=durable_stderr,
        command=durable_command,
        environment=environment_identity,
    )
