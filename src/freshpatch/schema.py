"""Versioned, dependency-free FreshPatch task artifacts."""

from __future__ import annotations

import hashlib
import json
import math
import os
import re
import tempfile
from collections.abc import Mapping
from contextlib import suppress
from dataclasses import dataclass, field
from pathlib import Path, PurePosixPath
from typing import Any

from .errors import SchemaError

SCHEMA_VERSION = "1.1"
DEFAULT_RUNNER_IMAGE = (
    "python:3.12-slim@"
    "sha256:57cd7c3a7a273101a6485ba99423ee568157882804b1124b4dd04266317710de"
)
_TASK_ID_RE = re.compile(r"^[a-z0-9][a-z0-9._-]{0,127}$")
_REVISION_RE = re.compile(r"^[0-9a-f]{7,64}$")
_IMAGE_DIGEST_RE = re.compile(r"^[^@\s]+@sha256:[0-9a-f]{64}$")
_RESOURCE_QUANTITY_RE = re.compile(r"^(?P<number>[0-9]+(?:\.[0-9]+)?)(?P<unit>[bkmg]?)$")
_ENV_NAME_RE = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*$")
_SECRET_NAME_PARTS = frozenset({"PASSWORD", "PASSWD", "SECRET", "TOKEN"})
_SECRET_KEY_PAIRS = frozenset({("API", "KEY"), ("ACCESS", "KEY"), ("PRIVATE", "KEY")})
_OBVIOUS_SECRET_VALUE_RES = (
    re.compile(r"-----BEGIN (?:[A-Z0-9]+ )?PRIVATE KEY-----"),
    re.compile(
        r"^(?:"
        r"gh[pousr]_[A-Za-z0-9]{20,}|"
        r"github_pat_[A-Za-z0-9_]{20,}|"
        r"sk-[A-Za-z0-9_-]{20,}|"
        r"xox[baprs]-[A-Za-z0-9-]{10,}|"
        r"AKIA[A-Z0-9]{16}|"
        r"AIza[A-Za-z0-9_-]{20,}"
        r")$"
    ),
    re.compile(r"^eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}$"),
)


def _environment_name_looks_sensitive(name: str) -> bool:
    parts = tuple(part for part in name.upper().split("_") if part)
    if any(part in _SECRET_NAME_PARTS or part.startswith("CREDENTIAL") for part in parts):
        return True
    return any(pair in zip(parts, parts[1:]) for pair in _SECRET_KEY_PAIRS)


def _environment_value_looks_sensitive(value: str) -> bool:
    candidate = value.strip()
    return any(pattern.search(candidate) is not None for pattern in _OBVIOUS_SECRET_VALUE_RES)


def _expect_mapping(value: Any, name: str) -> Mapping[str, Any]:
    if not isinstance(value, Mapping):
        raise SchemaError(f"{name} must be a JSON object")
    return value


def _strict_mapping(
    value: Any,
    path: str,
    *,
    required: frozenset[str],
) -> Mapping[str, Any]:
    """Return an object whose properties exactly match a documented schema.

    JSON Schema errors are most useful when they identify the exact property.
    Runtime readers mirror that behavior rather than silently discarding typos.
    """

    data = _expect_mapping(value, path)
    for key in data:
        if not isinstance(key, str):
            raise SchemaError(f"{path} contains a non-string property name")
    unknown = sorted(set(data).difference(required))
    if unknown:
        raise SchemaError(f"{path}.{unknown[0]} is not allowed")
    missing = sorted(required.difference(data))
    if missing:
        raise SchemaError(f"{path}.{missing[0]} is required")
    return data


def _expect_string(value: Any, name: str, *, allow_empty: bool = False) -> str:
    if not isinstance(value, str):
        raise SchemaError(f"{name} must be a string")
    if not allow_empty and not value.strip():
        raise SchemaError(f"{name} must not be empty")
    if "\x00" in value:
        raise SchemaError(f"{name} must not contain NUL bytes")
    return value


def _expect_string_sequence(value: Any, name: str) -> tuple[str, ...]:
    if not isinstance(value, (list, tuple)):
        raise SchemaError(f"{name} must be a JSON array")
    return tuple(_expect_string(item, f"{name}[]", allow_empty=True) for item in value)


def _relative_directory(value: str, name: str) -> str:
    candidate = PurePosixPath(value)
    if candidate.is_absolute() or ".." in candidate.parts:
        raise SchemaError(f"{name} must stay within the repository")
    return value or "."


def _resource_quantity(value: Any, name: str, *, allow_unit: bool) -> str:
    candidate = _expect_string(value, name)
    match = _RESOURCE_QUANTITY_RE.fullmatch(candidate)
    if match is None or (match.group("unit") and not allow_unit):
        expected = "a positive Docker size" if allow_unit else "a positive decimal"
        raise SchemaError(f"{name} must be {expected}")
    amount = float(match.group("number"))
    if not math.isfinite(amount) or amount <= 0:
        raise SchemaError(f"{name} must be positive")
    return candidate


def patch_digest(diff: str) -> str:
    """Return the canonical SHA-256 digest for a UTF-8 patch."""

    return hashlib.sha256(diff.encode("utf-8")).hexdigest()


@dataclass(frozen=True)
class RepositorySpec:
    """The repository state used to reconstruct a repair task."""

    source: str
    buggy_revision: str
    fixed_revision: str
    changed_files: tuple[str, ...] = field(default_factory=tuple)

    def __post_init__(self) -> None:
        _expect_string(self.source, "repository.source")
        for name, revision in (
            ("repository.buggy_revision", self.buggy_revision),
            ("repository.fixed_revision", self.fixed_revision),
        ):
            if not _REVISION_RE.fullmatch(revision):
                raise SchemaError(f"{name} must be a 7-64 character hexadecimal commit id")
        if self.buggy_revision == self.fixed_revision:
            raise SchemaError("buggy and fixed revisions must differ")
        if not self.changed_files:
            raise SchemaError("repository.changed_files must contain at least one path")
        for path in self.changed_files:
            _expect_string(path, "repository.changed_files[]")
            normalized = PurePosixPath(path)
            if normalized.is_absolute() or ".." in normalized.parts:
                raise SchemaError("changed file paths must stay within the repository")

    def to_dict(self) -> dict[str, Any]:
        return {
            "source": self.source,
            "buggy_revision": self.buggy_revision,
            "fixed_revision": self.fixed_revision,
            "changed_files": list(self.changed_files),
        }

    @classmethod
    def from_dict(cls, value: Any) -> RepositorySpec:
        data = _strict_mapping(
            value,
            "$.repository",
            required=frozenset(
                {"source", "buggy_revision", "fixed_revision", "changed_files"}
            ),
        )
        return cls(
            source=_expect_string(data.get("source"), "repository.source"),
            buggy_revision=_expect_string(data.get("buggy_revision"), "repository.buggy_revision"),
            fixed_revision=_expect_string(data.get("fixed_revision"), "repository.fixed_revision"),
            changed_files=_expect_string_sequence(
                data.get("changed_files"),
                "repository.changed_files",
            ),
        )


@dataclass(frozen=True)
class TestSpec:
    """A test process represented without a shell."""

    command: tuple[str, ...]
    timeout_seconds: int = 300
    working_directory: str = "."
    environment: tuple[tuple[str, str], ...] = field(default_factory=tuple)

    def __post_init__(self) -> None:
        if not self.command:
            raise SchemaError("test.command must contain at least one argument")
        for argument in self.command:
            _expect_string(argument, "test.command[]", allow_empty=True)
        if isinstance(self.timeout_seconds, bool) or not isinstance(self.timeout_seconds, int):
            raise SchemaError("test.timeout_seconds must be an integer")
        if not 1 <= self.timeout_seconds <= 86_400:
            raise SchemaError("test.timeout_seconds must be between 1 and 86400")
        _relative_directory(self.working_directory, "test.working_directory")
        seen = set()
        for name, value in self.environment:
            if not _ENV_NAME_RE.fullmatch(name):
                raise SchemaError(f"invalid environment variable name: {name!r}")
            _expect_string(value, f"test.environment.{name}", allow_empty=True)
            if _environment_name_looks_sensitive(name):
                raise SchemaError(
                    f"test.environment name {name!r} looks credential-like; "
                    "FreshPatch tasks must not depend on secrets"
                )
            if _environment_value_looks_sensitive(value):
                raise SchemaError(
                    f"test.environment.{name} appears to contain a credential; "
                    "FreshPatch tasks must not contain secrets"
                )
            if "\n" in value or "\r" in value:
                raise SchemaError(
                    f"test.environment.{name} must not contain carriage returns or newlines"
                )
            if name in seen:
                raise SchemaError(f"duplicate environment variable: {name}")
            seen.add(name)

    def to_dict(self) -> dict[str, Any]:
        return {
            "command": list(self.command),
            "timeout_seconds": self.timeout_seconds,
            "working_directory": self.working_directory,
            "environment": dict(self.environment),
        }

    @classmethod
    def from_dict(cls, value: Any) -> TestSpec:
        data = _strict_mapping(
            value,
            "$.test",
            required=frozenset(
                {"command", "timeout_seconds", "working_directory", "environment"}
            ),
        )
        environment = _expect_mapping(data.get("environment"), "test.environment")
        pairs = []
        for name in sorted(environment):
            key = _expect_string(name, "test.environment key")
            item = _expect_string(
                environment[name],
                f"test.environment.{key}",
                allow_empty=True,
            )
            pairs.append((key, item))
        timeout = data.get("timeout_seconds")
        if isinstance(timeout, bool) or not isinstance(timeout, int):
            raise SchemaError("test.timeout_seconds must be an integer")
        working_directory = data.get("working_directory")
        return cls(
            command=_expect_string_sequence(data.get("command"), "test.command"),
            timeout_seconds=timeout,
            working_directory=_expect_string(
                working_directory,
                "test.working_directory",
                allow_empty=True,
            ),
            environment=tuple(pairs),
        )


@dataclass(frozen=True)
class ReferencePatch:
    """The known repair, retained for benchmark verification and baselines."""

    diff: str
    sha256: str | None = None
    format: str = "git-diff"

    def __post_init__(self) -> None:
        _expect_string(self.diff, "reference_patch.diff")
        if self.format != "git-diff":
            raise SchemaError("reference_patch.format must be 'git-diff'")
        actual = patch_digest(self.diff)
        if self.sha256 is None:
            object.__setattr__(self, "sha256", actual)
        elif self.sha256 != actual:
            raise SchemaError("reference_patch.sha256 does not match the patch content")

    def to_dict(self) -> dict[str, Any]:
        return {"format": self.format, "sha256": self.sha256, "diff": self.diff}

    @classmethod
    def from_dict(cls, value: Any) -> ReferencePatch:
        data = _strict_mapping(
            value,
            "$.reference_patch",
            required=frozenset({"format", "sha256", "diff"}),
        )
        return cls(
            format=_expect_string(data.get("format"), "reference_patch.format"),
            sha256=_expect_string(data.get("sha256"), "reference_patch.sha256"),
            diff=_expect_string(data.get("diff"), "reference_patch.diff"),
        )


@dataclass(frozen=True)
class Provenance:
    """Stable facts copied from the source commit."""

    fixed_commit_subject: str
    fixed_commit_timestamp: str
    builder_version: str = "freshpatch/1"

    def __post_init__(self) -> None:
        _expect_string(self.fixed_commit_subject, "provenance.fixed_commit_subject")
        _expect_string(self.fixed_commit_timestamp, "provenance.fixed_commit_timestamp")
        _expect_string(self.builder_version, "provenance.builder_version")

    def to_dict(self) -> dict[str, str]:
        return {
            "fixed_commit_subject": self.fixed_commit_subject,
            "fixed_commit_timestamp": self.fixed_commit_timestamp,
            "builder_version": self.builder_version,
        }

    @classmethod
    def from_dict(cls, value: Any) -> Provenance:
        data = _strict_mapping(
            value,
            "$.provenance",
            required=frozenset(
                {"fixed_commit_subject", "fixed_commit_timestamp", "builder_version"}
            ),
        )
        return cls(
            fixed_commit_subject=_expect_string(
                data.get("fixed_commit_subject"),
                "provenance.fixed_commit_subject",
            ),
            fixed_commit_timestamp=_expect_string(
                data.get("fixed_commit_timestamp"),
                "provenance.fixed_commit_timestamp",
            ),
            builder_version=_expect_string(
                data.get("builder_version"),
                "provenance.builder_version",
            ),
        )


@dataclass(frozen=True)
class RunnerSpec:
    """Immutable Docker runner identity and its enforced isolation policy."""

    image: str = DEFAULT_RUNNER_IMAGE
    cpus: str = "1.0"
    memory: str = "1g"
    pids_limit: int = 256
    tmpfs_size: str = "128m"
    network: str = "none"
    read_only_root: bool = True
    cap_drop: tuple[str, ...] = ("ALL",)
    no_new_privileges: bool = True

    def __post_init__(self) -> None:
        if not isinstance(self.image, str) or not _IMAGE_DIGEST_RE.fullmatch(self.image):
            raise SchemaError(
                "runner.image must include an immutable @sha256:<64 lowercase hex> digest"
            )
        _resource_quantity(self.cpus, "runner.policy.cpus", allow_unit=False)
        _resource_quantity(self.memory, "runner.policy.memory", allow_unit=True)
        _resource_quantity(self.tmpfs_size, "runner.policy.tmpfs_size", allow_unit=True)
        if isinstance(self.pids_limit, bool) or not isinstance(self.pids_limit, int):
            raise SchemaError("runner.policy.pids_limit must be an integer")
        if not 16 <= self.pids_limit <= 4096:
            raise SchemaError("runner.policy.pids_limit must be between 16 and 4096")
        if self.network != "none":
            raise SchemaError("runner.policy.network must be 'none'")
        if self.read_only_root is not True:
            raise SchemaError("runner.policy.read_only_root must be true")
        if self.cap_drop != ("ALL",):
            raise SchemaError("runner.policy.cap_drop must be ['ALL']")
        if self.no_new_privileges is not True:
            raise SchemaError("runner.policy.no_new_privileges must be true")

    def to_dict(self) -> dict[str, Any]:
        return {
            "image": self.image,
            "policy": {
                "cap_drop": list(self.cap_drop),
                "cpus": self.cpus,
                "memory": self.memory,
                "network": self.network,
                "no_new_privileges": self.no_new_privileges,
                "pids_limit": self.pids_limit,
                "read_only_root": self.read_only_root,
                "tmpfs_size": self.tmpfs_size,
            },
        }

    @classmethod
    def from_dict(cls, value: Any) -> RunnerSpec:
        data = _strict_mapping(
            value,
            "$.runner",
            required=frozenset({"image", "policy"}),
        )
        policy = _strict_mapping(
            data.get("policy"),
            "$.runner.policy",
            required=frozenset(
                {
                    "cap_drop",
                    "cpus",
                    "memory",
                    "network",
                    "no_new_privileges",
                    "pids_limit",
                    "read_only_root",
                    "tmpfs_size",
                }
            ),
        )
        cap_drop = _expect_string_sequence(policy.get("cap_drop"), "runner.policy.cap_drop")
        no_new_privileges = policy.get("no_new_privileges")
        if not isinstance(no_new_privileges, bool):
            raise SchemaError("runner.policy.no_new_privileges must be a boolean")
        pids_limit = policy.get("pids_limit")
        if isinstance(pids_limit, bool) or not isinstance(pids_limit, int):
            raise SchemaError("runner.policy.pids_limit must be an integer")
        read_only_root = policy.get("read_only_root")
        if not isinstance(read_only_root, bool):
            raise SchemaError("runner.policy.read_only_root must be a boolean")
        return cls(
            image=_expect_string(data.get("image"), "runner.image"),
            cpus=_expect_string(policy.get("cpus"), "runner.policy.cpus"),
            memory=_expect_string(policy.get("memory"), "runner.policy.memory"),
            network=_expect_string(policy.get("network"), "runner.policy.network"),
            no_new_privileges=no_new_privileges,
            pids_limit=pids_limit,
            read_only_root=read_only_root,
            tmpfs_size=_expect_string(policy.get("tmpfs_size"), "runner.policy.tmpfs_size"),
            cap_drop=cap_drop,
        )


@dataclass(frozen=True)
class Task:
    """One reproducible code-repair benchmark case."""

    task_id: str
    title: str
    repository: RepositorySpec
    test: TestSpec
    reference_patch: ReferencePatch
    provenance: Provenance
    description: str = ""
    labels: tuple[str, ...] = field(default_factory=tuple)
    runner: RunnerSpec = field(default_factory=RunnerSpec)
    schema_version: str = SCHEMA_VERSION

    def __post_init__(self) -> None:
        if self.schema_version != SCHEMA_VERSION:
            raise SchemaError(
                f"unsupported task schema version {self.schema_version!r}; "
                f"expected {SCHEMA_VERSION!r}"
            )
        if not _TASK_ID_RE.fullmatch(self.task_id):
            raise SchemaError(f"task id must match {_TASK_ID_RE.pattern}")
        _expect_string(self.title, "title")
        _expect_string(self.description, "description", allow_empty=True)
        seen = set()
        for label in self.labels:
            normalized = _expect_string(label, "labels[]").lower()
            if normalized != label or not _TASK_ID_RE.fullmatch(label):
                raise SchemaError("labels must be lowercase identifiers")
            if label in seen:
                raise SchemaError(f"duplicate label: {label}")
            seen.add(label)

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema_version": self.schema_version,
            "id": self.task_id,
            "title": self.title,
            "description": self.description,
            "labels": list(self.labels),
            "repository": self.repository.to_dict(),
            "test": self.test.to_dict(),
            "reference_patch": self.reference_patch.to_dict(),
            "provenance": self.provenance.to_dict(),
            "runner": self.runner.to_dict(),
        }

    @property
    def sha256(self) -> str:
        """Return the canonical digest that binds evidence to this exact task."""

        return task_digest(self)

    @classmethod
    def from_dict(cls, value: Any) -> Task:
        data = _strict_mapping(
            value,
            "$",
            required=frozenset(
                {
                    "schema_version",
                    "id",
                    "title",
                    "description",
                    "labels",
                    "repository",
                    "test",
                    "reference_patch",
                    "provenance",
                    "runner",
                }
            ),
        )
        schema_version = _expect_string(data.get("schema_version"), "schema_version")
        return cls(
            schema_version=schema_version,
            task_id=_expect_string(data.get("id"), "id"),
            title=_expect_string(data.get("title"), "title"),
            description=_expect_string(data.get("description"), "description", allow_empty=True),
            labels=_expect_string_sequence(data.get("labels"), "labels"),
            repository=RepositorySpec.from_dict(data.get("repository")),
            test=TestSpec.from_dict(data.get("test")),
            reference_patch=ReferencePatch.from_dict(data.get("reference_patch")),
            provenance=Provenance.from_dict(data.get("provenance")),
            runner=RunnerSpec.from_dict(data.get("runner")),
        )


def loads_task(content: str) -> Task:
    """Parse and validate one JSON task."""

    try:
        value = json.loads(content)
    except (TypeError, json.JSONDecodeError) as exc:
        raise SchemaError(f"invalid task JSON: {exc}") from exc
    return Task.from_dict(value)


def load_task(path: Path) -> Task:
    """Load a UTF-8 task artifact from disk."""

    try:
        return loads_task(Path(path).read_text(encoding="utf-8"))
    except OSError as exc:
        raise SchemaError(f"could not read task {path}: {exc}") from exc


def dumps_task(task: Task) -> str:
    """Serialize a task deterministically for reviewable Git diffs."""

    return json.dumps(task.to_dict(), indent=2, sort_keys=True, ensure_ascii=False) + "\n"


def task_digest(task: Task) -> str:
    """Hash the canonical JSON value of a task, independent of presentation whitespace."""

    canonical = json.dumps(
        task.to_dict(),
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
    ).encode("utf-8")
    return hashlib.sha256(canonical).hexdigest()


def write_task(task: Task, path: Path) -> None:
    """Atomically write a task artifact."""

    destination = Path(path)
    destination.parent.mkdir(parents=True, exist_ok=True)
    file_descriptor, temporary_name = tempfile.mkstemp(
        prefix=f".{destination.name}-", suffix=".tmp", dir=str(destination.parent)
    )
    try:
        with os.fdopen(file_descriptor, "w", encoding="utf-8", newline="\n") as handle:
            handle.write(dumps_task(task))
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary_name, destination)
    except BaseException:
        with suppress(OSError):
            os.unlink(temporary_name)
        raise
