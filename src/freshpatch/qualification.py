"""Task qualification: prove the bug fails and the recorded repair passes."""

from __future__ import annotations

import json
import math
import os
import tempfile
import time
from collections.abc import Mapping
from contextlib import suppress
from dataclasses import dataclass
from datetime import datetime, timezone
from enum import Enum
from pathlib import Path
from typing import Any

from .errors import SchemaError
from .evaluator import (
    DEFAULT_OUTPUT_LIMIT,
    DockerConfig,
    EvaluationResult,
    EvaluationStatus,
    ExecutionEnvironment,
    evaluate,
)
from .schema import Task, task_digest

QUALIFICATION_SCHEMA_VERSION = "1.1"


class QualificationStatus(str, Enum):
    QUALIFIED = "qualified"
    REJECTED = "rejected"


def _timestamp() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


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


@dataclass(frozen=True)
class QualificationArtifact:
    """Reviewable proof that a task distinguishes its buggy and fixed states."""

    task_id: str
    task_sha256: str
    status: QualificationStatus
    reason: str
    started_at: str
    completed_at: str
    duration_seconds: float
    environment: ExecutionEnvironment
    baseline: EvaluationResult
    reference: EvaluationResult
    qualification_schema_version: str = QUALIFICATION_SCHEMA_VERSION

    def __post_init__(self) -> None:
        if self.qualification_schema_version != QUALIFICATION_SCHEMA_VERSION:
            raise SchemaError("unsupported qualification schema version")
        if not isinstance(self.task_id, str) or not self.task_id:
            raise SchemaError("qualification task_id must not be empty")
        if (
            not isinstance(self.task_sha256, str)
            or len(self.task_sha256) != 64
            or any(character not in "0123456789abcdef" for character in self.task_sha256)
        ):
            raise SchemaError("qualification task_sha256 must be a lowercase SHA-256 value")
        if not isinstance(self.status, QualificationStatus):
            raise SchemaError("invalid qualification status")
        if not isinstance(self.reason, str) or not self.reason:
            raise SchemaError("qualification reason must not be empty")
        if isinstance(self.duration_seconds, bool) or not isinstance(
            self.duration_seconds, (int, float)
        ):
            raise SchemaError("qualification duration_seconds must be numeric")
        if not math.isfinite(float(self.duration_seconds)) or self.duration_seconds < 0:
            raise SchemaError("qualification duration_seconds must be finite and nonnegative")
        parsed_timestamps = []
        for name, value in (
            ("started_at", self.started_at),
            ("completed_at", self.completed_at),
        ):
            if not isinstance(value, str) or not value.endswith("Z"):
                raise SchemaError(f"qualification {name} must be a UTC RFC3339 timestamp")
            try:
                parsed_timestamps.append(datetime.fromisoformat(value[:-1] + "+00:00"))
            except ValueError as exc:
                raise SchemaError(f"qualification {name} must be a valid timestamp") from exc
        if parsed_timestamps[1] < parsed_timestamps[0]:
            raise SchemaError("qualification completed_at must not precede started_at")
        if self.baseline.task_id != self.task_id or self.reference.task_id != self.task_id:
            raise SchemaError("qualification checks must match qualification task_id")
        if (
            self.baseline.task_sha256 != self.task_sha256
            or self.reference.task_sha256 != self.task_sha256
        ):
            raise SchemaError("qualification checks must match qualification task_sha256")
        if self.baseline.patch_kind != "none":
            raise SchemaError("qualification baseline must be unpatched")
        if self.reference.patch_kind != "reference":
            raise SchemaError("qualification reference must use the recorded reference patch")
        if self.baseline.environment != self.environment:
            raise SchemaError("qualification baseline environment does not match")
        if self.reference.environment != self.environment:
            raise SchemaError("qualification reference environment does not match")
        actually_qualified = (
            self.baseline.status == EvaluationStatus.FAILED
            and self.reference.status == EvaluationStatus.PASSED
        )
        if (self.status == QualificationStatus.QUALIFIED) != actually_qualified:
            raise SchemaError("qualification status is inconsistent with check results")

    @property
    def qualified(self) -> bool:
        return self.status == QualificationStatus.QUALIFIED

    def to_dict(self) -> dict[str, Any]:
        return {
            "qualification_schema_version": self.qualification_schema_version,
            "task_id": self.task_id,
            "task_sha256": self.task_sha256,
            "status": self.status.value,
            "qualified": self.qualified,
            "reason": self.reason,
            "started_at": self.started_at,
            "completed_at": self.completed_at,
            "duration_seconds": round(self.duration_seconds, 6),
            "environment": self.environment.to_dict(),
            "checks": {
                "baseline": self.baseline.to_dict(),
                "reference": self.reference.to_dict(),
            },
        }

    @classmethod
    def from_dict(cls, value: Any) -> QualificationArtifact:
        data = _strict_object(
            value,
            "$",
            frozenset(
                {
                    "qualification_schema_version",
                    "task_id",
                    "task_sha256",
                    "status",
                    "qualified",
                    "reason",
                    "started_at",
                    "completed_at",
                    "duration_seconds",
                    "environment",
                    "checks",
                }
            ),
        )
        checks = _strict_object(
            data.get("checks"),
            "$.checks",
            frozenset({"baseline", "reference"}),
        )
        try:
            status = QualificationStatus(data.get("status"))
        except (TypeError, ValueError) as exc:
            raise SchemaError(f"invalid qualification status: {data.get('status')!r}") from exc
        qualified = data.get("qualified")
        if not isinstance(qualified, bool):
            raise SchemaError("qualification qualified must be a boolean")
        if qualified != (status == QualificationStatus.QUALIFIED):
            raise SchemaError("qualification qualified flag is inconsistent with status")
        duration = data.get("duration_seconds")
        if isinstance(duration, bool) or not isinstance(duration, (int, float)):
            raise SchemaError("qualification duration_seconds must be numeric")
        environment = ExecutionEnvironment.from_dict(data.get("environment"))
        return cls(
            qualification_schema_version=data.get("qualification_schema_version", ""),
            task_id=data.get("task_id", ""),
            task_sha256=data.get("task_sha256", ""),
            status=status,
            reason=data.get("reason", ""),
            started_at=data.get("started_at", ""),
            completed_at=data.get("completed_at", ""),
            duration_seconds=float(duration),
            environment=environment,
            baseline=EvaluationResult.from_dict(checks.get("baseline")),
            reference=EvaluationResult.from_dict(checks.get("reference")),
        )


def qualify(
    task: Task,
    *,
    backend: str = "docker",
    allow_unsafe_local: bool = False,
    repository_override: Path | None = None,
    task_base_directory: Path | None = None,
    docker_config: DockerConfig | None = None,
    output_limit: int = DEFAULT_OUTPUT_LIMIT,
) -> QualificationArtifact:
    """Run both qualification checks under one effective execution policy."""

    started_at = _timestamp()
    started_clock = time.monotonic()
    baseline = evaluate(
        task,
        backend=backend,
        allow_unsafe_local=allow_unsafe_local,
        repository_override=repository_override,
        task_base_directory=task_base_directory,
        docker_config=docker_config,
        output_limit=output_limit,
    )
    reference = evaluate(
        task,
        candidate_patch=task.reference_patch.diff,
        patch_kind="reference",
        backend=backend,
        allow_unsafe_local=allow_unsafe_local,
        repository_override=repository_override,
        task_base_directory=task_base_directory,
        docker_config=docker_config,
        output_limit=output_limit,
    )
    if baseline.status != EvaluationStatus.FAILED:
        status = QualificationStatus.REJECTED
        reason = f"buggy baseline must fail, but it returned {baseline.status.value}"
    elif reference.status != EvaluationStatus.PASSED:
        status = QualificationStatus.REJECTED
        reason = f"reference patch must pass, but it returned {reference.status.value}"
    else:
        status = QualificationStatus.QUALIFIED
        reason = "buggy baseline failed and the reference patch passed"
    return QualificationArtifact(
        task_id=task.task_id,
        task_sha256=task_digest(task),
        status=status,
        reason=reason,
        started_at=started_at,
        completed_at=_timestamp(),
        duration_seconds=time.monotonic() - started_clock,
        environment=baseline.environment,
        baseline=baseline,
        reference=reference,
    )


def dumps_qualification(artifact: QualificationArtifact) -> str:
    return json.dumps(artifact.to_dict(), indent=2, sort_keys=True, ensure_ascii=False) + "\n"


def loads_qualification(content: str) -> QualificationArtifact:
    try:
        value = json.loads(content)
    except (TypeError, json.JSONDecodeError) as exc:
        raise SchemaError(f"invalid qualification JSON: {exc}") from exc
    return QualificationArtifact.from_dict(value)


def write_qualification(artifact: QualificationArtifact, path: Path) -> None:
    destination = Path(path)
    destination.parent.mkdir(parents=True, exist_ok=True)
    file_descriptor, temporary_name = tempfile.mkstemp(
        prefix=f".{destination.name}-",
        suffix=".tmp",
        dir=str(destination.parent),
    )
    try:
        with os.fdopen(file_descriptor, "w", encoding="utf-8", newline="\n") as handle:
            handle.write(dumps_qualification(artifact))
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary_name, destination)
    except BaseException:
        with suppress(OSError):
            os.unlink(temporary_name)
        raise
