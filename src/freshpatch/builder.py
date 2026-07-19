"""Build FreshPatch tasks from a known-buggy and known-fixed Git commit."""

from __future__ import annotations

import re
from collections.abc import Mapping, Sequence
from pathlib import Path

from .git import GitRepository
from .schema import Provenance, ReferencePatch, RepositorySpec, RunnerSpec, Task, TestSpec


def slugify(value: str) -> str:
    """Create a stable task identifier fragment."""

    slug = re.sub(r"[^a-z0-9._-]+", "-", value.lower()).strip("-._")
    return slug[:80] or "repair"


def build_task(
    repository_path: Path,
    buggy_revision: str,
    fixed_revision: str,
    test_command: Sequence[str],
    *,
    task_id: str | None = None,
    title: str | None = None,
    description: str = "",
    timeout_seconds: int = 300,
    working_directory: str = ".",
    environment: Mapping[str, str] | None = None,
    labels: Sequence[str] = (),
    published_source: str | None = None,
    runner: RunnerSpec | None = None,
) -> Task:
    """Create a validated task using only read-only Git operations.

    ``published_source`` can replace the local absolute path in the artifact (for
    example with a public clone URL). Evaluation remains network-free by default;
    callers can supply a local repository override when consuming such a task.
    """

    repository = GitRepository(repository_path)
    buggy = repository.resolve_commit(buggy_revision)
    fixed = repository.resolve_commit(fixed_revision)
    repository.require_ancestor(buggy, fixed)

    patch = repository.reference_patch(buggy, fixed)
    changed_files = repository.changed_files(buggy, fixed)
    subject, timestamp = repository.commit_metadata(fixed)
    source = published_source if published_source is not None else str(repository.root)
    identifier = task_id or f"{slugify(repository.root.name)}-{fixed[:12]}"
    test_environment = tuple(sorted((environment or {}).items()))

    return Task(
        task_id=identifier,
        title=title or subject,
        description=description,
        labels=tuple(labels),
        repository=RepositorySpec(
            source=source,
            buggy_revision=buggy,
            fixed_revision=fixed,
            changed_files=changed_files,
        ),
        test=TestSpec(
            command=tuple(test_command),
            timeout_seconds=timeout_seconds,
            working_directory=working_directory,
            environment=test_environment,
        ),
        reference_patch=ReferencePatch(diff=patch),
        provenance=Provenance(fixed_commit_subject=subject, fixed_commit_timestamp=timestamp),
        runner=runner or RunnerSpec(),
    )
