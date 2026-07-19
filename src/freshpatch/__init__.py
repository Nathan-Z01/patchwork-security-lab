"""FreshPatch: reproducible, execution-based code-repair benchmarks."""

from patchwork_common import __version__

from .builder import build_task
from .evaluator import (
    DockerConfig,
    EffectiveResourcePolicy,
    EvaluationResult,
    EvaluationStatus,
    ExecutionEnvironment,
    evaluate,
)
from .qualification import (
    QualificationArtifact,
    QualificationStatus,
    dumps_qualification,
    loads_qualification,
    qualify,
    write_qualification,
)
from .schema import (
    DEFAULT_RUNNER_IMAGE,
    SCHEMA_VERSION,
    Provenance,
    ReferencePatch,
    RepositorySpec,
    RunnerSpec,
    Task,
    TestSpec,
    dumps_task,
    load_task,
    loads_task,
    write_task,
)

__all__ = [
    "DockerConfig",
    "EffectiveResourcePolicy",
    "EvaluationResult",
    "EvaluationStatus",
    "ExecutionEnvironment",
    "DEFAULT_RUNNER_IMAGE",
    "Provenance",
    "ReferencePatch",
    "RepositorySpec",
    "RunnerSpec",
    "SCHEMA_VERSION",
    "Task",
    "TestSpec",
    "build_task",
    "dumps_qualification",
    "dumps_task",
    "evaluate",
    "load_task",
    "loads_task",
    "loads_qualification",
    "QualificationArtifact",
    "QualificationStatus",
    "qualify",
    "write_qualification",
    "write_task",
    "__version__",
]
