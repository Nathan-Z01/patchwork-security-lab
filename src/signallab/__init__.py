"""SignalLab: leakage-aware, transparent stock research models."""

from patchwork_common import __version__

from .artifact import dumps_artifact, load_artifact, write_artifact
from .errors import ArtifactError, DataValidationError, SignalLabError, TrainingError
from .models import FactorContribution, ModelArtifact, OpinionResult
from .research import demo_research, opinion_from_artifact, research
from .synthetic import generate_demo_data
from .training import train_model

__all__ = [
    "ArtifactError",
    "DataValidationError",
    "FactorContribution",
    "ModelArtifact",
    "OpinionResult",
    "SignalLabError",
    "TrainingError",
    "demo_research",
    "dumps_artifact",
    "generate_demo_data",
    "load_artifact",
    "opinion_from_artifact",
    "research",
    "train_model",
    "write_artifact",
    "__version__",
]
