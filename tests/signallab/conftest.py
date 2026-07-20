from pathlib import Path

import pytest

from signallab import generate_demo_data, train_model
from signallab.models import ModelArtifact


@pytest.fixture(scope="session")
def demo_csv(tmp_path_factory: pytest.TempPathFactory) -> Path:
    path = tmp_path_factory.mktemp("signallab") / "synthetic.csv"
    generate_demo_data(path)
    return path


@pytest.fixture(scope="session")
def trained_artifact(demo_csv: Path) -> ModelArtifact:
    return train_model(demo_csv, benchmark="SYNTH_MKT")
