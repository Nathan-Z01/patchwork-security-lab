from __future__ import annotations

import csv
import json
from pathlib import Path

import pytest

from signallab import load_artifact, train_model, write_artifact
from signallab.errors import ArtifactError
from signallab.models import ModelArtifact


def test_training_is_deterministic_and_beats_constant_baseline(demo_csv: Path) -> None:
    first = train_model(demo_csv, benchmark="SYNTH_MKT", seed=91)
    second = train_model(demo_csv, benchmark="SYNTH_MKT", seed=91)

    assert first.to_dict() == second.to_dict()
    assert first.test_metrics.brier < first.test_metrics.constant_brier
    assert first.test_metrics.roc_auc > 0.60
    assert first.test_metrics.balanced_accuracy > 0.55


def test_split_is_chronological_and_horizon_purged(
    trained_artifact: ModelArtifact,
) -> None:
    split = trained_artifact.split
    assert split.train_label_end < split.validation_start
    assert split.validation_label_end < split.test_start
    assert split.purged_rows > 0
    assert trained_artifact.training_cutoff == split.validation_label_end


def test_safe_json_round_trip(
    trained_artifact: ModelArtifact, tmp_path: Path
) -> None:
    path = tmp_path / "model.json"
    write_artifact(trained_artifact, path)

    assert path.read_bytes().startswith(b"{")
    assert load_artifact(path) == trained_artifact


def test_artifact_rejects_unknown_duplicate_and_nonfinite_json(
    trained_artifact: ModelArtifact, tmp_path: Path
) -> None:
    unknown = trained_artifact.to_dict()
    unknown["surprise"] = True
    unknown_path = tmp_path / "unknown.json"
    unknown_path.write_text(json.dumps(unknown), encoding="utf-8")
    with pytest.raises(ArtifactError, match="not allowed"):
        load_artifact(unknown_path)

    duplicate_path = tmp_path / "duplicate.json"
    duplicate_path.write_text('{"schema":"one","schema":"two"}', encoding="utf-8")
    with pytest.raises(ArtifactError, match="duplicate JSON property"):
        load_artifact(duplicate_path)

    nonfinite_path = tmp_path / "nonfinite.json"
    nonfinite_path.write_text('{"value":NaN}', encoding="utf-8")
    with pytest.raises(ArtifactError, match="non-finite JSON"):
        load_artifact(nonfinite_path)


def test_artifact_rejects_huge_json_integer_without_leaking_overflow(
    trained_artifact: ModelArtifact, tmp_path: Path
) -> None:
    value = trained_artifact.to_dict()
    value["models"]["logistic"]["intercept"] = 10**4000
    path = tmp_path / "huge-number.json"
    path.write_text(json.dumps(value), encoding="utf-8")

    with pytest.raises(ArtifactError, match="finite number"):
        load_artifact(path)

    too_many_digits = tmp_path / "too-many-digits.json"
    serialized = json.dumps(trained_artifact.to_dict())
    marker = '"intercept": '
    start = serialized.index(marker) + len(marker)
    end = serialized.index(",", start)
    too_many_digits.write_text(
        serialized[:start] + "9" * 5_000 + serialized[end:], encoding="utf-8"
    )
    with pytest.raises(ArtifactError):
        load_artifact(too_many_digits)


def test_training_symbols_only_claim_rows_seen_during_fitting(
    demo_csv: Path, tmp_path: Path
) -> None:
    staggered = tmp_path / "staggered.csv"
    with demo_csv.open(newline="", encoding="utf-8") as source:
        rows = list(csv.DictReader(source))
        fieldnames = list(rows[0])
    synth_a = [row for row in rows if row["symbol"] == "SYNTH_A"]
    late_rows = []
    for row in synth_a[-140:]:
        copied = dict(row)
        copied["symbol"] = "LATE"
        late_rows.append(copied)
    with staggered.open("w", newline="", encoding="utf-8") as output:
        writer = csv.DictWriter(output, fieldnames=fieldnames, lineterminator="\n")
        writer.writeheader()
        writer.writerows(rows + late_rows)

    baseline = train_model(demo_csv, benchmark="SYNTH_MKT")
    artifact = train_model(staggered, benchmark="SYNTH_MKT")
    assert "SYNTH_A" in artifact.training_symbols
    assert "LATE" not in artifact.training_symbols
    assert artifact.validation_metrics == baseline.validation_metrics
    assert artifact.test_metrics == baseline.test_metrics
    assert artifact.split.validation_rows == baseline.split.validation_rows
    assert artifact.split.test_rows == baseline.split.test_rows
    assert artifact.split.purged_rows == baseline.split.purged_rows
    assert artifact.split.excluded_unfitted_symbol_rows > 0
    assert artifact.split.effective_test_windows == baseline.split.effective_test_windows
