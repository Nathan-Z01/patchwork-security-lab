from __future__ import annotations

import csv
import json
from dataclasses import replace
from pathlib import Path

from signallab import opinion_from_artifact, train_model
from signallab.cli import main
from signallab.models import MetricSet, ModelArtifact
from signallab.research import _confidence


def test_real_core_opinion_matches_strict_api_contract(
    demo_csv: Path, trained_artifact: ModelArtifact
) -> None:
    result = opinion_from_artifact(
        demo_csv, "SYNTH_A", trained_artifact, sample_data=True
    )
    value = result.to_dict()

    assert set(value) == {
        "as_of",
        "benchmark",
        "confidence",
        "disclaimer",
        "horizon_days",
        "limitations",
        "model",
        "opinion",
        "probability_outperform",
        "rationale",
        "sample_data",
        "symbol",
    }
    assert value["symbol"] == "SYNTH_A"
    assert value["sample_data"] is True
    assert value["opinion"] in {"bullish", "neutral", "bearish"}
    assert 0.0 <= value["probability_outperform"] <= 1.0
    assert "not financial advice" in value["disclaimer"].lower()
    assert value["model"]["evaluation"]["constant_brier"] > 0.0
    assert value["model"]["evaluation"]["effective_windows"] == (
        trained_artifact.split.test_distinct_dates // trained_artifact.horizon_days
    )
    assert set(value["rationale"][0]) == {
        "feature",
        "label",
        "value",
        "direction",
        "explanation",
    }
    assert all(
        item["direction"] in {"positive", "negative", "neutral"}
        for item in value["rationale"]
    )


def test_weak_holdout_forces_neutral_low_confidence(
    demo_csv: Path, trained_artifact: ModelArtifact
) -> None:
    weak_metrics = MetricSet(
        accuracy=0.50,
        balanced_accuracy=0.50,
        brier=0.26,
        roc_auc=0.49,
        base_rate=0.50,
        constant_brier=0.25,
        rows=500,
    )
    weak = replace(trained_artifact, test_metrics=weak_metrics)
    result = opinion_from_artifact(demo_csv, "SYNTH_A", weak)

    assert result.opinion == "neutral"
    assert result.confidence == "low"
    assert "forced to neutral" in result.limitations[0]


def test_holdout_quality_gates_have_meaningful_boundaries(
    demo_csv: Path, trained_artifact: ModelArtifact
) -> None:
    too_small = replace(
        trained_artifact,
        test_metrics=MetricSet(0.9, 0.9, 0.10, 0.9, 0.5, 0.25, 99),
    )
    assert opinion_from_artifact(demo_csv, "SYNTH_A", too_small).opinion == "neutral"

    directional = replace(
        trained_artifact,
        test_metrics=MetricSet(0.7, 0.52, 0.248, 0.53, 0.5, 0.25, 100),
    )
    directional_result = opinion_from_artifact(demo_csv, "SYNTH_A", directional)
    assert directional_result.confidence != "high"
    assert _confidence(0.95, directional) == "moderate"

    strong = replace(
        trained_artifact,
        test_metrics=MetricSet(0.8, 0.55, 0.24, 0.60, 0.5, 0.25, 200),
    )
    assert _confidence(0.95, strong) == "moderate"
    target_specific = replace(
        strong,
        training_symbols=("SYNTH_A",),
        split=replace(strong.split, effective_test_windows=20, test_distinct_dates=400),
    )
    assert _confidence(0.95, target_specific) == "high"


def test_raw_close_fallback_is_prominently_limited(demo_csv: Path, tmp_path: Path) -> None:
    raw_path = tmp_path / "raw.csv"
    with demo_csv.open(newline="", encoding="utf-8") as source, raw_path.open(
        "w", newline="", encoding="utf-8"
    ) as output:
        reader = csv.DictReader(source)
        fields = [item for item in reader.fieldnames or [] if item != "adjusted_close"]
        writer = csv.DictWriter(output, fieldnames=fields, lineterminator="\n")
        writer.writeheader()
        for row in reader:
            row.pop("adjusted_close")
            writer.writerow(row)
    artifact = train_model(raw_path, benchmark="SYNTH_MKT")
    result = opinion_from_artifact(raw_path, "SYNTH_A", artifact)

    assert artifact.uses_adjusted_close is False
    assert any("omitted adjusted_close" in item for item in result.limitations)


def test_cli_demo_train_analyze_round_trip(tmp_path: Path, capsys: object) -> None:
    data = tmp_path / "demo.csv"
    model = tmp_path / "model.json"
    assert main(["demo-data", str(data)]) == 0
    assert main(
        [
            "train",
            str(data),
            "--output",
            str(model),
            "--benchmark",
            "SYNTH_MKT",
        ]
    ) == 0
    assert main(
        [
            "analyze",
            str(data),
            "SYNTH_A",
            "--artifact",
            str(model),
            "--sample-data",
            "--benchmark",
            "SYNTH_MKT",
        ]
    ) == 0
    # Each command writes JSON; the final document is still parseable in isolation.
    output = capsys.readouterr().out
    decoder = json.JSONDecoder()
    documents = []
    position = 0
    while position < len(output):
        while position < len(output) and output[position].isspace():
            position += 1
        if position == len(output):
            break
        value, position = decoder.raw_decode(output, position)
        documents.append(value)
    assert documents[-1]["symbol"] == "SYNTH_A"
    assert documents[-1]["sample_data"] is True
