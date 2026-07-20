# ruff: noqa: UP006, UP035, UP045 -- Keep annotations importable on Python 3.9.
"""Research-opinion orchestration and transparent local factor evidence."""

from __future__ import annotations

import tempfile
from pathlib import Path
from typing import Sequence, Tuple

from .data import load_market_csv, require_symbols
from .errors import DataValidationError
from .features import FEATURE_NAMES, latest_feature_row, validate_horizon
from .models import (
    DIRECTIONAL_MIN_AUC,
    DIRECTIONAL_MIN_BALANCED_ACCURACY,
    DIRECTIONAL_MIN_BRIER_IMPROVEMENT,
    DIRECTIONAL_MIN_EFFECTIVE_WINDOWS,
    DIRECTIONAL_MIN_TEST_ROWS,
    DISCLAIMER,
    HIGH_CONFIDENCE_MIN_AUC,
    HIGH_CONFIDENCE_MIN_BALANCED_ACCURACY,
    HIGH_CONFIDENCE_MIN_BRIER_IMPROVEMENT,
    HIGH_CONFIDENCE_MIN_EFFECTIVE_WINDOWS,
    HIGH_CONFIDENCE_MIN_TEST_ROWS,
    FactorContribution,
    ModelArtifact,
    OpinionResult,
)
from .synthetic import generate_demo_data
from .training import predict_probability, train_model

_FEATURE_LABELS = {
    "momentum_5": "5-session momentum",
    "momentum_20": "20-session momentum",
    "momentum_60": "60-session momentum",
    "volatility_20": "20-session annualized volatility",
    "sma_distance_20": "distance from 20-session average",
    "sma_distance_60": "distance from 60-session average",
    "rsi_14": "14-session relative strength",
    "volume_ratio_20": "volume versus 20-session average",
    "drawdown_60": "drawdown from 60-session high",
    "benchmark_momentum_20": "benchmark 20-session momentum",
    "benchmark_momentum_60": "benchmark 60-session momentum",
    "relative_momentum_20": "20-session relative momentum",
    "relative_momentum_60": "60-session relative momentum",
    "beta_60": "60-session market beta",
}


def _contributions(
    artifact: ModelArtifact, raw_values: Sequence[float]
) -> Tuple[FactorContribution, ...]:
    observed_probability = predict_probability(artifact, raw_values)
    deltas = []
    for index, stat in enumerate(artifact.feature_stats):
        perturbed = list(raw_values)
        perturbed[index] = stat.mean
        deltas.append(observed_probability - predict_probability(artifact, perturbed))
    ranked = sorted(range(len(deltas)), key=lambda index: (-abs(deltas[index]), index))[:6]
    result = []
    for index in ranked:
        contribution = deltas[index]
        if contribution > 1e-12:
            direction = "positive"
        elif contribution < -1e-12:
            direction = "negative"
        else:
            direction = "neutral"
        effect = "supports outperforming" if contribution >= 0.0 else "supports underperforming"
        label = _FEATURE_LABELS[FEATURE_NAMES[index]]
        result.append(
            FactorContribution(
                feature=FEATURE_NAMES[index],
                label=label,
                value=raw_values[index],
                contribution=contribution,
                direction=direction,
                explanation=(
                    f"The observed {label} {effect} versus replacing only that feature "
                    "with its training average. This descriptive, non-causal perturbation "
                    "holds other features fixed and ignores feature dependence."
                ),
            )
        )
    return tuple(result)


def _holdout_supports_signal(artifact: ModelArtifact) -> bool:
    metrics = artifact.test_metrics
    return (
        metrics.rows >= DIRECTIONAL_MIN_TEST_ROWS
        and artifact.split.effective_test_windows >= DIRECTIONAL_MIN_EFFECTIVE_WINDOWS
        and metrics.roc_auc >= DIRECTIONAL_MIN_AUC
        and metrics.balanced_accuracy >= DIRECTIONAL_MIN_BALANCED_ACCURACY
        and metrics.constant_brier - metrics.brier >= DIRECTIONAL_MIN_BRIER_IMPROVEMENT
    )


def _holdout_supports_high_confidence(artifact: ModelArtifact) -> bool:
    metrics = artifact.test_metrics
    return (
        metrics.rows >= HIGH_CONFIDENCE_MIN_TEST_ROWS
        and artifact.split.effective_test_windows >= HIGH_CONFIDENCE_MIN_EFFECTIVE_WINDOWS
        and metrics.roc_auc >= HIGH_CONFIDENCE_MIN_AUC
        and metrics.balanced_accuracy >= HIGH_CONFIDENCE_MIN_BALANCED_ACCURACY
        and metrics.constant_brier - metrics.brier
        >= HIGH_CONFIDENCE_MIN_BRIER_IMPROVEMENT
    )


def _opinion_label(probability: float, artifact: ModelArtifact) -> str:
    if not _holdout_supports_signal(artifact):
        return "neutral"
    if probability >= 0.58:
        return "bullish"
    if probability <= 0.42:
        return "bearish"
    return "neutral"


def _confidence(probability: float, artifact: ModelArtifact) -> str:
    if not _holdout_supports_signal(artifact):
        return "low"
    separation = abs(probability - 0.5) * 2.0
    discrimination = max(0.0, min(1.0, (artifact.test_metrics.roc_auc - 0.5) * 2.0))
    score = 0.7 * separation + 0.3 * discrimination
    if (
        score >= 0.60
        and _holdout_supports_high_confidence(artifact)
        and len(artifact.training_symbols) == 1
    ):
        return "high"
    if score >= 0.28:
        return "moderate"
    return "low"


def opinion_from_artifact(
    data_path: Path,
    symbol: str,
    artifact: ModelArtifact,
    *,
    sample_data: bool = False,
) -> OpinionResult:
    """Score the latest observation after binding data, benchmark, and model contract."""

    bars, digest, uses_adjusted_close = load_market_csv(Path(data_path))
    target, benchmark = require_symbols(bars, symbol, artifact.benchmark)
    if digest != artifact.data_sha256:
        raise DataValidationError(
            "model artifact data_sha256 does not match the supplied CSV; retrain before analysis"
        )
    if target not in artifact.training_symbols:
        raise DataValidationError(f"symbol {target!r} was not represented during model training")
    latest = latest_feature_row(bars, target, benchmark)
    probability = predict_probability(artifact, latest.values)
    limitations = [
        (
            "The model uses historical daily OHLCV-derived technical factors only; it does "
            "not read fundamentals, filings, news, options, or macroeconomic releases."
        ),
        (
            "The evaluation is a historical holdout from this one dataset and may not "
            "generalize to a new market regime."
        ),
        (
            "Training and holdout metrics are pooled across the CSV's eligible non-benchmark "
            "symbols; they are not a symbol-specific performance guarantee, and evidence "
            "strength is capped at moderate when more than one stock was fitted."
        ),
        (
            "Forward-return labels overlap and raw test samples are not independent. The "
            "reported effective_windows value is floor(distinct test dates / horizon days) "
            "and is used by evidence-strength gates across the pooled symbol regimes."
        ),
        (
            "The binary target measures benchmark outperformance, not positive absolute "
            "return or investment suitability."
        ),
        (
            "Probabilities are calibrated on a finite validation window and are estimates, "
            "not guarantees."
        ),
        (
            "No transaction costs, taxes, liquidity constraints, or portfolio-level risk "
            "controls are modeled."
        ),
    ]
    if uses_adjusted_close != artifact.uses_adjusted_close:
        raise DataValidationError("adjusted-close availability differs from the training data")
    if not artifact.uses_adjusted_close:
        limitations.insert(
            0,
            (
                "The CSV omitted adjusted_close, so features use raw close prices and may be "
                "distorted by splits, dividends, or other corporate actions."
            ),
        )
    if sample_data:
        limitations.insert(
            0,
            (
                "This result uses deterministic synthetic demonstration data, not real "
                "prices, and must not be interpreted as a view on any real security."
            ),
        )
    if not _holdout_supports_signal(artifact):
        limitations.insert(
            0,
            (
                "The held-out test did not beat chance and the constant-probability "
                "baseline on all quality gates, so the qualitative opinion is forced to "
                "neutral with low evidence strength."
            ),
        )
    fitted_rows = int(
        artifact.model_params.get("fitted_training_rows", artifact.split.train_rows)
    )
    return OpinionResult(
        symbol=target,
        benchmark=benchmark,
        as_of=latest.date,
        horizon_days=artifact.horizon_days,
        opinion=_opinion_label(probability, artifact),
        probability_outperform=probability,
        confidence=_confidence(probability, artifact),
        sample_data=sample_data,
        rationale=_contributions(artifact, latest.values),
        model_test_metrics=artifact.test_metrics,
        model_version=artifact.version,
        model_trained_through=artifact.training_cutoff,
        model_training_rows=fitted_rows,
        model_symbols=artifact.training_symbols,
        model_feature_count=len(artifact.feature_names),
        model_test_start=artifact.split.test_start,
        model_test_end=artifact.split.test_end,
        model_effective_windows=artifact.split.effective_test_windows,
        limitations=tuple(limitations),
        disclaimer=DISCLAIMER,
    )


def research(
    data_path: Path,
    symbol: str,
    benchmark: str = "SPY",
    horizon_days: int = 20,
) -> OpinionResult:
    """Train against a CSV and return the latest evidence-backed research opinion."""

    validate_horizon(horizon_days)
    artifact = train_model(Path(data_path), benchmark, horizon_days)
    return opinion_from_artifact(Path(data_path), symbol, artifact)


def demo_research(
    symbol: str = "SYNTH_A",
    benchmark: str = "SYNTH_MKT",
    horizon_days: int = 20,
    *,
    seed: int = 1729,
) -> OpinionResult:
    """Run the complete workflow on explicitly synthetic deterministic data."""

    with tempfile.TemporaryDirectory(prefix="signallab-demo-") as directory:
        data_path = Path(directory) / "synthetic-market-data.csv"
        generate_demo_data(data_path, seed=seed)
        artifact = train_model(data_path, benchmark, horizon_days, seed=seed)
        return opinion_from_artifact(data_path, symbol, artifact, sample_data=True)
