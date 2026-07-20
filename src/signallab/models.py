# ruff: noqa: UP006, UP035, UP045 -- Keep annotations importable on Python 3.9.
"""Stable, dependency-free data structures for SignalLab."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Dict, Tuple

ARTIFACT_SCHEMA = "signallab.model"
ARTIFACT_VERSION = "1.0"
FEATURE_VERSION = "1.0"
DISCLAIMER = (
    "Research output only—not financial advice, a recommendation, or a promise of future "
    "performance. Markets can produce losses, including total loss of capital."
)
DIRECTIONAL_MIN_TEST_ROWS = 100
DIRECTIONAL_MIN_AUC = 0.53
DIRECTIONAL_MIN_BALANCED_ACCURACY = 0.52
DIRECTIONAL_MIN_BRIER_IMPROVEMENT = 0.002
DIRECTIONAL_MIN_EFFECTIVE_WINDOWS = 5
HIGH_CONFIDENCE_MIN_TEST_ROWS = 200
HIGH_CONFIDENCE_MIN_AUC = 0.60
HIGH_CONFIDENCE_MIN_BALANCED_ACCURACY = 0.55
HIGH_CONFIDENCE_MIN_BRIER_IMPROVEMENT = 0.01
HIGH_CONFIDENCE_MIN_EFFECTIVE_WINDOWS = 20


@dataclass(frozen=True)
class Bar:
    """One validated daily OHLCV observation."""

    date: str
    symbol: str
    open: float
    high: float
    low: float
    close: float
    volume: float
    adjusted_close: float


@dataclass(frozen=True)
class FeatureRow:
    """A point-in-time feature vector and, when available, its future label."""

    date: str
    symbol: str
    values: Tuple[float, ...]
    label: int
    future_excess_return: float
    label_end_date: str


@dataclass(frozen=True)
class FeatureStats:
    """Training-only standardization values."""

    mean: float
    scale: float

    def to_dict(self) -> Dict[str, float]:
        return {"mean": self.mean, "scale": self.scale}


@dataclass(frozen=True)
class DecisionStump:
    """One transparent regression stump in the boosted model."""

    feature_index: int
    threshold: float
    left_value: float
    right_value: float

    def to_dict(self) -> Dict[str, Any]:
        return {
            "feature_index": self.feature_index,
            "threshold": self.threshold,
            "left_value": self.left_value,
            "right_value": self.right_value,
        }


@dataclass(frozen=True)
class SplitMetadata:
    """Auditable chronological boundaries, including purged label endpoints."""

    train_start: str
    train_end: str
    train_label_end: str
    validation_start: str
    validation_end: str
    validation_label_end: str
    test_start: str
    test_end: str
    test_label_end: str
    train_rows: int
    validation_rows: int
    test_rows: int
    purged_rows: int
    excluded_unfitted_symbol_rows: int
    test_distinct_dates: int
    effective_test_windows: int

    def to_dict(self) -> Dict[str, Any]:
        return {
            "train_start": self.train_start,
            "train_end": self.train_end,
            "train_label_end": self.train_label_end,
            "validation_start": self.validation_start,
            "validation_end": self.validation_end,
            "validation_label_end": self.validation_label_end,
            "test_start": self.test_start,
            "test_end": self.test_end,
            "test_label_end": self.test_label_end,
            "train_rows": self.train_rows,
            "validation_rows": self.validation_rows,
            "test_rows": self.test_rows,
            "purged_rows": self.purged_rows,
            "excluded_unfitted_symbol_rows": self.excluded_unfitted_symbol_rows,
            "test_distinct_dates": self.test_distinct_dates,
            "effective_test_windows": self.effective_test_windows,
        }


@dataclass(frozen=True)
class MetricSet:
    """Binary probabilistic classification metrics."""

    accuracy: float
    balanced_accuracy: float
    brier: float
    roc_auc: float
    base_rate: float
    constant_brier: float
    rows: int

    def to_dict(self) -> Dict[str, Any]:
        return {
            "accuracy": self.accuracy,
            "balanced_accuracy": self.balanced_accuracy,
            "brier": self.brier,
            "roc_auc": self.roc_auc,
            "base_rate": self.base_rate,
            "constant_brier": self.constant_brier,
            "rows": self.rows,
        }


@dataclass(frozen=True)
class ModelArtifact:
    """Complete safe-JSON representation of a trained transparent ensemble."""

    schema: str
    version: str
    feature_version: str
    created_at: str
    data_sha256: str
    uses_adjusted_close: bool
    training_cutoff: str
    benchmark: str
    horizon_days: int
    seed: int
    feature_names: Tuple[str, ...]
    feature_stats: Tuple[FeatureStats, ...]
    logistic_intercept: float
    logistic_weights: Tuple[float, ...]
    logistic_l2: float
    stumps_base_logit: float
    stumps_learning_rate: float
    stumps: Tuple[DecisionStump, ...]
    blend_weight_logistic: float
    calibration_slope: float
    calibration_intercept: float
    split: SplitMetadata
    validation_metrics: MetricSet
    test_metrics: MetricSet
    training_symbols: Tuple[str, ...]
    model_params: Dict[str, Any]

    def to_dict(self) -> Dict[str, Any]:
        return {
            "schema": self.schema,
            "version": self.version,
            "feature_version": self.feature_version,
            "created_at": self.created_at,
            "data_sha256": self.data_sha256,
            "uses_adjusted_close": self.uses_adjusted_close,
            "training_cutoff": self.training_cutoff,
            "benchmark": self.benchmark,
            "horizon_days": self.horizon_days,
            "seed": self.seed,
            "feature_names": list(self.feature_names),
            "feature_stats": [item.to_dict() for item in self.feature_stats],
            "models": {
                "logistic": {
                    "intercept": self.logistic_intercept,
                    "weights": list(self.logistic_weights),
                    "l2": self.logistic_l2,
                },
                "gradient_boosted_stumps": {
                    "base_logit": self.stumps_base_logit,
                    "learning_rate": self.stumps_learning_rate,
                    "stumps": [item.to_dict() for item in self.stumps],
                },
                "ensemble": {
                    "blend_weight_logistic": self.blend_weight_logistic,
                    "calibration_slope": self.calibration_slope,
                    "calibration_intercept": self.calibration_intercept,
                },
            },
            "split": self.split.to_dict(),
            "metrics": {
                "validation": self.validation_metrics.to_dict(),
                "test": self.test_metrics.to_dict(),
            },
            "training_symbols": list(self.training_symbols),
            "model_params": dict(self.model_params),
        }


@dataclass(frozen=True)
class FactorContribution:
    """Directional, local evidence for an opinion."""

    feature: str
    label: str
    value: float
    contribution: float
    direction: str
    explanation: str

    def to_dict(self) -> Dict[str, Any]:
        return {
            "feature": self.feature,
            "label": self.label,
            "value": self.value,
            "direction": self.direction,
            "explanation": self.explanation,
        }


@dataclass(frozen=True)
class OpinionResult:
    """A calibrated research opinion with evidence and explicit limitations."""

    symbol: str
    benchmark: str
    as_of: str
    horizon_days: int
    opinion: str
    probability_outperform: float
    confidence: str
    sample_data: bool
    rationale: Tuple[FactorContribution, ...]
    model_test_metrics: MetricSet
    model_version: str
    model_trained_through: str
    model_training_rows: int
    model_symbols: Tuple[str, ...]
    model_feature_count: int
    model_test_start: str
    model_test_end: str
    model_effective_windows: int
    limitations: Tuple[str, ...]
    disclaimer: str

    def to_dict(self) -> Dict[str, Any]:
        return {
            "symbol": self.symbol,
            "benchmark": self.benchmark,
            "as_of": self.as_of,
            "horizon_days": self.horizon_days,
            "opinion": self.opinion,
            "probability_outperform": self.probability_outperform,
            "confidence": self.confidence,
            "sample_data": self.sample_data,
            "rationale": [item.to_dict() for item in self.rationale],
            "limitations": list(self.limitations),
            "disclaimer": self.disclaimer,
            "model": {
                "name": "SignalLab transparent ensemble",
                "version": self.model_version,
                "trained_through": self.model_trained_through,
                "training_rows": self.model_training_rows,
                "symbols": list(self.model_symbols),
                "feature_count": self.model_feature_count,
                "evaluation": {
                    "test_start": self.model_test_start,
                    "test_end": self.model_test_end,
                    "samples": self.model_test_metrics.rows,
                    "effective_windows": self.model_effective_windows,
                    "accuracy": self.model_test_metrics.accuracy,
                    "balanced_accuracy": self.model_test_metrics.balanced_accuracy,
                    "brier_score": self.model_test_metrics.brier,
                    "constant_brier": self.model_test_metrics.constant_brier,
                    "roc_auc": self.model_test_metrics.roc_auc,
                    "base_rate": self.model_test_metrics.base_rate,
                },
            },
        }
