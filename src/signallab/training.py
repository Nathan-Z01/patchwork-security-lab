# ruff: noqa: UP006, UP035, UP045 -- Keep annotations importable on Python 3.9.
"""Deterministic training for SignalLab's transparent two-model ensemble."""

from __future__ import annotations

import math
import random
import statistics
from dataclasses import replace
from pathlib import Path
from typing import List, Sequence, Tuple

from .data import load_market_csv, normalize_symbol
from .errors import DataValidationError, TrainingError
from .features import FEATURE_NAMES, build_labeled_rows, validate_horizon
from .models import (
    ARTIFACT_SCHEMA,
    ARTIFACT_VERSION,
    DIRECTIONAL_MIN_AUC,
    DIRECTIONAL_MIN_BALANCED_ACCURACY,
    DIRECTIONAL_MIN_BRIER_IMPROVEMENT,
    DIRECTIONAL_MIN_EFFECTIVE_WINDOWS,
    DIRECTIONAL_MIN_TEST_ROWS,
    FEATURE_VERSION,
    HIGH_CONFIDENCE_MIN_AUC,
    HIGH_CONFIDENCE_MIN_BALANCED_ACCURACY,
    HIGH_CONFIDENCE_MIN_BRIER_IMPROVEMENT,
    HIGH_CONFIDENCE_MIN_EFFECTIVE_WINDOWS,
    HIGH_CONFIDENCE_MIN_TEST_ROWS,
    DecisionStump,
    FeatureRow,
    FeatureStats,
    MetricSet,
    ModelArtifact,
    SplitMetadata,
)

MAX_TRAINING_ROWS = 20_000
LOGISTIC_ITERATIONS = 220
STUMP_ROUNDS = 36
STUMP_LEARNING_RATE = 0.08
LOGISTIC_L2 = 0.02


def _sigmoid(value: float) -> float:
    if value >= 0.0:
        inverse = math.exp(-min(value, 40.0))
        return 1.0 / (1.0 + inverse)
    exponent = math.exp(max(value, -40.0))
    return exponent / (1.0 + exponent)


def _logit(probability: float) -> float:
    bounded = min(max(probability, 1e-7), 1.0 - 1e-7)
    return math.log(bounded / (1.0 - bounded))


def _chronological_split(
    rows: Sequence[FeatureRow],
) -> Tuple[List[FeatureRow], List[FeatureRow], List[FeatureRow], SplitMetadata]:
    dates = sorted({item.date for item in rows})
    if len(dates) < 120:
        raise TrainingError(
            "at least 120 distinct labeled feature dates are required for train/validation/test"
        )
    validation_index = max(1, int(len(dates) * 0.60))
    test_index = max(validation_index + 1, int(len(dates) * 0.80))
    if test_index >= len(dates):
        raise TrainingError("not enough dates to create an untouched test split")
    validation_start = dates[validation_index]
    test_start = dates[test_index]

    train = [
        item
        for item in rows
        if item.date < validation_start and item.label_end_date < validation_start
    ]
    validation = [
        item
        for item in rows
        if validation_start <= item.date < test_start and item.label_end_date < test_start
    ]
    test = [item for item in rows if item.date >= test_start]
    assigned = len(train) + len(validation) + len(test)
    purged = len(rows) - assigned
    for name, split in (("training", train), ("validation", validation), ("test", test)):
        if len(split) < 20:
            raise TrainingError(
                f"{name} split has only {len(split)} rows; at least 20 are required"
            )
        if len({item.label for item in split}) < 2:
            raise TrainingError(f"{name} split must contain both target classes")
    if max(item.label_end_date for item in train) >= min(item.date for item in validation):
        raise TrainingError("training labels overlap the validation feature period")
    if max(item.label_end_date for item in validation) >= min(item.date for item in test):
        raise TrainingError("validation labels overlap the test feature period")

    metadata = SplitMetadata(
        train_start=min(item.date for item in train),
        train_end=max(item.date for item in train),
        train_label_end=max(item.label_end_date for item in train),
        validation_start=min(item.date for item in validation),
        validation_end=max(item.date for item in validation),
        validation_label_end=max(item.label_end_date for item in validation),
        test_start=min(item.date for item in test),
        test_end=max(item.date for item in test),
        test_label_end=max(item.label_end_date for item in test),
        train_rows=len(train),
        validation_rows=len(validation),
        test_rows=len(test),
        purged_rows=purged,
        excluded_unfitted_symbol_rows=0,
        test_distinct_dates=len({item.date for item in test}),
        effective_test_windows=0,
    )
    return train, validation, test, metadata


def _bounded_training_rows(rows: Sequence[FeatureRow], seed: int) -> List[FeatureRow]:
    if len(rows) <= MAX_TRAINING_ROWS:
        return list(rows)
    generator = random.Random(seed)  # noqa: S311 - deterministic sampling, not security.
    indices = sorted(generator.sample(range(len(rows)), MAX_TRAINING_ROWS))
    return [rows[index] for index in indices]


def _filter_evaluation_rows(
    validation: Sequence[FeatureRow],
    test: Sequence[FeatureRow],
    split: SplitMetadata,
    training_symbols: Sequence[str],
    horizon_days: int,
) -> Tuple[List[FeatureRow], List[FeatureRow], SplitMetadata]:
    """Restrict evaluation to symbols represented in the actual fitted sample."""

    allowed = set(training_symbols)
    filtered_validation = [item for item in validation if item.symbol in allowed]
    filtered_test = [item for item in test if item.symbol in allowed]
    for name, values in (("validation", filtered_validation), ("test", filtered_test)):
        if len(values) < 20:
            raise TrainingError(
                f"{name} split has only {len(values)} fitted-symbol rows; at least 20 are required"
            )
        if len({item.label for item in values}) < 2:
            raise TrainingError(f"{name} fitted-symbol split must contain both target classes")
    dropped = len(validation) + len(test) - len(filtered_validation) - len(filtered_test)
    updated = replace(
        split,
        validation_start=min(item.date for item in filtered_validation),
        validation_end=max(item.date for item in filtered_validation),
        validation_label_end=max(item.label_end_date for item in filtered_validation),
        test_start=min(item.date for item in filtered_test),
        test_end=max(item.date for item in filtered_test),
        test_label_end=max(item.label_end_date for item in filtered_test),
        validation_rows=len(filtered_validation),
        test_rows=len(filtered_test),
        excluded_unfitted_symbol_rows=dropped,
        test_distinct_dates=len({item.date for item in filtered_test}),
        effective_test_windows=(
            len({item.date for item in filtered_test}) // horizon_days
        ),
    )
    if updated.train_label_end >= updated.validation_start:
        raise TrainingError("filtered validation rows violate the training horizon purge")
    if updated.validation_label_end >= updated.test_start:
        raise TrainingError("filtered test rows violate the validation horizon purge")
    return filtered_validation, filtered_test, updated


def _feature_stats(rows: Sequence[FeatureRow]) -> Tuple[FeatureStats, ...]:
    result = []
    for feature_index in range(len(FEATURE_NAMES)):
        values = [item.values[feature_index] for item in rows]
        mean = statistics.fmean(values)
        scale = statistics.pstdev(values)
        if scale < 1e-9:
            scale = 1.0
        result.append(FeatureStats(mean, scale))
    return tuple(result)


def standardize(
    values: Sequence[float], stats: Sequence[FeatureStats]
) -> Tuple[float, ...]:
    return tuple((value - stat.mean) / stat.scale for value, stat in zip(values, stats))


def _matrix(
    rows: Sequence[FeatureRow], stats: Sequence[FeatureStats]
) -> Tuple[List[Tuple[float, ...]], List[int]]:
    return [standardize(item.values, stats) for item in rows], [item.label for item in rows]


def _fit_logistic(
    matrix: Sequence[Sequence[float]], labels: Sequence[int]
) -> Tuple[float, Tuple[float, ...]]:
    feature_count = len(FEATURE_NAMES)
    base_rate = (sum(labels) + 0.5) / (len(labels) + 1.0)
    intercept = _logit(base_rate)
    weights = [0.0] * feature_count
    for iteration in range(LOGISTIC_ITERATIONS):
        intercept_gradient = 0.0
        gradients = [0.0] * feature_count
        for values, label in zip(matrix, labels):
            score = intercept + sum(weight * value for weight, value in zip(weights, values))
            error = _sigmoid(score) - label
            intercept_gradient += error
            for index, value in enumerate(values):
                gradients[index] += error * value
        rate = 0.16 / math.sqrt(1.0 + iteration * 0.04)
        inverse_count = 1.0 / len(labels)
        intercept -= rate * intercept_gradient * inverse_count
        for index in range(feature_count):
            gradient = gradients[index] * inverse_count + LOGISTIC_L2 * weights[index]
            weights[index] -= rate * gradient
    return intercept, tuple(weights)


def logistic_probability(
    values: Sequence[float], intercept: float, weights: Sequence[float]
) -> float:
    return _sigmoid(intercept + sum(weight * value for weight, value in zip(weights, values)))


def _best_stump(
    matrix: Sequence[Sequence[float]],
    residuals: Sequence[float],
    hessians: Sequence[float],
    sorted_orders: Sequence[Sequence[int]],
) -> DecisionStump:
    row_count = len(matrix)
    min_leaf = max(5, row_count // 100)
    total_sum = sum(residuals)
    total_square = sum(value * value for value in residuals)
    best_loss = float("inf")
    best = DecisionStump(0, 0.0, 0.0, 0.0)
    total_hessian = sum(hessians)
    for feature_index in range(len(FEATURE_NAMES)):
        order = sorted_orders[feature_index]
        left_sum = 0.0
        left_square = 0.0
        left_hessian = 0.0
        for position, row_index in enumerate(order[:-1], start=1):
            residual = residuals[row_index]
            left_sum += residual
            left_square += residual * residual
            left_hessian += hessians[row_index]
            if position < min_leaf or row_count - position < min_leaf:
                continue
            current_value = matrix[row_index][feature_index]
            next_value = matrix[order[position]][feature_index]
            if current_value == next_value:
                continue
            right_sum = total_sum - left_sum
            right_square = total_square - left_square
            left_loss = left_square - left_sum * left_sum / position
            right_count = row_count - position
            right_loss = right_square - right_sum * right_sum / right_count
            loss = left_loss + right_loss
            if loss < best_loss - 1e-15:
                best_loss = loss
                right_hessian = total_hessian - left_hessian
                left_value = left_sum / max(left_hessian, 1e-6)
                right_value = right_sum / max(right_hessian, 1e-6)
                best = DecisionStump(
                    feature_index=feature_index,
                    threshold=(current_value + next_value) / 2.0,
                    left_value=max(-3.0, min(3.0, left_value)),
                    right_value=max(-3.0, min(3.0, right_value)),
                )
    if not math.isfinite(best_loss):
        raise TrainingError("gradient-boosted stump learner could not find a valid split")
    return best


def _fit_stumps(
    matrix: Sequence[Sequence[float]], labels: Sequence[int]
) -> Tuple[float, Tuple[DecisionStump, ...]]:
    base_rate = (sum(labels) + 0.5) / (len(labels) + 1.0)
    base_logit = _logit(base_rate)
    scores = [base_logit] * len(labels)
    stumps = []
    sorted_orders = [
        sorted(range(len(matrix)), key=lambda row: (matrix[row][feature_index], row))
        for feature_index in range(len(FEATURE_NAMES))
    ]
    for _ in range(STUMP_ROUNDS):
        probabilities = [_sigmoid(score) for score in scores]
        residuals = [label - probability for label, probability in zip(labels, probabilities)]
        hessians = [max(probability * (1.0 - probability), 1e-5) for probability in probabilities]
        stump = _best_stump(matrix, residuals, hessians, sorted_orders)
        stumps.append(stump)
        for index, values in enumerate(matrix):
            leaf = (
                stump.left_value
                if values[stump.feature_index] <= stump.threshold
                else stump.right_value
            )
            scores[index] += STUMP_LEARNING_RATE * leaf
    return base_logit, tuple(stumps)


def stumps_probability(
    values: Sequence[float],
    base_logit: float,
    learning_rate: float,
    stumps: Sequence[DecisionStump],
) -> float:
    score = base_logit
    for stump in stumps:
        leaf = (
            stump.left_value
            if values[stump.feature_index] <= stump.threshold
            else stump.right_value
        )
        score += learning_rate * leaf
    return _sigmoid(score)


def _raw_predictions(
    matrix: Sequence[Sequence[float]],
    logistic_intercept: float,
    logistic_weights: Sequence[float],
    stumps_base_logit: float,
    stumps: Sequence[DecisionStump],
) -> Tuple[List[float], List[float]]:
    logistic = [
        logistic_probability(values, logistic_intercept, logistic_weights) for values in matrix
    ]
    boosted = [
        stumps_probability(values, stumps_base_logit, STUMP_LEARNING_RATE, stumps)
        for values in matrix
    ]
    return logistic, boosted


def _fit_calibration(
    probabilities: Sequence[float], labels: Sequence[int]
) -> Tuple[float, float]:
    logits = [_logit(value) for value in probabilities]
    slope = 1.0
    intercept = 0.0
    for iteration in range(180):
        slope_gradient = 0.0
        intercept_gradient = 0.0
        for value, label in zip(logits, labels):
            error = _sigmoid(intercept + slope * value) - label
            intercept_gradient += error
            slope_gradient += error * value
        inverse = 1.0 / len(labels)
        rate = 0.08 / math.sqrt(1.0 + iteration * 0.03)
        intercept -= rate * intercept_gradient * inverse
        slope -= rate * (slope_gradient * inverse + 0.01 * (slope - 1.0))
        slope = max(0.05, min(5.0, slope))
        intercept = max(-5.0, min(5.0, intercept))
    return slope, intercept


def calibrated_probability(
    logistic: float,
    boosted: float,
    blend_weight_logistic: float,
    calibration_slope: float,
    calibration_intercept: float,
) -> float:
    blended = blend_weight_logistic * logistic + (1.0 - blend_weight_logistic) * boosted
    return _sigmoid(calibration_intercept + calibration_slope * _logit(blended))


def _tune_ensemble(
    logistic: Sequence[float], boosted: Sequence[float], labels: Sequence[int]
) -> Tuple[float, float, float, List[float]]:
    best: Tuple[float, float, float, float, List[float]] = (
        float("inf"),
        0.5,
        1.0,
        0.0,
        [],
    )
    for step in range(11):
        weight = step / 10.0
        blended = [weight * left + (1.0 - weight) * right for left, right in zip(logistic, boosted)]
        slope, intercept = _fit_calibration(blended, labels)
        calibrated = [
            _sigmoid(intercept + slope * _logit(probability)) for probability in blended
        ]
        brier = sum(
            (probability - label) ** 2
            for probability, label in zip(calibrated, labels)
        ) / len(labels)
        candidate = (brier, weight, slope, intercept, calibrated)
        if candidate[:4] < best[:4]:
            best = candidate
    return best[1], best[2], best[3], best[4]


def _roc_auc(labels: Sequence[int], probabilities: Sequence[float]) -> float:
    positives = sum(labels)
    negatives = len(labels) - positives
    if positives == 0 or negatives == 0:
        return 0.5
    ordered = sorted(zip(probabilities, labels), key=lambda item: item[0])
    rank_sum = 0.0
    index = 0
    while index < len(ordered):
        end = index + 1
        while end < len(ordered) and ordered[end][0] == ordered[index][0]:
            end += 1
        average_rank = ((index + 1) + end) / 2.0
        rank_sum += average_rank * sum(label for _, label in ordered[index:end])
        index = end
    return (rank_sum - positives * (positives + 1) / 2.0) / (positives * negatives)


def calculate_metrics(
    labels: Sequence[int], probabilities: Sequence[float], baseline_probability: float
) -> MetricSet:
    if len(labels) != len(probabilities) or not labels:
        raise ValueError("metrics require equal non-empty labels and probabilities")
    predictions = [1 if value >= 0.5 else 0 for value in probabilities]
    correct = sum(prediction == label for prediction, label in zip(predictions, labels))
    positives = sum(labels)
    negatives = len(labels) - positives
    true_positive = sum(
        prediction == 1 and label == 1 for prediction, label in zip(predictions, labels)
    )
    true_negative = sum(
        prediction == 0 and label == 0 for prediction, label in zip(predictions, labels)
    )
    sensitivity = true_positive / positives if positives else 0.5
    specificity = true_negative / negatives if negatives else 0.5
    return MetricSet(
        accuracy=correct / len(labels),
        balanced_accuracy=(sensitivity + specificity) / 2.0,
        brier=sum((value - label) ** 2 for value, label in zip(probabilities, labels))
        / len(labels),
        roc_auc=_roc_auc(labels, probabilities),
        base_rate=positives / len(labels),
        constant_brier=sum((baseline_probability - label) ** 2 for label in labels)
        / len(labels),
        rows=len(labels),
    )


def predict_probability(artifact: ModelArtifact, raw_values: Sequence[float]) -> float:
    """Score one raw feature vector with the complete calibrated ensemble."""

    values = standardize(raw_values, artifact.feature_stats)
    logistic = logistic_probability(
        values, artifact.logistic_intercept, artifact.logistic_weights
    )
    boosted = stumps_probability(
        values,
        artifact.stumps_base_logit,
        artifact.stumps_learning_rate,
        artifact.stumps,
    )
    return calibrated_probability(
        logistic,
        boosted,
        artifact.blend_weight_logistic,
        artifact.calibration_slope,
        artifact.calibration_intercept,
    )


def train_model(
    data_path: Path,
    benchmark: str = "SPY",
    horizon_days: int = 20,
    *,
    seed: int = 1729,
) -> ModelArtifact:
    """Train and evaluate a deterministic, leakage-purged transparent ensemble."""

    if isinstance(seed, bool) or not isinstance(seed, int) or not 0 <= seed <= 2**31 - 1:
        raise DataValidationError("seed must be an integer between 0 and 2147483647")
    reference = normalize_symbol(benchmark, "benchmark")
    horizon = validate_horizon(horizon_days)
    bars, digest, uses_adjusted_close = load_market_csv(Path(data_path))
    if reference not in bars:
        raise DataValidationError(f"benchmark {reference!r} is not present in the market data")
    rows = build_labeled_rows(bars, reference, horizon)
    train_full, validation, test, split = _chronological_split(rows)
    train = _bounded_training_rows(train_full, seed)
    training_symbols = tuple(sorted({item.symbol for item in train}))
    validation, test, split = _filter_evaluation_rows(
        validation, test, split, training_symbols, horizon
    )
    stats = _feature_stats(train)
    train_matrix, train_labels = _matrix(train, stats)
    validation_matrix, validation_labels = _matrix(validation, stats)
    test_matrix, test_labels = _matrix(test, stats)

    logistic_intercept, logistic_weights = _fit_logistic(train_matrix, train_labels)
    stumps_base_logit, stumps = _fit_stumps(train_matrix, train_labels)
    validation_logistic, validation_boosted = _raw_predictions(
        validation_matrix,
        logistic_intercept,
        logistic_weights,
        stumps_base_logit,
        stumps,
    )
    blend, calibration_slope, calibration_intercept, validation_probabilities = _tune_ensemble(
        validation_logistic, validation_boosted, validation_labels
    )
    test_logistic, test_boosted = _raw_predictions(
        test_matrix,
        logistic_intercept,
        logistic_weights,
        stumps_base_logit,
        stumps,
    )
    test_probabilities = [
        calibrated_probability(
            left,
            right,
            blend,
            calibration_slope,
            calibration_intercept,
        )
        for left, right in zip(test_logistic, test_boosted)
    ]
    training_base_rate = sum(train_labels) / len(train_labels)
    validation_metrics = calculate_metrics(
        validation_labels, validation_probabilities, training_base_rate
    )
    test_metrics = calculate_metrics(test_labels, test_probabilities, training_base_rate)
    last_data_date = max(item.date for history in bars.values() for item in history)
    artifact = ModelArtifact(
        schema=ARTIFACT_SCHEMA,
        version=ARTIFACT_VERSION,
        feature_version=FEATURE_VERSION,
        created_at=f"{last_data_date}T00:00:00Z",
        data_sha256=digest,
        uses_adjusted_close=uses_adjusted_close,
        training_cutoff=split.validation_label_end,
        benchmark=reference,
        horizon_days=horizon,
        seed=seed,
        feature_names=FEATURE_NAMES,
        feature_stats=stats,
        logistic_intercept=logistic_intercept,
        logistic_weights=logistic_weights,
        logistic_l2=LOGISTIC_L2,
        stumps_base_logit=stumps_base_logit,
        stumps_learning_rate=STUMP_LEARNING_RATE,
        stumps=stumps,
        blend_weight_logistic=blend,
        calibration_slope=calibration_slope,
        calibration_intercept=calibration_intercept,
        split=split,
        validation_metrics=validation_metrics,
        test_metrics=test_metrics,
        training_symbols=training_symbols,
        model_params={
            "algorithm": "regularized_logistic_plus_gradient_boosted_decision_stumps",
            "logistic_iterations": LOGISTIC_ITERATIONS,
            "stump_rounds": STUMP_ROUNDS,
            "max_training_rows": MAX_TRAINING_ROWS,
            "split_ratios": [0.6, 0.2, 0.2],
            "horizon_purge": True,
            "threshold": 0.5,
            "deterministic_timestamp": "latest_input_observation_at_midnight_utc",
            "directional_min_test_rows": DIRECTIONAL_MIN_TEST_ROWS,
            "directional_min_auc": DIRECTIONAL_MIN_AUC,
            "directional_min_balanced_accuracy": DIRECTIONAL_MIN_BALANCED_ACCURACY,
            "directional_min_brier_improvement": DIRECTIONAL_MIN_BRIER_IMPROVEMENT,
            "directional_min_effective_windows": DIRECTIONAL_MIN_EFFECTIVE_WINDOWS,
            "high_confidence_min_test_rows": HIGH_CONFIDENCE_MIN_TEST_ROWS,
            "high_confidence_min_auc": HIGH_CONFIDENCE_MIN_AUC,
            "high_confidence_min_balanced_accuracy": HIGH_CONFIDENCE_MIN_BALANCED_ACCURACY,
            "high_confidence_min_brier_improvement": HIGH_CONFIDENCE_MIN_BRIER_IMPROVEMENT,
            "high_confidence_min_effective_windows": HIGH_CONFIDENCE_MIN_EFFECTIVE_WINDOWS,
        },
    )
    # Keep metadata honest if deterministic downsampling was necessary.
    if len(train) != len(train_full):
        artifact = replace(
            artifact,
            model_params={**artifact.model_params, "fitted_training_rows": len(train)},
        )
    return artifact
