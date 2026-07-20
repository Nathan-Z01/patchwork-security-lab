# ruff: noqa: UP006, UP035, UP045 -- Keep annotations importable on Python 3.9.
"""Strict, non-executable JSON persistence for SignalLab model artifacts."""

from __future__ import annotations

import json
import math
import os
import re
import tempfile
from contextlib import suppress
from datetime import date, datetime
from pathlib import Path
from typing import Any, Dict, List, Mapping, Sequence, Tuple

from .errors import ArtifactError
from .features import FEATURE_NAMES
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
    FeatureStats,
    MetricSet,
    ModelArtifact,
    SplitMetadata,
)

MAX_ARTIFACT_BYTES = 4 * 1024 * 1024
MAX_STUMPS = 512
_SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
_SYMBOL_RE = re.compile(r"^[A-Z0-9][A-Z0-9._-]{0,15}$")


def _strict_object(
    value: Any,
    path: str,
    required: Sequence[str],
    *,
    optional: Sequence[str] = (),
) -> Mapping[str, Any]:
    if not isinstance(value, dict):
        raise ArtifactError(f"{path} must be a JSON object")
    allowed = set(required).union(optional)
    unknown = sorted(set(value).difference(allowed))
    missing = sorted(set(required).difference(value))
    if unknown:
        raise ArtifactError(f"{path}.{unknown[0]} is not allowed")
    if missing:
        raise ArtifactError(f"{path}.{missing[0]} is required")
    return value


def _string(value: Any, path: str) -> str:
    if not isinstance(value, str) or not value or "\x00" in value:
        raise ArtifactError(f"{path} must be a non-empty string without NUL bytes")
    return value


def _number(
    value: Any,
    path: str,
    *,
    minimum: float = -1e12,
    maximum: float = 1e12,
) -> float:
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise ArtifactError(f"{path} must be a finite number")
    try:
        result = float(value)
    except (OverflowError, ValueError) as exc:
        raise ArtifactError(f"{path} must be a finite number") from exc
    if not math.isfinite(result) or not minimum <= result <= maximum:
        raise ArtifactError(f"{path} must be finite and between {minimum} and {maximum}")
    return result


def _integer(value: Any, path: str, minimum: int, maximum: int) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or not minimum <= value <= maximum:
        raise ArtifactError(f"{path} must be an integer between {minimum} and {maximum}")
    return value


def _date_string(value: Any, path: str) -> str:
    candidate = _string(value, path)
    try:
        parsed = date.fromisoformat(candidate)
    except ValueError as exc:
        raise ArtifactError(f"{path} must use YYYY-MM-DD format") from exc
    if parsed.isoformat() != candidate:
        raise ArtifactError(f"{path} must use YYYY-MM-DD format")
    return candidate


def _metric(value: Any, path: str) -> MetricSet:
    data = _strict_object(
        value,
        path,
        (
            "accuracy",
            "balanced_accuracy",
            "brier",
            "roc_auc",
            "base_rate",
            "constant_brier",
            "rows",
        ),
    )
    return MetricSet(
        accuracy=_number(data["accuracy"], f"{path}.accuracy", minimum=0.0, maximum=1.0),
        balanced_accuracy=_number(
            data["balanced_accuracy"],
            f"{path}.balanced_accuracy",
            minimum=0.0,
            maximum=1.0,
        ),
        brier=_number(data["brier"], f"{path}.brier", minimum=0.0, maximum=1.0),
        roc_auc=_number(data["roc_auc"], f"{path}.roc_auc", minimum=0.0, maximum=1.0),
        base_rate=_number(
            data["base_rate"], f"{path}.base_rate", minimum=0.0, maximum=1.0
        ),
        constant_brier=_number(
            data["constant_brier"],
            f"{path}.constant_brier",
            minimum=0.0,
            maximum=1.0,
        ),
        rows=_integer(data["rows"], f"{path}.rows", 1, 10_000_000),
    )


def _split(value: Any) -> SplitMetadata:
    keys = (
        "train_start",
        "train_end",
        "train_label_end",
        "validation_start",
        "validation_end",
        "validation_label_end",
        "test_start",
        "test_end",
        "test_label_end",
        "train_rows",
        "validation_rows",
        "test_rows",
        "purged_rows",
        "excluded_unfitted_symbol_rows",
        "test_distinct_dates",
        "effective_test_windows",
    )
    data = _strict_object(value, "$.split", keys)
    dates = {key: _date_string(data[key], f"$.split.{key}") for key in keys[:9]}
    if not (
        dates["train_start"]
        <= dates["train_end"]
        <= dates["train_label_end"]
        < dates["validation_start"]
        <= dates["validation_end"]
        <= dates["validation_label_end"]
        < dates["test_start"]
        <= dates["test_end"]
        <= dates["test_label_end"]
    ):
        raise ArtifactError("$.split dates violate chronological purge ordering")
    return SplitMetadata(
        **dates,
        train_rows=_integer(data["train_rows"], "$.split.train_rows", 1, 10_000_000),
        validation_rows=_integer(
            data["validation_rows"], "$.split.validation_rows", 1, 10_000_000
        ),
        test_rows=_integer(data["test_rows"], "$.split.test_rows", 1, 10_000_000),
        purged_rows=_integer(data["purged_rows"], "$.split.purged_rows", 0, 10_000_000),
        excluded_unfitted_symbol_rows=_integer(
            data["excluded_unfitted_symbol_rows"],
            "$.split.excluded_unfitted_symbol_rows",
            0,
            10_000_000,
        ),
        test_distinct_dates=_integer(
            data["test_distinct_dates"], "$.split.test_distinct_dates", 1, 10_000_000
        ),
        effective_test_windows=_integer(
            data["effective_test_windows"],
            "$.split.effective_test_windows",
            0,
            10_000_000,
        ),
    )


def artifact_from_dict(value: Any) -> ModelArtifact:
    """Validate every artifact property and construct an immutable model."""

    root_keys = (
        "schema",
        "version",
        "feature_version",
        "created_at",
        "data_sha256",
        "uses_adjusted_close",
        "training_cutoff",
        "benchmark",
        "horizon_days",
        "seed",
        "feature_names",
        "feature_stats",
        "models",
        "split",
        "metrics",
        "training_symbols",
        "model_params",
    )
    data = _strict_object(value, "$", root_keys)
    if data["schema"] != ARTIFACT_SCHEMA:
        raise ArtifactError(f"$.schema must equal {ARTIFACT_SCHEMA!r}")
    if data["version"] != ARTIFACT_VERSION:
        raise ArtifactError(f"unsupported artifact version {data['version']!r}")
    if data["feature_version"] != FEATURE_VERSION:
        raise ArtifactError(f"unsupported feature version {data['feature_version']!r}")
    created_at = _string(data["created_at"], "$.created_at")
    try:
        datetime.fromisoformat(created_at.replace("Z", "+00:00"))
    except ValueError as exc:
        raise ArtifactError("$.created_at must be an ISO-8601 timestamp") from exc
    digest = _string(data["data_sha256"], "$.data_sha256")
    if not _SHA256_RE.fullmatch(digest):
        raise ArtifactError("$.data_sha256 must be a lowercase SHA-256 digest")
    if not isinstance(data["uses_adjusted_close"], bool):
        raise ArtifactError("$.uses_adjusted_close must be a boolean")
    uses_adjusted_close = data["uses_adjusted_close"]
    cutoff = _date_string(data["training_cutoff"], "$.training_cutoff")
    benchmark = _string(data["benchmark"], "$.benchmark")
    if not _SYMBOL_RE.fullmatch(benchmark):
        raise ArtifactError("$.benchmark is not a normalized symbol")
    horizon = _integer(data["horizon_days"], "$.horizon_days", 1, 60)
    seed = _integer(data["seed"], "$.seed", 0, 2**31 - 1)

    if not isinstance(data["feature_names"], list) or tuple(data["feature_names"]) != FEATURE_NAMES:
        raise ArtifactError("$.feature_names must exactly match the supported feature contract")
    if not isinstance(data["feature_stats"], list) or len(data["feature_stats"]) != len(
        FEATURE_NAMES
    ):
        raise ArtifactError("$.feature_stats must contain one item per feature")
    stats = []
    for index, item in enumerate(data["feature_stats"]):
        stat = _strict_object(item, f"$.feature_stats[{index}]", ("mean", "scale"))
        stats.append(
            FeatureStats(
                mean=_number(stat["mean"], f"$.feature_stats[{index}].mean"),
                scale=_number(
                    stat["scale"],
                    f"$.feature_stats[{index}].scale",
                    minimum=1e-12,
                    maximum=1e12,
                ),
            )
        )

    models = _strict_object(
        data["models"],
        "$.models",
        ("logistic", "gradient_boosted_stumps", "ensemble"),
    )
    logistic = _strict_object(
        models["logistic"], "$.models.logistic", ("intercept", "weights", "l2")
    )
    weights_data = logistic["weights"]
    if not isinstance(weights_data, list) or len(weights_data) != len(FEATURE_NAMES):
        raise ArtifactError("$.models.logistic.weights must contain one weight per feature")
    weights = tuple(
        _number(item, f"$.models.logistic.weights[{index}]")
        for index, item in enumerate(weights_data)
    )
    boosted = _strict_object(
        models["gradient_boosted_stumps"],
        "$.models.gradient_boosted_stumps",
        ("base_logit", "learning_rate", "stumps"),
    )
    stumps_data = boosted["stumps"]
    if not isinstance(stumps_data, list) or not 1 <= len(stumps_data) <= MAX_STUMPS:
        raise ArtifactError(
            f"$.models.gradient_boosted_stumps.stumps must have 1-{MAX_STUMPS} items"
        )
    stumps = []
    for index, item in enumerate(stumps_data):
        path = f"$.models.gradient_boosted_stumps.stumps[{index}]"
        stump = _strict_object(
            item, path, ("feature_index", "threshold", "left_value", "right_value")
        )
        stumps.append(
            DecisionStump(
                feature_index=_integer(
                    stump["feature_index"],
                    f"{path}.feature_index",
                    0,
                    len(FEATURE_NAMES) - 1,
                ),
                threshold=_number(stump["threshold"], f"{path}.threshold"),
                left_value=_number(stump["left_value"], f"{path}.left_value"),
                right_value=_number(stump["right_value"], f"{path}.right_value"),
            )
        )
    ensemble = _strict_object(
        models["ensemble"],
        "$.models.ensemble",
        ("blend_weight_logistic", "calibration_slope", "calibration_intercept"),
    )
    split = _split(data["split"])
    if cutoff != split.validation_label_end:
        raise ArtifactError("$.training_cutoff must equal the final calibration-label date")
    if split.effective_test_windows != split.test_distinct_dates // horizon:
        raise ArtifactError(
            "$.split.effective_test_windows must equal floor(test_distinct_dates / horizon_days)"
        )
    metrics = _strict_object(data["metrics"], "$.metrics", ("validation", "test"))
    validation_metrics = _metric(metrics["validation"], "$.metrics.validation")
    test_metrics = _metric(metrics["test"], "$.metrics.test")
    if validation_metrics.rows != split.validation_rows or test_metrics.rows != split.test_rows:
        raise ArtifactError("metric row counts must match split row counts")

    symbols_data = data["training_symbols"]
    if not isinstance(symbols_data, list) or not symbols_data or len(symbols_data) > 511:
        raise ArtifactError("$.training_symbols must be a non-empty bounded array")
    symbols = []
    for index, item in enumerate(symbols_data):
        symbol = _string(item, f"$.training_symbols[{index}]")
        if not _SYMBOL_RE.fullmatch(symbol) or symbol == benchmark:
            raise ArtifactError(f"$.training_symbols[{index}] is invalid")
        symbols.append(symbol)
    if tuple(sorted(set(symbols))) != tuple(symbols):
        raise ArtifactError("$.training_symbols must be sorted and unique")

    params = _strict_object(
        data["model_params"],
        "$.model_params",
        (
            "algorithm",
            "logistic_iterations",
            "stump_rounds",
            "max_training_rows",
            "split_ratios",
            "horizon_purge",
            "threshold",
            "deterministic_timestamp",
            "directional_min_test_rows",
            "directional_min_auc",
            "directional_min_balanced_accuracy",
            "directional_min_brier_improvement",
            "directional_min_effective_windows",
            "high_confidence_min_test_rows",
            "high_confidence_min_auc",
            "high_confidence_min_balanced_accuracy",
            "high_confidence_min_brier_improvement",
            "high_confidence_min_effective_windows",
        ),
        optional=("fitted_training_rows",),
    )
    if params["algorithm"] != "regularized_logistic_plus_gradient_boosted_decision_stumps":
        raise ArtifactError("$.model_params.algorithm is unsupported")
    if params["horizon_purge"] is not True:
        raise ArtifactError("$.model_params.horizon_purge must be true")
    split_ratios = params["split_ratios"]
    if split_ratios != [0.6, 0.2, 0.2]:
        raise ArtifactError("$.model_params.split_ratios must equal [0.6, 0.2, 0.2]")
    validated_params: Dict[str, Any] = {
        "algorithm": params["algorithm"],
        "logistic_iterations": _integer(
            params["logistic_iterations"], "$.model_params.logistic_iterations", 1, 100_000
        ),
        "stump_rounds": _integer(
            params["stump_rounds"], "$.model_params.stump_rounds", 1, MAX_STUMPS
        ),
        "max_training_rows": _integer(
            params["max_training_rows"], "$.model_params.max_training_rows", 1, 1_000_000
        ),
        "split_ratios": [0.6, 0.2, 0.2],
        "horizon_purge": True,
        "threshold": _number(
            params["threshold"], "$.model_params.threshold", minimum=0.0, maximum=1.0
        ),
        "deterministic_timestamp": _string(
            params["deterministic_timestamp"], "$.model_params.deterministic_timestamp"
        ),
        "directional_min_test_rows": _integer(
            params["directional_min_test_rows"],
            "$.model_params.directional_min_test_rows",
            DIRECTIONAL_MIN_TEST_ROWS,
            DIRECTIONAL_MIN_TEST_ROWS,
        ),
        "directional_min_auc": _number(
            params["directional_min_auc"],
            "$.model_params.directional_min_auc",
            minimum=DIRECTIONAL_MIN_AUC,
            maximum=DIRECTIONAL_MIN_AUC,
        ),
        "directional_min_balanced_accuracy": _number(
            params["directional_min_balanced_accuracy"],
            "$.model_params.directional_min_balanced_accuracy",
            minimum=DIRECTIONAL_MIN_BALANCED_ACCURACY,
            maximum=DIRECTIONAL_MIN_BALANCED_ACCURACY,
        ),
        "directional_min_brier_improvement": _number(
            params["directional_min_brier_improvement"],
            "$.model_params.directional_min_brier_improvement",
            minimum=DIRECTIONAL_MIN_BRIER_IMPROVEMENT,
            maximum=DIRECTIONAL_MIN_BRIER_IMPROVEMENT,
        ),
        "directional_min_effective_windows": _integer(
            params["directional_min_effective_windows"],
            "$.model_params.directional_min_effective_windows",
            DIRECTIONAL_MIN_EFFECTIVE_WINDOWS,
            DIRECTIONAL_MIN_EFFECTIVE_WINDOWS,
        ),
        "high_confidence_min_test_rows": _integer(
            params["high_confidence_min_test_rows"],
            "$.model_params.high_confidence_min_test_rows",
            HIGH_CONFIDENCE_MIN_TEST_ROWS,
            HIGH_CONFIDENCE_MIN_TEST_ROWS,
        ),
        "high_confidence_min_auc": _number(
            params["high_confidence_min_auc"],
            "$.model_params.high_confidence_min_auc",
            minimum=HIGH_CONFIDENCE_MIN_AUC,
            maximum=HIGH_CONFIDENCE_MIN_AUC,
        ),
        "high_confidence_min_balanced_accuracy": _number(
            params["high_confidence_min_balanced_accuracy"],
            "$.model_params.high_confidence_min_balanced_accuracy",
            minimum=HIGH_CONFIDENCE_MIN_BALANCED_ACCURACY,
            maximum=HIGH_CONFIDENCE_MIN_BALANCED_ACCURACY,
        ),
        "high_confidence_min_brier_improvement": _number(
            params["high_confidence_min_brier_improvement"],
            "$.model_params.high_confidence_min_brier_improvement",
            minimum=HIGH_CONFIDENCE_MIN_BRIER_IMPROVEMENT,
            maximum=HIGH_CONFIDENCE_MIN_BRIER_IMPROVEMENT,
        ),
        "high_confidence_min_effective_windows": _integer(
            params["high_confidence_min_effective_windows"],
            "$.model_params.high_confidence_min_effective_windows",
            HIGH_CONFIDENCE_MIN_EFFECTIVE_WINDOWS,
            HIGH_CONFIDENCE_MIN_EFFECTIVE_WINDOWS,
        ),
    }
    if "fitted_training_rows" in params:
        validated_params["fitted_training_rows"] = _integer(
            params["fitted_training_rows"],
            "$.model_params.fitted_training_rows",
            1,
            1_000_000,
        )

    return ModelArtifact(
        schema=ARTIFACT_SCHEMA,
        version=ARTIFACT_VERSION,
        feature_version=FEATURE_VERSION,
        created_at=created_at,
        data_sha256=digest,
        uses_adjusted_close=uses_adjusted_close,
        training_cutoff=cutoff,
        benchmark=benchmark,
        horizon_days=horizon,
        seed=seed,
        feature_names=FEATURE_NAMES,
        feature_stats=tuple(stats),
        logistic_intercept=_number(
            logistic["intercept"], "$.models.logistic.intercept"
        ),
        logistic_weights=weights,
        logistic_l2=_number(
            logistic["l2"], "$.models.logistic.l2", minimum=0.0, maximum=1000.0
        ),
        stumps_base_logit=_number(
            boosted["base_logit"], "$.models.gradient_boosted_stumps.base_logit"
        ),
        stumps_learning_rate=_number(
            boosted["learning_rate"],
            "$.models.gradient_boosted_stumps.learning_rate",
            minimum=1e-12,
            maximum=1.0,
        ),
        stumps=tuple(stumps),
        blend_weight_logistic=_number(
            ensemble["blend_weight_logistic"],
            "$.models.ensemble.blend_weight_logistic",
            minimum=0.0,
            maximum=1.0,
        ),
        calibration_slope=_number(
            ensemble["calibration_slope"],
            "$.models.ensemble.calibration_slope",
            minimum=0.0,
            maximum=10.0,
        ),
        calibration_intercept=_number(
            ensemble["calibration_intercept"], "$.models.ensemble.calibration_intercept"
        ),
        split=split,
        validation_metrics=validation_metrics,
        test_metrics=test_metrics,
        training_symbols=tuple(symbols),
        model_params=validated_params,
    )


def _reject_constant(value: str) -> None:
    raise ArtifactError(f"non-finite JSON number {value!r} is not allowed")


def _reject_duplicate_pairs(pairs: List[Tuple[str, Any]]) -> Dict[str, Any]:
    result: Dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ArtifactError(f"duplicate JSON property {key!r} is not allowed")
        result[key] = value
    return result


def dumps_artifact(artifact: ModelArtifact) -> str:
    """Return canonical, human-inspectable JSON after contract validation."""

    validated = artifact_from_dict(artifact.to_dict())
    return json.dumps(validated.to_dict(), indent=2, sort_keys=True, allow_nan=False) + "\n"


def write_artifact(artifact: ModelArtifact, path: Path) -> None:
    """Atomically write a validated artifact without executable serialization."""

    destination = Path(path)
    if destination.exists() and destination.is_symlink():
        raise ArtifactError("artifact destination must not be a symbolic link")
    if not destination.parent.is_dir():
        raise ArtifactError("artifact destination parent must be an existing directory")
    payload = dumps_artifact(artifact)
    temporary_name = ""
    try:
        with tempfile.NamedTemporaryFile(
            mode="w",
            encoding="utf-8",
            newline="\n",
            dir=str(destination.parent),
            prefix=f".{destination.name}.",
            suffix=".tmp",
            delete=False,
        ) as handle:
            temporary_name = handle.name
            handle.write(payload)
            handle.flush()
            os.fsync(handle.fileno())
        os.chmod(temporary_name, 0o644)
        os.replace(temporary_name, destination)
    except OSError as exc:
        if temporary_name:
            with suppress(OSError):
                os.unlink(temporary_name)
        raise ArtifactError(f"could not write artifact: {exc}") from exc


def load_artifact(path: Path) -> ModelArtifact:
    """Load bounded strict JSON; duplicate keys and non-finite values fail closed."""

    source = Path(path)
    try:
        if source.is_symlink() or not source.is_file():
            raise ArtifactError("artifact path must be a regular non-symbolic-link file")
        size = source.stat().st_size
        if size > MAX_ARTIFACT_BYTES:
            raise ArtifactError(f"artifact exceeds the {MAX_ARTIFACT_BYTES}-byte safety limit")
        with source.open("rb") as handle:
            payload = handle.read(MAX_ARTIFACT_BYTES + 1)
    except ArtifactError:
        raise
    except OSError as exc:
        raise ArtifactError(f"could not read artifact: {exc}") from exc
    if len(payload) > MAX_ARTIFACT_BYTES:
        raise ArtifactError(f"artifact exceeds the {MAX_ARTIFACT_BYTES}-byte safety limit")
    try:
        text = payload.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise ArtifactError("artifact must be valid UTF-8 JSON") from exc
    try:
        value = json.loads(
            text,
            object_pairs_hook=_reject_duplicate_pairs,
            parse_constant=_reject_constant,
        )
    except ArtifactError:
        raise
    except (ValueError, RecursionError) as exc:
        raise ArtifactError(f"invalid artifact JSON: {exc}") from exc
    return artifact_from_dict(value)
