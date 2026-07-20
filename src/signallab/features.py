# ruff: noqa: UP006, UP035, UP045 -- Keep annotations importable on Python 3.9.
"""Point-in-time feature engineering and excess-return labels."""

from __future__ import annotations

import math
import statistics
from typing import List, Mapping, Sequence, Tuple

from .errors import DataValidationError, TrainingError
from .models import Bar, FeatureRow

FEATURE_NAMES = (
    "momentum_5",
    "momentum_20",
    "momentum_60",
    "volatility_20",
    "sma_distance_20",
    "sma_distance_60",
    "rsi_14",
    "volume_ratio_20",
    "drawdown_60",
    "benchmark_momentum_20",
    "benchmark_momentum_60",
    "relative_momentum_20",
    "relative_momentum_60",
    "beta_60",
)
MIN_LOOKBACK = 60
MIN_HORIZON = 1
MAX_HORIZON = 60


def validate_horizon(horizon_days: int) -> int:
    if isinstance(horizon_days, bool) or not isinstance(horizon_days, int):
        raise DataValidationError("horizon_days must be an integer")
    if not MIN_HORIZON <= horizon_days <= MAX_HORIZON:
        raise DataValidationError(
            f"horizon_days must be between {MIN_HORIZON} and {MAX_HORIZON} trading sessions"
        )
    return horizon_days


def _return(current: float, past: float) -> float:
    return current / past - 1.0


def _daily_returns(prices: Sequence[float], start: int, end: int) -> List[float]:
    return [_return(prices[index], prices[index - 1]) for index in range(start, end + 1)]


def _rsi(prices: Sequence[float], index: int) -> float:
    changes = [prices[pos] - prices[pos - 1] for pos in range(index - 13, index + 1)]
    gains = sum(max(value, 0.0) for value in changes) / 14.0
    losses = sum(max(-value, 0.0) for value in changes) / 14.0
    if losses <= 1e-15:
        return 0.5 if gains <= 1e-15 else 1.0
    relative_strength = gains / losses
    return (100.0 - 100.0 / (1.0 + relative_strength)) / 100.0


def _beta(stock_returns: Sequence[float], benchmark_returns: Sequence[float]) -> float:
    stock_mean = statistics.fmean(stock_returns)
    benchmark_mean = statistics.fmean(benchmark_returns)
    covariance = sum(
        (stock - stock_mean) * (market - benchmark_mean)
        for stock, market in zip(stock_returns, benchmark_returns)
    ) / len(stock_returns)
    variance = sum((market - benchmark_mean) ** 2 for market in benchmark_returns) / len(
        benchmark_returns
    )
    return covariance / variance if variance > 1e-18 else 0.0


def _feature_values(
    stock: Sequence[Bar],
    benchmark: Sequence[Bar],
    stock_prices: Sequence[float],
    benchmark_prices: Sequence[float],
    index: int,
) -> Tuple[float, ...]:
    stock_returns_20 = _daily_returns(stock_prices, index - 19, index)
    stock_returns_60 = _daily_returns(stock_prices, index - 59, index)
    benchmark_returns_60 = _daily_returns(benchmark_prices, index - 59, index)
    momentum_5 = _return(stock_prices[index], stock_prices[index - 5])
    momentum_20 = _return(stock_prices[index], stock_prices[index - 20])
    momentum_60 = _return(stock_prices[index], stock_prices[index - 60])
    benchmark_momentum_20 = _return(
        benchmark_prices[index], benchmark_prices[index - 20]
    )
    benchmark_momentum_60 = _return(
        benchmark_prices[index], benchmark_prices[index - 60]
    )
    average_volume = statistics.fmean(item.volume for item in stock[index - 20 : index])
    volume_ratio = stock[index].volume / average_volume if average_volume > 1e-12 else 1.0
    values = (
        momentum_5,
        momentum_20,
        momentum_60,
        statistics.pstdev(stock_returns_20) * math.sqrt(252.0),
        stock_prices[index] / statistics.fmean(stock_prices[index - 19 : index + 1]) - 1.0,
        stock_prices[index] / statistics.fmean(stock_prices[index - 59 : index + 1]) - 1.0,
        _rsi(stock_prices, index),
        min(volume_ratio, 100.0),
        stock_prices[index] / max(stock_prices[index - 59 : index + 1]) - 1.0,
        benchmark_momentum_20,
        benchmark_momentum_60,
        momentum_20 - benchmark_momentum_20,
        momentum_60 - benchmark_momentum_60,
        _beta(stock_returns_60, benchmark_returns_60),
    )
    if not all(math.isfinite(value) for value in values):
        raise DataValidationError(f"non-finite feature generated for {stock[index].symbol}")
    return values


def _aligned_bars(
    stock: Sequence[Bar], benchmark: Sequence[Bar]
) -> Tuple[Tuple[Bar, ...], Tuple[Bar, ...]]:
    benchmark_by_date = {item.date: item for item in benchmark}
    aligned_stock = tuple(item for item in stock if item.date in benchmark_by_date)
    aligned_benchmark = tuple(benchmark_by_date[item.date] for item in aligned_stock)
    return aligned_stock, aligned_benchmark


def build_labeled_rows(
    bars: Mapping[str, Sequence[Bar]], benchmark: str, horizon_days: int
) -> Tuple[FeatureRow, ...]:
    """Build labels using only future observations after point-in-time features."""

    horizon = validate_horizon(horizon_days)
    if benchmark not in bars:
        raise DataValidationError(f"benchmark {benchmark!r} is not present in the market data")
    rows: List[FeatureRow] = []
    for symbol in sorted(bars):
        if symbol == benchmark:
            continue
        stock, reference = _aligned_bars(bars[symbol], bars[benchmark])
        stock_prices = tuple(item.adjusted_close for item in stock)
        benchmark_prices = tuple(item.adjusted_close for item in reference)
        for index in range(MIN_LOOKBACK, len(stock) - horizon):
            values = _feature_values(
                stock, reference, stock_prices, benchmark_prices, index
            )
            stock_future = _return(
                stock[index + horizon].adjusted_close, stock[index].adjusted_close
            )
            benchmark_future = _return(
                reference[index + horizon].adjusted_close,
                reference[index].adjusted_close,
            )
            excess = stock_future - benchmark_future
            rows.append(
                FeatureRow(
                    date=stock[index].date,
                    symbol=symbol,
                    values=values,
                    label=1 if excess > 0.0 else 0,
                    future_excess_return=excess,
                    label_end_date=stock[index + horizon].date,
                )
            )
    if not rows:
        raise TrainingError("no labeled feature rows could be built from the aligned histories")
    return tuple(sorted(rows, key=lambda item: (item.date, item.symbol)))


def latest_feature_row(
    bars: Mapping[str, Sequence[Bar]], symbol: str, benchmark: str
) -> FeatureRow:
    """Return the latest fully observed point-in-time feature row without a label."""

    stock, reference = _aligned_bars(bars[symbol], bars[benchmark])
    if len(stock) <= MIN_LOOKBACK:
        raise DataValidationError(
            f"{symbol} and {benchmark} need at least {MIN_LOOKBACK + 1} aligned sessions"
        )
    index = len(stock) - 1
    stock_prices = tuple(item.adjusted_close for item in stock)
    benchmark_prices = tuple(item.adjusted_close for item in reference)
    return FeatureRow(
        date=stock[index].date,
        symbol=symbol,
        values=_feature_values(stock, reference, stock_prices, benchmark_prices, index),
        label=-1,
        future_excess_return=0.0,
        label_end_date="",
    )
