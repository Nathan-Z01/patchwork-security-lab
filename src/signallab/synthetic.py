# ruff: noqa: UP006, UP035, UP045 -- Keep annotations importable on Python 3.9.
"""Deterministic synthetic OHLCV generation for demos and tests only."""

from __future__ import annotations

import csv
import math
import os
import random
import tempfile
from contextlib import suppress
from datetime import date, timedelta
from pathlib import Path
from typing import Dict, List

from .errors import DataValidationError


def _business_dates(start: date, count: int) -> List[date]:
    result: List[date] = []
    current = start
    while len(result) < count:
        if current.weekday() < 5:
            result.append(current)
        current += timedelta(days=1)
    return result


def generate_demo_data(
    path: Path,
    *,
    rows: int = 700,
    seed: int = 1729,
    overwrite: bool = False,
) -> Path:
    """Write clearly synthetic, deterministic long-format OHLCV demo data."""

    if isinstance(rows, bool) or not isinstance(rows, int) or not 260 <= rows <= 5_000:
        raise DataValidationError("demo rows must be an integer between 260 and 5000")
    if isinstance(seed, bool) or not isinstance(seed, int) or not 0 <= seed <= 2**31 - 1:
        raise DataValidationError("seed must be an integer between 0 and 2147483647")
    destination = Path(path)
    if destination.exists() and not overwrite:
        raise DataValidationError("demo output already exists; pass overwrite=True to replace it")
    if destination.exists() and destination.is_symlink():
        raise DataValidationError("demo output must not be a symbolic link")
    if not destination.parent.is_dir():
        raise DataValidationError("demo output parent must be an existing directory")

    generator = random.Random(seed)  # noqa: S311 - deterministic simulation, not security.
    dates = _business_dates(date(2020, 1, 2), rows)
    prices: Dict[str, float] = {
        "SYNTH_MKT": 300.0,
        "SYNTH_A": 95.0,
        "SYNTH_B": 55.0,
    }
    output_rows = []
    for index, day in enumerate(dates):
        slow_regime = 0.0018 * math.sin(2.0 * math.pi * index / 126.0)
        medium_regime = 0.0007 * math.sin(2.0 * math.pi * index / 47.0)
        benchmark_return = (
            0.00025
            + 0.00025 * math.sin(2.0 * math.pi * index / 180.0)
            + generator.gauss(0.0, 0.004)
        )
        daily_returns = {
            "SYNTH_MKT": benchmark_return,
            "SYNTH_A": benchmark_return
            + slow_regime
            + medium_regime
            + generator.gauss(0.0, 0.0018),
            "SYNTH_B": benchmark_return
            + 0.75 * slow_regime
            + 0.5 * medium_regime
            + generator.gauss(0.0, 0.0022),
        }
        for symbol in ("SYNTH_MKT", "SYNTH_A", "SYNTH_B"):
            previous = prices[symbol]
            close = previous * max(0.8, 1.0 + daily_returns[symbol])
            overnight = generator.gauss(0.0, 0.0015)
            open_price = previous * (1.0 + overnight)
            spread = 0.0015 + abs(generator.gauss(0.0, 0.0012))
            high = max(open_price, close) * (1.0 + spread)
            low = min(open_price, close) * (1.0 - spread)
            regime_activity = 1.0 + min(1.5, abs(slow_regime) * 350.0)
            volume = int(
                (1_200_000 if symbol == "SYNTH_MKT" else 650_000)
                * regime_activity
                * (0.9 + 0.2 * generator.random())
            )
            prices[symbol] = close
            output_rows.append(
                (
                    day.isoformat(),
                    symbol,
                    f"{open_price:.6f}",
                    f"{high:.6f}",
                    f"{low:.6f}",
                    f"{close:.6f}",
                    str(volume),
                    f"{close:.6f}",
                )
            )

    temporary_name = ""
    try:
        with tempfile.NamedTemporaryFile(
            mode="w",
            encoding="utf-8",
            newline="",
            dir=str(destination.parent),
            prefix=f".{destination.name}.",
            suffix=".tmp",
            delete=False,
        ) as handle:
            temporary_name = handle.name
            writer = csv.writer(handle, lineterminator="\n")
            writer.writerow(
                ("date", "symbol", "open", "high", "low", "close", "volume", "adjusted_close")
            )
            writer.writerows(output_rows)
            handle.flush()
            os.fsync(handle.fileno())
        os.chmod(temporary_name, 0o644)
        os.replace(temporary_name, destination)
    except OSError as exc:
        if temporary_name:
            with suppress(OSError):
                os.unlink(temporary_name)
        raise DataValidationError(f"could not write synthetic demo data: {exc}") from exc
    return destination
