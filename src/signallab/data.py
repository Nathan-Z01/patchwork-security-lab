# ruff: noqa: UP006, UP035, UP045 -- Keep annotations importable on Python 3.9.
"""Strict and bounded long-format OHLCV CSV ingestion."""

from __future__ import annotations

import csv
import hashlib
import io
import math
import re
from collections import defaultdict
from datetime import date
from pathlib import Path
from typing import DefaultDict, Dict, List, Mapping, Sequence, Tuple

from .errors import DataValidationError
from .models import Bar

REQUIRED_COLUMNS = ("date", "symbol", "open", "high", "low", "close", "volume")
OPTIONAL_COLUMNS = ("adjusted_close",)
MAX_DATA_BYTES = 64 * 1024 * 1024
MAX_DATA_ROWS = 250_000
MAX_SYMBOLS = 512
MAX_FIELD_CHARS = 256
MIN_HISTORY_ROWS = 101
_SYMBOL_RE = re.compile(r"^[A-Z0-9][A-Z0-9._-]{0,15}$")


def normalize_symbol(value: str, name: str = "symbol") -> str:
    """Normalize and validate a ticker-like identifier."""

    candidate = value.strip().upper()
    if not _SYMBOL_RE.fullmatch(candidate):
        raise DataValidationError(
            f"{name} must be 1-16 uppercase letters, numbers, dots, underscores, or hyphens"
        )
    return candidate


def _parse_date(value: str, row_number: int) -> str:
    if value != value.strip() or len(value) != 10:
        raise DataValidationError(f"row {row_number}: date must use exact YYYY-MM-DD format")
    try:
        parsed = date.fromisoformat(value)
    except ValueError as exc:
        raise DataValidationError(f"row {row_number}: invalid date {value!r}") from exc
    if parsed.isoformat() != value:
        raise DataValidationError(f"row {row_number}: date must use exact YYYY-MM-DD format")
    return value


def _parse_number(value: str, name: str, row_number: int, *, allow_zero: bool) -> float:
    if value == "" or value != value.strip() or len(value) > 64:
        raise DataValidationError(f"row {row_number}: {name} must be a plain finite number")
    try:
        number = float(value)
    except ValueError as exc:
        raise DataValidationError(f"row {row_number}: {name} must be a finite number") from exc
    if not math.isfinite(number):
        raise DataValidationError(f"row {row_number}: {name} must be finite")
    if number < 0 or (number == 0 and not allow_zero):
        qualifier = "non-negative" if allow_zero else "positive"
        raise DataValidationError(f"row {row_number}: {name} must be {qualifier}")
    return number


def _read_bounded(path: Path, max_bytes: int) -> bytes:
    try:
        if path.is_symlink():
            raise DataValidationError("market data must be a regular file, not a symbolic link")
        stat = path.stat()
    except OSError as exc:
        raise DataValidationError(f"cannot read market data: {exc}") from exc
    if not path.is_file():
        raise DataValidationError("market data path must be a regular file")
    if stat.st_size > max_bytes:
        raise DataValidationError(f"market data exceeds the {max_bytes}-byte safety limit")
    try:
        with path.open("rb") as handle:
            payload = handle.read(max_bytes + 1)
    except OSError as exc:
        raise DataValidationError(f"cannot read market data: {exc}") from exc
    if len(payload) > max_bytes:
        raise DataValidationError(f"market data exceeds the {max_bytes}-byte safety limit")
    if not payload:
        raise DataValidationError("market data file is empty")
    return payload


def load_market_csv(
    path: Path,
    *,
    max_bytes: int = MAX_DATA_BYTES,
    max_rows: int = MAX_DATA_ROWS,
) -> Tuple[Dict[str, Tuple[Bar, ...]], str, bool]:
    """Load a strict long-format OHLCV file and return grouped bars plus its digest."""

    if max_bytes < 1 or max_rows < 1:
        raise ValueError("safety limits must be positive")
    payload = _read_bounded(Path(path), max_bytes)
    digest = hashlib.sha256(payload).hexdigest()
    try:
        text = payload.decode("utf-8-sig")
    except UnicodeDecodeError as exc:
        raise DataValidationError("market data must be valid UTF-8") from exc
    if "\x00" in text:
        raise DataValidationError("market data must not contain NUL bytes")

    try:
        reader = csv.DictReader(io.StringIO(text, newline=""), strict=True)
        header = reader.fieldnames
        if header is None:
            raise DataValidationError("market data is missing a CSV header")
        if len(header) != len(set(header)):
            raise DataValidationError("CSV header contains duplicate columns")
        expected = set(REQUIRED_COLUMNS)
        actual = set(header)
        missing = sorted(expected.difference(actual))
        unknown = sorted(actual.difference(expected.union(OPTIONAL_COLUMNS)))
        if missing:
            raise DataValidationError(f"CSV header is missing required column {missing[0]!r}")
        if unknown:
            raise DataValidationError(f"CSV header contains unsupported column {unknown[0]!r}")

        has_adjusted = "adjusted_close" in actual
        grouped: DefaultDict[str, List[Bar]] = defaultdict(list)
        seen = set()
        for row_count, row in enumerate(reader, start=1):
            row_number = row_count + 1
            if row_count > max_rows:
                raise DataValidationError(f"market data exceeds the {max_rows}-row safety limit")
            if None in row:
                raise DataValidationError(f"row {row_number}: contains extra CSV fields")
            if any(value is None for value in row.values()):
                raise DataValidationError(f"row {row_number}: contains missing CSV fields")
            if any(len(value or "") > MAX_FIELD_CHARS for value in row.values()):
                raise DataValidationError(f"row {row_number}: a field exceeds the length limit")

            day = _parse_date(row["date"], row_number)
            symbol = normalize_symbol(row["symbol"], f"row {row_number} symbol")
            if row["symbol"] != symbol:
                raise DataValidationError(
                    f"row {row_number}: symbol must already be normalized uppercase"
                )
            key = (day, symbol)
            if key in seen:
                raise DataValidationError(f"row {row_number}: duplicate date/symbol observation")
            seen.add(key)

            open_price = _parse_number(row["open"], "open", row_number, allow_zero=False)
            high = _parse_number(row["high"], "high", row_number, allow_zero=False)
            low = _parse_number(row["low"], "low", row_number, allow_zero=False)
            close = _parse_number(row["close"], "close", row_number, allow_zero=False)
            volume = _parse_number(row["volume"], "volume", row_number, allow_zero=True)
            adjusted = (
                _parse_number(
                    row["adjusted_close"], "adjusted_close", row_number, allow_zero=False
                )
                if has_adjusted
                else close
            )
            if high < max(open_price, low, close) or low > min(open_price, high, close):
                raise DataValidationError(
                    f"row {row_number}: OHLC values violate low <= open/close <= high"
                )
            grouped[symbol].append(
                Bar(day, symbol, open_price, high, low, close, volume, adjusted)
            )
    except csv.Error as exc:
        raise DataValidationError(f"malformed CSV: {exc}") from exc

    if not grouped:
        raise DataValidationError("market data contains no observations")
    if len(grouped) > MAX_SYMBOLS:
        raise DataValidationError(f"market data exceeds the {MAX_SYMBOLS}-symbol safety limit")

    result: Dict[str, Tuple[Bar, ...]] = {}
    for symbol, values in grouped.items():
        ordered = sorted(values, key=lambda item: item.date)
        if len(ordered) < MIN_HISTORY_ROWS:
            raise DataValidationError(
                f"symbol {symbol} has {len(ordered)} rows; at least {MIN_HISTORY_ROWS} are required"
            )
        result[symbol] = tuple(ordered)
    return result, digest, has_adjusted


def require_symbols(
    bars: Mapping[str, Sequence[Bar]], symbol: str, benchmark: str
) -> Tuple[str, str]:
    """Validate requested symbols and prove both occur in the loaded dataset."""

    target = normalize_symbol(symbol)
    reference = normalize_symbol(benchmark, "benchmark")
    if target == reference:
        raise DataValidationError("symbol and benchmark must differ")
    if target not in bars:
        raise DataValidationError(f"symbol {target!r} is not present in the market data")
    if reference not in bars:
        raise DataValidationError(f"benchmark {reference!r} is not present in the market data")
    return target, reference
