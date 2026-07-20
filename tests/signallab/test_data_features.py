from __future__ import annotations

import csv
from dataclasses import replace
from pathlib import Path

import pytest

from signallab.data import load_market_csv
from signallab.errors import DataValidationError
from signallab.features import FEATURE_NAMES, build_labeled_rows


def _write(path: Path, text: str) -> None:
    path.write_text(text, encoding="utf-8")


def test_loads_strict_long_format_and_prefers_adjusted_close(demo_csv: Path) -> None:
    bars, digest, uses_adjusted = load_market_csv(demo_csv)

    assert set(bars) == {"SYNTH_A", "SYNTH_B", "SYNTH_MKT"}
    assert len(digest) == 64
    assert uses_adjusted is True
    assert bars["SYNTH_A"][0].adjusted_close == bars["SYNTH_A"][0].close


def test_adjusted_close_is_optional_but_disclosed(demo_csv: Path, tmp_path: Path) -> None:
    destination = tmp_path / "raw-close.csv"
    with demo_csv.open(newline="", encoding="utf-8") as source, destination.open(
        "w", newline="", encoding="utf-8"
    ) as output:
        reader = csv.DictReader(source)
        writer = csv.DictWriter(
            output,
            fieldnames=[name for name in reader.fieldnames or [] if name != "adjusted_close"],
            lineterminator="\n",
        )
        writer.writeheader()
        for row in reader:
            row.pop("adjusted_close")
            writer.writerow(row)

    bars, _, uses_adjusted = load_market_csv(destination)
    assert uses_adjusted is False
    assert bars["SYNTH_A"][0].adjusted_close == bars["SYNTH_A"][0].close


@pytest.mark.parametrize(
    "header,row,error",
    [
        (
            "date,symbol,open,high,low,close,volume,unknown\n",
            "2024-01-02,SYNTH_A,10,11,9,10,100,wat\n",
            "unsupported column",
        ),
        (
            "date,symbol,open,high,low,close,volume\n",
            "2024-01-02,synth_a,10,11,9,10,100\n",
            "normalized uppercase",
        ),
        (
            "date,symbol,open,high,low,close,volume\n",
            "2024-01-02,SYNTH_A,10,9,8,10,100\n",
            "OHLC values",
        ),
        (
            "date,symbol,open,high,low,close,volume\n",
            "2024-01-02,SYNTH_A,10,11,9,nan,100\n",
            "finite",
        ),
    ],
)
def test_rejects_malformed_rows(
    tmp_path: Path, header: str, row: str, error: str
) -> None:
    path = tmp_path / "bad.csv"
    _write(path, header + row)
    with pytest.raises(DataValidationError, match=error):
        load_market_csv(path)


def test_rejects_duplicate_observations(tmp_path: Path) -> None:
    path = tmp_path / "duplicate.csv"
    row = "2024-01-02,SYNTH_A,10,11,9,10,100\n"
    _write(path, "date,symbol,open,high,low,close,volume\n" + row + row)
    with pytest.raises(DataValidationError, match="duplicate date/symbol"):
        load_market_csv(path)


def test_enforces_byte_and_row_bounds(demo_csv: Path) -> None:
    with pytest.raises(DataValidationError, match="byte safety limit"):
        load_market_csv(demo_csv, max_bytes=100)
    with pytest.raises(DataValidationError, match="row safety limit"):
        load_market_csv(demo_csv, max_rows=10)


def test_rejects_symlink(demo_csv: Path, tmp_path: Path) -> None:
    link = tmp_path / "linked.csv"
    link.symlink_to(demo_csv)
    with pytest.raises(DataValidationError, match="symbolic link"):
        load_market_csv(link)


def test_feature_contract_and_future_label_do_not_leak(demo_csv: Path) -> None:
    bars, _, _ = load_market_csv(demo_csv)
    original = build_labeled_rows(bars, "SYNTH_MKT", 20)
    target = next(item for item in original if item.symbol == "SYNTH_A")
    changed_histories = dict(bars)
    changed = list(changed_histories["SYNTH_A"])
    future_index = next(
        index for index, bar in enumerate(changed) if bar.date == target.label_end_date
    )
    changed[future_index] = replace(
        changed[future_index], adjusted_close=changed[future_index].adjusted_close * 10.0
    )
    changed_histories["SYNTH_A"] = tuple(changed)
    revised = build_labeled_rows(changed_histories, "SYNTH_MKT", 20)
    revised_target = next(
        item
        for item in revised
        if item.symbol == target.symbol and item.date == target.date
    )

    assert len(target.values) == len(FEATURE_NAMES) == 14
    assert revised_target.values == target.values
    assert revised_target.future_excess_return != target.future_excess_return
