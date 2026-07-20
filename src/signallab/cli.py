# ruff: noqa: UP006, UP035, UP045 -- Keep annotations importable on Python 3.9.
"""Command-line interface for deterministic SignalLab research workflows."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any, Dict, Optional, Sequence

from .artifact import load_artifact, write_artifact
from .errors import DataValidationError, SignalLabError
from .research import opinion_from_artifact
from .synthetic import generate_demo_data
from .training import train_model


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="signallab",
        description=(
            "Train a transparent benchmark-relative stock research model. "
            "Research only; not financial advice."
        ),
    )
    subcommands = parser.add_subparsers(dest="command", required=True)

    demo = subcommands.add_parser(
        "demo-data", help="generate clearly labeled deterministic synthetic OHLCV data"
    )
    demo.add_argument("output", type=Path)
    demo.add_argument("--rows", type=int, default=700)
    demo.add_argument("--seed", type=int, default=1729)
    demo.add_argument("--force", action="store_true", help="replace an existing regular file")

    train = subcommands.add_parser("train", help="train and evaluate a safe-JSON model artifact")
    train.add_argument("data", type=Path, help="long-format OHLCV CSV")
    train.add_argument("--output", type=Path, required=True, help="model JSON destination")
    train.add_argument("--benchmark", default="SPY")
    train.add_argument("--horizon-days", type=int, default=20)
    train.add_argument("--seed", type=int, default=1729)

    analyze = subcommands.add_parser(
        "analyze", help="emit a bullish/neutral/bearish research opinion as JSON"
    )
    analyze.add_argument("data", type=Path, help="the exact CSV used for training")
    analyze.add_argument("symbol")
    analyze.add_argument(
        "--artifact",
        type=Path,
        help="reuse a model JSON; otherwise train deterministically from the CSV",
    )
    analyze.add_argument("--benchmark", default="SPY")
    analyze.add_argument("--horizon-days", type=int, default=20)
    analyze.add_argument("--seed", type=int, default=1729)
    analyze.add_argument(
        "--sample-data",
        action="store_true",
        help="label this result as synthetic demonstration output",
    )
    return parser


def _emit(value: Dict[str, Any]) -> None:
    print(json.dumps(value, indent=2, sort_keys=True, allow_nan=False))


def main(argv: Optional[Sequence[str]] = None) -> int:
    """Run SignalLab and return a process status without hiding expected errors."""

    arguments = _parser().parse_args(argv)
    try:
        if arguments.command == "demo-data":
            path = generate_demo_data(
                arguments.output,
                rows=arguments.rows,
                seed=arguments.seed,
                overwrite=arguments.force,
            )
            _emit(
                {
                    "kind": "synthetic_demo_data",
                    "path": str(path),
                    "rows_per_symbol": arguments.rows,
                    "symbols": ["SYNTH_MKT", "SYNTH_A", "SYNTH_B"],
                    "warning": (
                        "Synthetic demonstration data only; it contains no real "
                        "market observations."
                    ),
                }
            )
            return 0
        if arguments.command == "train":
            artifact = train_model(
                arguments.data,
                arguments.benchmark,
                arguments.horizon_days,
                seed=arguments.seed,
            )
            write_artifact(artifact, arguments.output)
            _emit(
                {
                    "artifact": str(arguments.output),
                    "data_sha256": artifact.data_sha256,
                    "test_metrics": artifact.test_metrics.to_dict(),
                    "training_cutoff": artifact.training_cutoff,
                }
            )
            return 0
        if arguments.command == "analyze":
            if arguments.artifact:
                artifact = load_artifact(arguments.artifact)
                if artifact.benchmark != arguments.benchmark.strip().upper():
                    raise DataValidationError(
                        "artifact benchmark differs from --benchmark; use the artifact's benchmark"
                    )
                if artifact.horizon_days != arguments.horizon_days:
                    raise DataValidationError(
                        "artifact horizon differs from --horizon-days; use the artifact's horizon"
                    )
            else:
                artifact = train_model(
                    arguments.data,
                    arguments.benchmark,
                    arguments.horizon_days,
                    seed=arguments.seed,
                )
            opinion = opinion_from_artifact(
                arguments.data,
                arguments.symbol,
                artifact,
                sample_data=arguments.sample_data,
            )
            _emit(opinion.to_dict())
            return 0
        raise AssertionError("argparse accepted an unknown command")
    except SignalLabError as exc:
        print(f"signallab: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":  # pragma: no cover - exercised through the console entry point
    raise SystemExit(main())
