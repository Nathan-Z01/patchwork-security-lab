"""Run the Patchwork API and built dashboard."""

from __future__ import annotations

import argparse
import importlib
import os
from collections.abc import Sequence

from patchwork_common import __version__


def _port(value: str) -> int:
    try:
        port = int(value)
    except ValueError as exc:
        raise argparse.ArgumentTypeError("port must be an integer") from exc
    if not 1 <= port <= 65_535:
        raise argparse.ArgumentTypeError("port must be between 1 and 65535")
    return port


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="patchwork-api",
        description="Run the local Patchwork API and bundled Sentinel dashboard.",
    )
    parser.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    parser.add_argument(
        "--host",
        default=os.getenv("PATCHWORK_HOST", "127.0.0.1"),
        help="bind address (default: PATCHWORK_HOST or 127.0.0.1)",
    )
    parser.add_argument(
        "--port",
        type=_port,
        default=os.getenv("PATCHWORK_PORT", "8765"),
        help="bind port (default: PATCHWORK_PORT or 8765)",
    )
    return parser


def main(argv: Sequence[str] | None = None) -> None:
    """Start the local API server using environment-configurable bind settings."""

    arguments = build_parser().parse_args(argv)
    uvicorn = importlib.import_module("uvicorn")
    uvicorn.run(
        "patchwork_api.app:app",
        host=arguments.host,
        port=arguments.port,
        reload=False,
    )


if __name__ == "__main__":
    main()
