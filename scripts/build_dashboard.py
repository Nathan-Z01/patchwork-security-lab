#!/usr/bin/env python3
"""Build the Vite dashboard and synchronize it into the Python package.

The checked-in package copy makes wheels self-contained. Run this script after
dashboard changes so ``patchwork-api`` serves the same UI from source, wheels,
and containers.
"""

from __future__ import annotations

import argparse
import shutil
import subprocess  # noqa: S404 - arguments are fixed and never use a shell
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[1]
DASHBOARD_DIR = PROJECT_ROOT / "apps" / "dashboard"
VITE_DIST = DASHBOARD_DIR / "dist"
PACKAGE_DIST = PROJECT_ROOT / "src" / "patchwork_api" / "dashboard"


def _run(command: list[str]) -> None:
    subprocess.run(command, cwd=PROJECT_ROOT, check=True)  # noqa: S603


def _validate_dist() -> None:
    index = VITE_DIST / "index.html"
    assets = VITE_DIST / "assets"
    if not index.is_file() or not assets.is_dir() or not any(assets.iterdir()):
        raise SystemExit(
            "Dashboard build output is incomplete. Expected index.html and populated assets/."
        )


def _sync_dist() -> None:
    _validate_dist()
    staging = PACKAGE_DIST.with_name(f".{PACKAGE_DIST.name}.staging")
    if staging.exists():
        shutil.rmtree(staging)
    shutil.copytree(VITE_DIST, staging)
    if PACKAGE_DIST.exists():
        shutil.rmtree(PACKAGE_DIST)
    staging.replace(PACKAGE_DIST)


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Build and package the Patchwork dashboard static assets."
    )
    parser.add_argument(
        "--skip-install",
        action="store_true",
        help="Reuse the existing node_modules instead of running npm ci.",
    )
    parser.add_argument(
        "--sync-only",
        action="store_true",
        help="Only copy an existing apps/dashboard/dist build into the package.",
    )
    args = parser.parse_args()

    if not args.sync_only:
        if not args.skip_install:
            _run(["npm", "--prefix", str(DASHBOARD_DIR), "ci"])
        _run(["npm", "--prefix", str(DASHBOARD_DIR), "run", "build"])
    _sync_dist()
    print(f"Dashboard assets synchronized to {PACKAGE_DIST.relative_to(PROJECT_ROOT)}")


if __name__ == "__main__":
    main()
