"""Render a local aisec source review as JSON.

Run with: PYTHONPATH=src python examples/aisec/scan_local.py [PATH]
"""

from __future__ import annotations

import sys

from aisec import json_report, scan_source


def main() -> int:
    target = sys.argv[1] if len(sys.argv) > 1 else "src"
    report = scan_source(target, max_files=5_000)
    sys.stdout.write(json_report(report))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
