"""Exercise the passive URL scanner without making a network request."""

from __future__ import annotations

import sys
from collections.abc import Sequence

from aisec import HTTPResponse, json_report, scan_url


def example_resolver(hostname: str, port: int) -> list[str]:
    del hostname, port
    return ["93.184.216.34"]


def example_fetcher(
    url: str,
    *,
    timeout: float,
    max_bytes: int,
    resolved_ips: Sequence[str],
) -> HTTPResponse:
    del timeout, max_bytes, resolved_ips
    return HTTPResponse(
        url=url,
        status=200,
        headers=[("Content-Type", "text/html; charset=utf-8")],
        body=b"<html><body><p>Mock public page</p></body></html>",
    )


def main() -> int:
    report = scan_url(
        "https://example.com",
        resolver=example_resolver,
        fetcher=example_fetcher,
        max_pages=1,
        max_depth=0,
    )
    sys.stdout.write(json_report(report))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
