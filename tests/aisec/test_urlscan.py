from __future__ import annotations

import gzip
from collections.abc import Sequence

import pytest

from aisec import (
    HTTPResponse,
    ScanCompleteness,
    TargetValidationError,
    scan_url,
    validate_public_url,
)

PUBLIC_IP = "93.184.216.34"


def public_resolver(hostname: str, port: int) -> list[str]:
    del hostname, port
    return [PUBLIC_IP]


class MappingFetcher:
    def __init__(self, responses: dict[str, HTTPResponse]) -> None:
        self.responses = responses
        self.calls: list[tuple[str, Sequence[str]]] = []

    def __call__(
        self,
        url: str,
        *,
        timeout: float,
        max_bytes: int,
        resolved_ips: Sequence[str],
    ) -> HTTPResponse:
        del timeout, max_bytes
        self.calls.append((url, resolved_ips))
        return self.responses[url]


def test_url_scan_is_passive_same_origin_and_reports_surface_risks() -> None:
    home = HTTPResponse(
        "https://example.com/",
        200,
        [
            ("Content-Type", "text/html; charset=utf-8"),
            ("Access-Control-Allow-Origin", "*"),
            ("Set-Cookie", "session=secret-value; Path=/"),
        ],
        b"""
        <html><body>
          <a href="/next">Next</a>
          <a href="https://other.example/private">Other origin</a>
          <form action="http://example.com/login"><input type="password"></form>
          <script>const endpoint = "/api/chat";</script>
        </body></html>
        """,
    )
    next_page = HTTPResponse(
        "https://example.com/next",
        200,
        [
            ("Content-Type", "text/html"),
            ("Content-Security-Policy", "default-src 'self'"),
            ("X-Content-Type-Options", "nosniff"),
            ("Referrer-Policy", "strict-origin"),
            ("Permissions-Policy", "camera=()"),
            ("Strict-Transport-Security", "max-age=31536000"),
        ],
        b"<html><body>Done</body></html>",
    )
    fetcher = MappingFetcher(
        {
            "https://example.com/": home,
            "https://example.com/next": next_page,
        }
    )

    report = scan_url(
        "https://example.com",
        resolver=public_resolver,
        fetcher=fetcher,
        max_pages=4,
    )

    ids = {finding.rule_id for finding in report.findings}
    assert report.pages_scanned == 2
    assert {"AISEC301", "AISEC302", "AISEC303", "AISEC304", "AISEC305"} <= ids
    assert [call[0] for call in fetcher.calls] == [
        "https://example.com/",
        "https://example.com/next",
    ]
    assert all(tuple(addresses) == (PUBLIC_IP,) for _, addresses in fetcher.calls)
    assert "secret-value" not in str(report.to_dict())


@pytest.mark.parametrize(
    "address",
    ["127.0.0.1", "10.0.0.2", "169.254.169.254", "::1", "fc00::1"],
)
def test_private_or_local_dns_results_are_blocked_before_fetch(address: str) -> None:
    with pytest.raises(TargetValidationError, match="non-public"):
        validate_public_url(
            "https://example.com/",
            resolver=lambda hostname, port: [address],
        )


def test_all_dns_answers_must_be_public() -> None:
    with pytest.raises(TargetValidationError, match="non-public"):
        validate_public_url(
            "https://example.com/",
            resolver=lambda hostname, port: [PUBLIC_IP, "127.0.0.1"],
        )


def test_non_web_schemes_credentials_and_unapproved_ports_are_blocked() -> None:
    invalid = [
        "file:///etc/passwd",
        "https://user:password@example.com/",
        "https://example.com:8443/",
    ]
    for url in invalid:
        with pytest.raises(TargetValidationError):
            validate_public_url(url, resolver=public_resolver)


def test_cross_origin_redirect_is_not_followed() -> None:
    fetcher = MappingFetcher(
        {
            "https://example.com/": HTTPResponse(
                "https://example.com/",
                302,
                [("Location", "https://other.example/target")],
                b"",
            )
        }
    )

    report = scan_url("https://example.com/", resolver=public_resolver, fetcher=fetcher)

    assert len(fetcher.calls) == 1
    assert report.pages_scanned == 0
    assert report.completeness is ScanCompleteness.FAILED
    assert any("Cross-origin redirect" in warning for warning in report.warnings)


def test_same_host_http_to_https_redirect_is_followed_and_becomes_crawl_origin() -> None:
    fetcher = MappingFetcher(
        {
            "http://example.com/": HTTPResponse(
                "http://example.com/",
                301,
                [("Location", "https://example.com/")],
                b"",
            ),
            "https://example.com/": HTTPResponse(
                "https://example.com/",
                200,
                [("Content-Type", "text/html")],
                b'<a href="/next">Next</a>',
            ),
            "https://example.com/next": HTTPResponse(
                "https://example.com/next",
                200,
                [("Content-Type", "text/plain")],
                b"done",
            ),
        }
    )

    report = scan_url("http://example.com/", resolver=public_resolver, fetcher=fetcher)

    assert [call[0] for call in fetcher.calls] == [
        "http://example.com/",
        "https://example.com/",
        "https://example.com/next",
    ]
    assert report.pages_scanned == 2
    assert report.completeness is ScanCompleteness.COMPLETE
    assert report.metadata["effective_origin"] == ["https", "example.com", 443]


def test_https_downgrade_redirect_is_rejected() -> None:
    fetcher = MappingFetcher(
        {
            "https://example.com/": HTTPResponse(
                "https://example.com/",
                302,
                [("Location", "http://example.com/login")],
                b"",
            )
        }
    )

    report = scan_url("https://example.com/", resolver=public_resolver, fetcher=fetcher)

    assert len(fetcher.calls) == 1
    assert report.completeness is ScanCompleteness.FAILED
    assert any("downgrade" in warning for warning in report.warnings)


def test_root_fetch_failure_is_a_failed_scan() -> None:
    def failing_fetcher(
        url: str,
        *,
        timeout: float,
        max_bytes: int,
        resolved_ips: Sequence[str],
    ) -> HTTPResponse:
        del url, timeout, max_bytes, resolved_ips
        raise OSError("connection refused")

    report = scan_url(
        "https://example.com/",
        resolver=public_resolver,
        fetcher=failing_fetcher,
    )

    assert report.pages_scanned == 0
    assert report.completeness is ScanCompleteness.FAILED
    assert any("connection refused" in warning for warning in report.warnings)


def test_cross_origin_password_form_action_is_reported() -> None:
    fetcher = MappingFetcher(
        {
            "https://example.com/": HTTPResponse(
                "https://example.com/",
                200,
                [("Content-Type", "text/html")],
                b'<form method="post" action="https://login.example.net/session">'
                b'<input type="password"></form>',
            )
        }
    )

    report = scan_url("https://example.com/", resolver=public_resolver, fetcher=fetcher)

    finding = next(item for item in report.findings if item.rule_id == "AISEC303")
    assert "cross-origin" in finding.evidence
    assert finding.metadata["action"] == "https://login.example.net/session"


def test_unsupported_content_encoding_is_partial_instead_of_false_clean() -> None:
    encoded = gzip.compress(
        b'<form action="http://example.com/login"><input type="password"></form>'
        b'<script>const endpoint = "/api/chat";</script>'
    )
    fetcher = MappingFetcher(
        {
            "https://example.com/": HTTPResponse(
                "https://example.com/",
                200,
                [
                    ("Content-Type", "text/html"),
                    ("Content-Encoding", "gzip"),
                ],
                encoded,
            )
        }
    )

    report = scan_url("https://example.com/", resolver=public_resolver, fetcher=fetcher)

    assert report.pages_scanned == 1
    assert report.completeness is ScanCompleteness.PARTIAL
    assert report.skipped == 1
    assert any("unsupported Content-Encoding" in warning for warning in report.warnings)
