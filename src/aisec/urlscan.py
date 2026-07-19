# ruff: noqa: E501, UP006, UP030, UP035, UP045 -- Retain Python 3.9 typing and evidence prose.
"""Passive public-URL review with strict SSRF and crawl boundaries."""

from __future__ import annotations

import http.client
import ipaddress
import re
import socket
import ssl
from collections import deque
from collections.abc import Iterable, Mapping, Sequence
from dataclasses import dataclass
from html.parser import HTMLParser
from typing import (
    Callable,
    Deque,
    Dict,
    List,
    Optional,
    Set,
    Tuple,
    Union,
)
from urllib.parse import urljoin, urlsplit, urlunsplit

from patchwork_common import __version__

from .models import Confidence, Finding, Location, ScanReport, Severity
from .rules import get_rule
from .suppressions import Suppressions, coerce_suppressions


class TargetValidationError(ValueError):
    """Raised before a URL that is unsafe or out of policy can be fetched."""


HeaderInput = Union[Mapping[str, object], Sequence[Tuple[str, str]]]
Resolver = Callable[[str, int], Iterable[str]]


@dataclass(frozen=True)
class HTTPResponse:
    """Small fetcher-independent response used by the passive scanner."""

    url: str
    status: int
    headers: HeaderInput
    body: bytes
    truncated: bool = False

    def header_values(self, name: str) -> List[str]:
        expected = name.lower()
        values: List[str] = []
        items = self.headers.items() if isinstance(self.headers, Mapping) else self.headers
        for key, raw_value in items:
            if str(key).lower() != expected:
                continue
            if isinstance(raw_value, (list, tuple)):
                values.extend(str(value) for value in raw_value)
            else:
                values.append(str(raw_value))
        return values

    def header(self, name: str, default: str = "") -> str:
        values = self.header_values(name)
        return values[-1] if values else default


@dataclass(frozen=True)
class ValidatedURL:
    url: str
    scheme: str
    hostname: str
    port: int
    resolved_ips: Tuple[str, ...]

    @property
    def origin(self) -> Tuple[str, str, int]:
        return (self.scheme, self.hostname, self.port)


def default_resolver(hostname: str, port: int) -> Iterable[str]:
    """Resolve all stream addresses so every candidate can be policy checked."""

    addresses: Set[str] = set()
    for item in socket.getaddrinfo(hostname, port, type=socket.SOCK_STREAM):
        addresses.add(str(item[4][0]))
    return sorted(addresses, key=lambda value: (":" in value, value))


def _is_public_ip(value: str) -> bool:
    try:
        address = ipaddress.ip_address(value.split("%", 1)[0])
    except ValueError:
        return False
    if isinstance(address, ipaddress.IPv6Address) and address.ipv4_mapped:
        address = address.ipv4_mapped
    return bool(address.is_global)


def validate_public_url(
    url: str,
    *,
    resolver: Resolver = default_resolver,
    allowed_ports: Iterable[int] = (80, 443),
) -> ValidatedURL:
    """Normalize a URL and reject private, local, ambiguous, or non-web targets."""

    if not isinstance(url, str) or not url.strip():
        raise TargetValidationError("URL must be a non-empty string")
    if any(ord(character) < 32 for character in url):
        raise TargetValidationError("URL contains control characters")
    parsed = urlsplit(url.strip())
    scheme = parsed.scheme.lower()
    if scheme not in {"http", "https"}:
        raise TargetValidationError("only http and https URLs are allowed")
    if parsed.username is not None or parsed.password is not None:
        raise TargetValidationError("URLs containing credentials are not allowed")
    if not parsed.hostname:
        raise TargetValidationError("URL must include a hostname")
    if "%" in parsed.hostname:
        raise TargetValidationError("IPv6 zone identifiers are not allowed")
    try:
        hostname = parsed.hostname.rstrip(".").encode("idna").decode("ascii").lower()
    except UnicodeError as exc:
        raise TargetValidationError("hostname is not valid IDNA") from exc
    try:
        port = parsed.port or (443 if scheme == "https" else 80)
    except ValueError as exc:
        raise TargetValidationError("URL port is invalid") from exc
    allowed = {int(candidate) for candidate in allowed_ports}
    if port not in allowed:
        raise TargetValidationError(
            "port {0} is not allowed; permitted ports: {1}".format(
                port, ", ".join(str(item) for item in sorted(allowed))
            )
        )
    try:
        addresses = tuple(dict.fromkeys(str(item) for item in resolver(hostname, port)))
    except (OSError, socket.gaierror) as exc:
        raise TargetValidationError("hostname could not be resolved") from exc
    if not addresses:
        raise TargetValidationError("hostname did not resolve to an address")
    blocked = [address for address in addresses if not _is_public_ip(address)]
    if blocked:
        raise TargetValidationError("hostname resolves to a non-public address; request blocked")
    default_port = 443 if scheme == "https" else 80
    display_host = f"[{hostname}]" if ":" in hostname else hostname
    netloc = display_host if port == default_port else f"{display_host}:{port}"
    normalized = urlunsplit((scheme, netloc, parsed.path or "/", parsed.query, ""))
    return ValidatedURL(normalized, scheme, hostname, port, addresses)


def _response_headers(message: http.client.HTTPMessage) -> List[Tuple[str, str]]:
    return [(str(key), str(value)) for key, value in message.items()]


def default_fetcher(
    url: str,
    *,
    timeout: float,
    max_bytes: int,
    resolved_ips: Sequence[str],
) -> HTTPResponse:
    """Fetch one validated URL while pinning the connection to its checked IP.

    Redirects are deliberately not followed here; the scanner validates each
    redirect target separately before another request is made.
    """

    parsed = urlsplit(url)
    hostname = parsed.hostname or ""
    port = parsed.port or (443 if parsed.scheme == "https" else 80)
    if not resolved_ips:
        raise TargetValidationError("fetcher requires a pre-validated address")
    connect_ip = sorted(resolved_ips, key=lambda value: (":" in value, value))[0]
    raw_socket = socket.create_connection((connect_ip, port), timeout=timeout)
    connection: Optional[http.client.HTTPConnection] = None
    try:
        if parsed.scheme == "https":
            context = ssl.create_default_context()
            wrapped = context.wrap_socket(raw_socket, server_hostname=hostname)
            connection = http.client.HTTPSConnection(
                hostname, port=port, timeout=timeout, context=context
            )
            connection.sock = wrapped
        else:
            connection = http.client.HTTPConnection(hostname, port=port, timeout=timeout)
            connection.sock = raw_socket
        target = urlunsplit(("", "", parsed.path or "/", parsed.query, ""))
        default_port = 443 if parsed.scheme == "https" else 80
        display_host = f"[{hostname}]" if ":" in hostname else hostname
        host_header = display_host if port == default_port else f"{display_host}:{port}"
        connection.request(
            "GET",
            target,
            headers={
                "Host": host_header,
                "User-Agent": f"aisec-passive-scanner/{__version__} (+read-only)",
                "Accept": "text/html,application/xhtml+xml;q=0.9,*/*;q=0.1",
                "Accept-Encoding": "identity",
                "Connection": "close",
            },
        )
        response = connection.getresponse()
        body = response.read(max_bytes + 1)
        truncated = len(body) > max_bytes
        if truncated:
            body = body[:max_bytes]
        return HTTPResponse(
            url=url,
            status=response.status,
            headers=_response_headers(response.headers),
            body=body,
            truncated=truncated,
        )
    finally:
        try:
            if connection is not None:
                connection.close()
            else:
                raw_socket.close()
        except OSError:
            raw_socket.close()


def _decode_body(response: HTTPResponse) -> str:
    content_type = response.header("content-type")
    match = re.search(r"charset\s*=\s*[\"']?([^;\s\"']+)", content_type, re.I)
    charset = match.group(1) if match else "utf-8"
    try:
        return response.body.decode(charset, "replace")
    except LookupError:
        return response.body.decode("utf-8", "replace")


def _is_html(response: HTTPResponse) -> bool:
    content_type = response.header("content-type").lower()
    return "text/html" in content_type or "application/xhtml+xml" in content_type


def _url_origin(url: str) -> Optional[Tuple[str, str, int]]:
    """Return a normalized web origin without resolving or fetching it."""

    parsed = urlsplit(url)
    scheme = parsed.scheme.lower()
    hostname = (parsed.hostname or "").rstrip(".").lower()
    if scheme not in {"http", "https"} or not hostname:
        return None
    try:
        port = parsed.port or (443 if scheme == "https" else 80)
    except ValueError:
        return None
    return (scheme, hostname, port)


_AI_ENDPOINT = re.compile(
    r"(?i)(?:https://api\.(?:openai|anthropic)\.com/[^\"'\s<]*|"
    r"/(?:api|v1)/(?:chat|generate|completion|completions|agent|agents|llm|ai)"
    r"(?:[/\w?=&.-]*))"
)
_EXPOSED_PROMPT = re.compile(r"(?i)\b(?:system|developer|privileged)[_-]?prompt\b\s*[:=]")
_WEB_SECRET = re.compile(
    r"\bsk-(?:proj-)?[A-Za-z0-9_-]{12,}\b|"
    r"\b(?:api[_-]?key|client[_-]?secret)\b\s*[:=]\s*[\"'][^\"']{8,}[\"']",
    re.I,
)


def _safe_web_evidence(value: str, limit: int = 200) -> str:
    compact = " ".join(value.strip().split())
    compact = re.sub(
        r"\bsk-(?:proj-)?[A-Za-z0-9_-]{12,}\b",
        "<redacted-token>",
        compact,
    )
    compact = re.sub(
        r"(?i)(\b(?:api[_-]?key|client[_-]?secret)\b\s*[:=]\s*[\"'])"
        r"[^\"']+([\"'])",
        r"\1<redacted>\2",
        compact,
    )
    return compact if len(compact) <= limit else compact[: limit - 1] + "…"


class _SurfaceParser(HTMLParser):
    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.links: List[str] = []
        self.forms: List[Dict[str, object]] = []
        self.ai_exposures: List[str] = []
        self._form: Optional[Dict[str, object]] = None

    def _inspect_values(self, values: Iterable[str]) -> None:
        for value in values:
            if _AI_ENDPOINT.search(value) or _WEB_SECRET.search(value):
                self.ai_exposures.append(_safe_web_evidence(value))

    def handle_starttag(self, tag: str, attrs: List[Tuple[str, Optional[str]]]) -> None:
        attributes = {key.lower(): value or "" for key, value in attrs}
        values = list(attributes.values())
        self._inspect_values(values)
        if tag.lower() == "a" and attributes.get("href"):
            self.links.append(attributes["href"])
        elif tag.lower() == "form":
            if self._form is not None:
                self.forms.append(self._form)
            self._form = {
                "action": attributes.get("action", ""),
                "method": attributes.get("method", "get").lower(),
                "has_password": False,
                "line": self.getpos()[0],
            }
        elif (
            tag.lower() == "input"
            and self._form is not None
            and attributes.get("type", "text").lower() == "password"
        ):
            self._form["has_password"] = True

    def handle_endtag(self, tag: str) -> None:
        if tag.lower() == "form" and self._form is not None:
            self.forms.append(self._form)
            self._form = None

    def handle_data(self, data: str) -> None:
        if _EXPOSED_PROMPT.search(data) or _WEB_SECRET.search(data) or _AI_ENDPOINT.search(data):
            self.ai_exposures.append(_safe_web_evidence(data))

    def close(self) -> None:
        super().close()
        if self._form is not None:
            self.forms.append(self._form)
            self._form = None


class URLScanner:
    """Crawl a small same-origin surface using passive GET requests only."""

    def __init__(
        self,
        *,
        suppressions: Optional[Suppressions] = None,
        resolver: Resolver = default_resolver,
        fetcher: Callable[..., HTTPResponse] = default_fetcher,
        max_pages: int = 8,
        max_depth: int = 1,
        max_redirects: int = 3,
        max_response_bytes: int = 1_000_000,
        timeout: float = 8.0,
        allowed_ports: Iterable[int] = (80, 443),
    ) -> None:
        if not 1 <= max_pages <= 50:
            raise ValueError("max_pages must be between 1 and 50")
        if not 0 <= max_depth <= 3:
            raise ValueError("max_depth must be between 0 and 3")
        if not 0 <= max_redirects <= 5:
            raise ValueError("max_redirects must be between 0 and 5")
        if not 1 <= max_response_bytes <= 5_000_000:
            raise ValueError("max_response_bytes must be between 1 and 5000000")
        if not 0.1 <= timeout <= 30:
            raise ValueError("timeout must be between 0.1 and 30 seconds")
        self.suppressions = suppressions or Suppressions()
        self.resolver = resolver
        self.fetcher = fetcher
        self.max_pages = max_pages
        self.max_depth = max_depth
        self.max_redirects = max_redirects
        self.max_response_bytes = max_response_bytes
        self.timeout = timeout
        self.allowed_ports = tuple(allowed_ports)

    def _validate(self, url: str) -> ValidatedURL:
        return validate_public_url(url, resolver=self.resolver, allowed_ports=self.allowed_ports)

    def _finding(
        self,
        report: ScanReport,
        rule_id: str,
        url: str,
        evidence: str,
        *,
        severity: Optional[Severity] = None,
        confidence: Optional[Confidence] = None,
        metadata: Optional[Dict[str, object]] = None,
        line: Optional[int] = None,
    ) -> None:
        if self.suppressions.is_suppressed(rule_id, url, line):
            return
        report.findings.append(
            Finding.from_rule(
                get_rule(rule_id),
                Location(url, line),
                _safe_web_evidence(evidence),
                severity=severity,
                confidence=confidence,
                metadata=metadata,
            )
        )

    def _fetch_redirects(
        self, start: ValidatedURL, root_hostname: str
    ) -> Tuple[Optional[HTTPResponse], ValidatedURL, List[str]]:
        current = start
        warnings: List[str] = []
        for redirect_number in range(self.max_redirects + 1):
            response = self.fetcher(
                current.url,
                timeout=self.timeout,
                max_bytes=self.max_response_bytes,
                resolved_ips=current.resolved_ips,
            )
            if response.status not in {301, 302, 303, 307, 308}:
                return response, current, warnings
            location = response.header("location")
            if not location:
                warnings.append(f"Redirect response at {current.url} had no Location header.")
                return response, current, warnings
            if redirect_number >= self.max_redirects:
                warnings.append(f"Redirect limit reached at {current.url}.")
                return None, current, warnings
            candidate = self._validate(urljoin(current.url, location))
            if candidate.hostname != root_hostname:
                warnings.append(f"Cross-origin redirect was not followed: {candidate.url}.")
                return None, current, warnings
            if current.scheme == "https" and candidate.scheme == "http":
                warnings.append(f"HTTPS downgrade redirect was not followed: {candidate.url}.")
                return None, current, warnings
            safe_upgrade = (
                current.scheme == "http"
                and current.port == 80
                and candidate.scheme == "https"
                and candidate.port == 443
            )
            if candidate.origin != current.origin and not safe_upgrade:
                warnings.append(f"Cross-origin redirect was not followed: {candidate.url}.")
                return None, current, warnings
            current = candidate
        return None, current, warnings

    def _analyze_headers(
        self, report: ScanReport, response: HTTPResponse, page: ValidatedURL
    ) -> None:
        if _is_html(response):
            required = [
                "Content-Security-Policy",
                "X-Content-Type-Options",
                "Referrer-Policy",
                "Permissions-Policy",
            ]
            if page.scheme == "https":
                required.append("Strict-Transport-Security")
            for header in required:
                if not response.header(header):
                    self._finding(
                        report,
                        "AISEC301",
                        page.url,
                        f"Missing response header: {header}",
                        metadata={"header": header, "status": response.status},
                    )
        allow_origin = response.header("Access-Control-Allow-Origin").strip()
        allow_credentials = response.header("Access-Control-Allow-Credentials").strip().lower()
        if allow_origin == "*":
            severity = Severity.CRITICAL if allow_credentials == "true" else Severity.HIGH
            self._finding(
                report,
                "AISEC305",
                page.url,
                "Access-Control-Allow-Origin: *{0}".format(
                    " with credentials enabled" if allow_credentials == "true" else ""
                ),
                severity=severity,
                metadata={
                    "allow_origin": "*",
                    "allow_credentials": allow_credentials == "true",
                },
            )
        for raw_cookie in response.header_values("Set-Cookie"):
            first = raw_cookie.split(";", 1)[0]
            name = first.split("=", 1)[0].strip() or "unnamed"
            lowered = raw_cookie.lower()
            issues: List[str] = []
            if page.scheme == "https" and "; secure" not in lowered:
                issues.append("Secure")
            if re.search(r"(?i)(session|auth|token|sid|jwt)", name) and "; httponly" not in lowered:
                issues.append("HttpOnly")
            if "; samesite=" not in lowered:
                issues.append("SameSite")
            if "samesite=none" in lowered and "; secure" not in lowered and "Secure" not in issues:
                issues.append("Secure")
            if issues:
                self._finding(
                    report,
                    "AISEC302",
                    page.url,
                    "Cookie '{0}' is missing: {1}".format(name[:80], ", ".join(issues)),
                    metadata={"cookie_name": name[:80], "missing_attributes": issues},
                )

    def _analyze_html(
        self, report: ScanReport, response: HTTPResponse, page: ValidatedURL
    ) -> List[str]:
        text = _decode_body(response)
        parser = _SurfaceParser()
        try:
            parser.feed(text)
            parser.close()
        except Exception as exc:  # HTMLParser must not make a scan fatal.
            report.warnings.append(f"Markup parsing was incomplete for {page.url}: {exc}")
        for form in parser.forms:
            if not form.get("has_password"):
                continue
            action = urljoin(page.url, str(form.get("action") or page.url))
            issues = []
            if str(form.get("method", "get")).lower() == "get":
                issues.append("method is GET")
            if urlsplit(action).scheme.lower() != "https":
                issues.append("action is not HTTPS")
            if _url_origin(action) != page.origin:
                issues.append("action is cross-origin")
            if issues:
                raw_line = form.get("line")
                self._finding(
                    report,
                    "AISEC303",
                    page.url,
                    "Password form: {0}".format("; ".join(issues)),
                    metadata={
                        "method": form.get("method"),
                        "action": action,
                    },
                    line=raw_line if isinstance(raw_line, int) else None,
                )
        if parser.ai_exposures:
            unique = list(dict.fromkeys(parser.ai_exposures))[:5]
            self._finding(
                report,
                "AISEC304",
                page.url,
                "Public markup contains: {0}".format(" | ".join(unique)),
                metadata={"signals": len(parser.ai_exposures)},
            )
        return parser.links

    def scan(self, url: str) -> ScanReport:
        initial = self._validate(url)
        report = ScanReport(initial.url, "url")
        report.metadata.update(
            {
                "mode": "passive",
                "http_methods": ["GET"],
                "same_origin_only": True,
                "max_pages": self.max_pages,
                "max_depth": self.max_depth,
                "max_response_bytes": self.max_response_bytes,
            }
        )
        root_origin = initial.origin
        crawl_origin = root_origin
        queue: Deque[Tuple[ValidatedURL, int]] = deque([(initial, 0)])
        queued: Set[str] = {initial.url}
        visited: Set[str] = set()
        while queue and report.pages_scanned < self.max_pages:
            candidate, depth = queue.popleft()
            if candidate.url in visited:
                continue
            visited.add(candidate.url)
            is_root = candidate.url == initial.url and depth == 0
            try:
                response, final_page, warnings = self._fetch_redirects(candidate, initial.hostname)
                report.warnings.extend(warnings)
            except (OSError, http.client.HTTPException, ssl.SSLError, TargetValidationError) as exc:
                report.warnings.append(f"Could not fetch {candidate.url}: {exc}")
                report.skipped += 1
                if is_root and report.pages_scanned == 0:
                    report.mark_failed()
                else:
                    report.mark_partial()
                continue
            if response is None:
                report.skipped += 1
                if is_root and report.pages_scanned == 0:
                    report.mark_failed()
                else:
                    report.mark_partial()
                continue
            report.pages_scanned += 1
            if crawl_origin[0] == "http" and final_page.scheme == "https":
                crawl_origin = final_page.origin
                report.metadata["effective_origin"] = list(crawl_origin)
            if response.truncated:
                report.warnings.append(
                    f"Response body was truncated at {self.max_response_bytes} bytes for {final_page.url}."
                )
            self._analyze_headers(report, response, final_page)
            links: List[str] = []
            content_encoding = response.header("Content-Encoding").strip().lower()
            if content_encoding and content_encoding != "identity":
                report.warnings.append(
                    f"Skipped encoded response body for {final_page.url}: "
                    f"unsupported Content-Encoding {content_encoding!r}."
                )
                report.skipped += 1
                report.mark_partial()
            elif _is_html(response):
                links = self._analyze_html(report, response, final_page)
            if depth >= self.max_depth:
                continue
            for href in links:
                if len(queue) + len(visited) >= self.max_pages * 4:
                    break
                try:
                    linked = self._validate(urljoin(final_page.url, href))
                except TargetValidationError:
                    continue
                if linked.origin != crawl_origin or linked.url in queued:
                    continue
                queued.add(linked.url)
                queue.append((linked, depth + 1))
        if queue:
            report.warnings.append(
                f"Stopped after max_pages={self.max_pages}; discovered pages were not scanned."
            )
            report.mark_partial()
        unique: Dict[str, Finding] = {}
        for finding in report.findings:
            unique[finding.fingerprint] = finding
        report.findings = list(unique.values())
        return report.finish()


def scan_url(
    url: str,
    *,
    suppressions: Optional[Suppressions] = None,
    suppressed_rules: Optional[Iterable[str]] = None,
    suppression_file: Optional[str] = None,
    resolver: Resolver = default_resolver,
    fetcher: Callable[..., HTTPResponse] = default_fetcher,
    max_pages: int = 8,
    max_depth: int = 1,
    max_redirects: int = 3,
    max_response_bytes: int = 1_000_000,
    timeout: float = 8.0,
    allowed_ports: Iterable[int] = (80, 443),
) -> ScanReport:
    """Passively scan a bounded, same-origin public website surface."""

    policy = coerce_suppressions(suppressions, suppressed_rules, suppression_file)
    return URLScanner(
        suppressions=policy,
        resolver=resolver,
        fetcher=fetcher,
        max_pages=max_pages,
        max_depth=max_depth,
        max_redirects=max_redirects,
        max_response_bytes=max_response_bytes,
        timeout=timeout,
        allowed_ports=allowed_ports,
    ).scan(url)
