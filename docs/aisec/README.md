# aisec

`aisec` is a deterministic, read-only AI security checker for local source trees and small public website surfaces. It reports evidence and remediation without changing code, executing model output, submitting forms, or probing discovered API endpoints.

It is a review aid, not a penetration test or a guarantee that a target is secure.

## Quick start

```bash
# Source tree; the default terminal report is human-readable.
uv run aisec source .

# Machine-readable evidence for automation.
uv run aisec source . --format json

# Opt into a CI policy and a GitHub-compatible report.
uv run aisec source . --format sarif --output aisec.sarif --fail-on high

# Passive public-website review (bounded same-origin GET requests).
uv run aisec url https://example.com --max-pages 5 --max-depth 1 --format html -o aisec.html
```

The module form works without an installed console script:

```bash
PYTHONPATH=src python3 -m aisec source .
```

## Public Python API

```python
from aisec import scan_source, scan_url

source_report = scan_source(
    "src",
    max_files=5_000,
    max_total_bytes=50_000_000,
    max_findings=1_000,
)
website_report = scan_url("https://example.com", max_pages=5)

for finding in source_report.findings:
    print(finding.rule_id, finding.severity.value, finding.location.uri)

payload = website_report.to_dict()
```

Both entry points return `ScanReport`. A report contains structured `Finding` objects, severity counts, bounds, skipped work, warnings, and a `completeness` value of `complete`, `partial`, or `failed`. Never treat zero findings in a partial or failed report as a clean result. Text, JSON, standalone HTML, and SARIF renderers consume that same object:

```python
from aisec import html_report, json_report, sarif_report, text_report
```

## Source checks

The source scanner combines redacted regular-expression evidence with a small Python AST data-flow heuristic. It checks for:

- credential and private-key material;
- likely LLM output flowing into `eval`, `exec`, `compile`, shells, or process launchers;
- untrusted request data mixed into privileged prompts;
- executable model formats, unsafe deserialization, and remote model code;
- disabled TLS verification;
- browser HTML injection sinks; and
- permissive CORS configuration.

Directories such as `.git`, virtual environments, package vendors, build output, and `node_modules` are skipped by default. Symlinks are never followed. Source scans default to at most 10,000 files, 1 MB per file, 50 MB in aggregate, and 1,000 reported findings. Use `--max-files`, `--max-file-bytes`, `--max-total-bytes`, and `--max-findings` to tighten those limits. Reaching an aggregate byte or finding limit stops the scan deterministically and marks the report `partial`.

### Exclusions and suppressions

Use an exclusion for generated content or an intentionally vulnerable fixture:

```bash
uv run aisec source . \
  --exclude 'examples/unsafe/**' \
  --exclude 'tests/fixtures/**'
```

An automatically discovered `.aisecignore` can hold exclusions and scoped suppressions:

```text
# One relative path glob excludes matching files and directories.
examples/unsafe/**
tests/fixtures/**

# A rule by itself is disabled for this scan.
AISEC104

# A rule plus a glob is suppressed only at matching locations.
AISEC001 tests/snapshots/**
```

Negated gitignore patterns are intentionally unsupported: narrow, explicit entries are easier to audit. Use `--ignore-file PATH` to select another file. Use `--suppress AISEC104` for a command-line rule exception, or `--suppress-file PATH` for a file containing only `RULE_ID` and `RULE_ID GLOB` entries. Explicit IDs from all three sources are checked against the rule catalog; a typo fails the scan instead of silently disabling nothing. `*` remains available for an intentional all-rule suppression.

For a reviewed source line, an inline suppression applies to that line or the immediately following line:

```python
# aisec: ignore[AISEC104] -- trusted legacy artifact, digest checked above
model = torch.load(verified_path)
```

Prefer named rule IDs over bare `aisec: ignore`. Suppressions remove findings from every report format, so review them like code.

## Passive URL safety boundary

The URL scanner:

- accepts only HTTP and HTTPS on ports 80 and 443 by default;
- rejects embedded credentials, local/private/link-local/reserved/multicast addresses, and any hostname with a non-public DNS answer;
- pins the default connection to a prevalidated IP to reduce DNS-rebinding risk;
- revalidates every redirect and discovered link;
- follows redirects and links only within the approved origin, with one safe exception for a same-host HTTP-to-HTTPS upgrade;
- rejects cross-host redirects, port changes, and HTTPS-to-HTTP downgrades;
- sends bounded `GET` requests only, with no cookies, credentials, form submissions, JavaScript execution, or discovered-endpoint probes;
- caps pages, depth, redirects, response bytes, and request time; and
- does not decompress response bodies.

It inspects browser security headers, CORS response policy, cookie attributes, password-form method/transport/origin, and AI integration details present in returned markup. Only scan public websites you are authorized to access and respect their operational constraints.

For tests, inject both DNS and HTTP behavior. `HTTPResponse` preserves duplicate headers such as `Set-Cookie`:

```python
from aisec import HTTPResponse, scan_url

def resolver(hostname: str, port: int):
    return ["93.184.216.34"]

def fetcher(url: str, *, timeout: float, max_bytes: int, resolved_ips):
    return HTTPResponse(
        url=url,
        status=200,
        headers=[("Content-Type", "text/html")],
        body=b"<html><body>Example</body></html>",
    )

report = scan_url("https://example.com", resolver=resolver, fetcher=fetcher)
```

## Exit statuses

- `0`: a complete scan, or an explicitly allowed partial scan, completed and no configured finding policy failed; findings may be present.
- `1`: at least one finding met an explicitly configured `--fail-on` threshold.
- `2`: target/configuration/output error, failed scan, or a partial scan that was not explicitly allowed.

Use `--allow-partial` only when a workflow intentionally accepts incomplete coverage; failed scans still return status 2. Keeping finding policy opt-in means text, JSON, HTML, and SARIF generation behave consistently. CI can choose `--fail-on critical`, `high`, `medium`, `low`, or `info`.

## Rule catalog

Run `uv run aisec rules` for machine-readable metadata. Rule identifiers are stable within the `1.x` report schema. Findings include rule-specific impact and verification guidance, severity, confidence, category, evidence, remediation, references, location, metadata, and a deterministic partial fingerprint. Python AST taint findings also include a compact source-to-sink trace in metadata.

Secret evidence is redacted before it reaches a `Finding`; report renderers never receive the full matched value. Reports can still contain paths, source evidence, URLs, and values that automatic redaction does not recognize. Review every artifact before publishing it.
