# Threat model

## Assets

- Developer source code and local filesystem data
- Credentials in the environment or repository
- Network access available to the dashboard host
- Integrity of benchmark results
- Availability of the host executing untrusted code
- Integrity and provenance of market data, trained model artifacts, and reported
  holdout evidence

## Trust boundaries

### Public URL input

A submitted URL is untrusted. The scanner accepts only HTTP(S), resolves the
hostname, rejects non-public IP ranges, revalidates redirects, limits response
bytes and page count, and uses passive GET requests. DNS rebinding remains a
consideration; resolution is checked for each request and redirects never
inherit trust from an earlier destination.

### Local source paths

Dashboard requests may reference only paths beneath `PATCHWORK_WORKSPACE_ROOT`.
Resolved paths are checked after symlink resolution. CLI users already possess
local filesystem access, but traversal remains bounded and ignores VCS,
dependency, cache, and build directories by default.

### Benchmark repositories

Repositories and candidate patches may execute attacker-controlled code through
their test commands. Docker is the safe default: no network, no added
capabilities, no new privileges, bounded PIDs/CPU/memory, and an ephemeral
filesystem. Tasks require a digest-pinned image, and results record the effective
policy. The explicitly authorized local backend has host access and records that
fact in its evidence; it is only for trusted fixtures and development. Containers
reduce risk but are not a perfect security boundary;
run hostile workloads on a disposable VM for stronger isolation.

### Market-data CSV and model artifacts

A submitted market-data path is untrusted and must resolve beneath
`PATCHWORK_WORKSPACE_ROOT`. SignalLab accepts only a bounded UTF-8 regular CSV
file. The API resolves symlinks before enforcing the workspace boundary, while
the core reader rejects a direct symbolic-link input. It validates an exact
column contract, caps bytes, rows, symbols, and field lengths, and rejects
duplicate observations, invalid OHLC relationships, and non-finite numbers.
Model training is CPU-bound, so API requests share the concurrency limiter and
are rejected when capacity is exhausted rather than queued without bound.

SignalLab model files use a strict, size-bounded JSON schema. The loader rejects
unknown structure, non-finite constants, incompatible schema or feature
versions, invalid dimensions, and out-of-range parameters. It never loads
pickle, joblib, or another executable serialization format.

Artifacts are not cryptographically signed. Strict validation prevents an
artifact from executing code but cannot authenticate who created it or prove
that user-editable metrics and parameters were produced from the claimed data
digest. CLI users should load only artifacts they trained or independently
reviewed; accepting third-party artifacts as trustworthy is out of scope.

These controls do not prove that the underlying prices are accurate. Malicious,
stale, cherry-picked, survivorship-biased, or incorrectly adjusted observations
can produce misleading models while remaining syntactically valid. The data
digest and cutoff make the input auditable; users remain responsible for data
licensing, corporate-action handling, provenance, and validation.

## Out of scope

- Active exploitation, fuzzing, credential testing, or authentication bypass
- Full JavaScript execution or browser sandbox analysis
- Malware detection
- Proof that a repository or website is free from vulnerabilities
- Hosting the dashboard as a multi-tenant internet service without an external
  authentication, authorization, and rate-limiting layer
- Real-time trading, brokerage execution, portfolio optimization, personalized
  suitability analysis, or a claim that a stock will rise or outperform
- Detecting every form of market-data poisoning, regime change, survivorship
  bias, look-ahead bias in upstream data, or distribution shift

## Abuse resistance

The product avoids offensive payloads and does not provide exploit generation.
Findings explain secure remediation. Network checks are request-count- and scope-bounded.
The API bounds simultaneous source scans, URL scans, and stock analyses with
`PATCHWORK_MAX_CONCURRENT_SCANS` (four by default) and rejects excess work with
HTTP 429 instead of queueing it. This protects local availability but does not
replace identity-aware rate limiting at an authenticated reverse proxy.
The UI describes heuristic confidence and never presents a risk score as fact.
SignalLab never presents a guaranteed outcome or an instruction to buy or sell;
it pairs each opinion with the horizon, benchmark, test-period metrics,
limitations, and a research-only disclaimer. That disclosure does not turn a
model into financial advice or make it suitable for a user's circumstances.
