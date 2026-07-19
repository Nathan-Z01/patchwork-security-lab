# Threat model

## Assets

- Developer source code and local filesystem data
- Credentials in the environment or repository
- Network access available to the dashboard host
- Integrity of benchmark results
- Availability of the host executing untrusted code

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

## Out of scope

- Active exploitation, fuzzing, credential testing, or authentication bypass
- Full JavaScript execution or browser sandbox analysis
- Malware detection
- Proof that a repository or website is free from vulnerabilities
- Hosting the dashboard as a multi-tenant internet service without an external
  authentication, authorization, and rate-limiting layer

## Abuse resistance

The product avoids offensive payloads and does not provide exploit generation.
Findings explain secure remediation. Network checks are request-count- and scope-bounded.
The API bounds simultaneous source and URL scans with
`PATCHWORK_MAX_CONCURRENT_SCANS` (four by default) and rejects excess work with
HTTP 429 instead of queueing it. This protects local availability but does not
replace identity-aware rate limiting at an authenticated reverse proxy.
The UI describes heuristic confidence and never presents a risk score as fact.
