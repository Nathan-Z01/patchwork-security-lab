# Patchwork Security Lab

[![CI](https://github.com/Nathan-Z01/patchwork-security-lab/actions/workflows/ci.yml/badge.svg)](https://github.com/Nathan-Z01/patchwork-security-lab/actions/workflows/ci.yml)
[![License: MIT](https://img.shields.io/badge/License-MIT-0f172a.svg)](LICENSE)

Reproducible code-repair benchmarks and evidence-first AI security scanning,
packaged as one portfolio-grade open-source monorepo.

Patchwork contains two independent tools:

- **FreshPatch** turns real bug-fix commits into versioned, executable repair
  tasks and evaluates candidate patches inside constrained containers.
- **AI Security Checker** scans source repositories and public website surfaces
  for AI-specific security mistakes, unsafe data flows, exposed secrets, and
  missing browser defenses. It exports JSON, HTML, and GitHub-compatible SARIF.

The project is defensive by design. URL checks are passive and bounded; private
network targets are rejected. Findings include evidence, confidence, impact,
and remediation rather than an opaque score.

## Quick start

Requirements: Git, GNU Make, Python 3.9+, [uv](https://docs.astral.sh/uv/),
Node 20.19+ or 22.12+ with npm, and Docker for isolated FreshPatch execution
or the containerized dashboard.

```bash
git clone https://github.com/Nathan-Z01/patchwork-security-lab.git
cd patchwork-security-lab
make setup
make test
make dev
```

Open `http://127.0.0.1:8765`. The server binds to loopback by default.
Run `uv run patchwork-api --help` to see the server CLI and its bind options.

For installation, dashboard, CLI, API, FreshPatch, Docker, CI, and
troubleshooting instructions, see the **[complete user guide](docs/USER_GUIDE.md)**.
If `make` reports `getcwd: Operation not permitted` or cannot find the `dev`
target, start with the guide's [troubleshooting section](docs/USER_GUIDE.md#8-troubleshooting).

Run the scanners directly:

```bash
uv run aisec source .
uv run aisec source . --format json
uv run aisec source . --format sarif --output reports/local/self-scan.sarif
uv run aisec url https://example.com --format html --output reports/local/example.html
uv run freshpatch --help
```

Build and validate the deterministic offline repair fixture:

```bash
uv run python examples/freshpatch/bootstrap_sample.py /tmp/freshpatch-sample
uv run freshpatch validate /tmp/freshpatch-sample/freshpatch-task.json
uv run freshpatch verify --task /tmp/freshpatch-sample/freshpatch-task.json \
  --backend local --allow-unsafe-local --output /tmp/qualification.json
```

Choose a sample destination that does not already exist; the bootstrap script
refuses to overwrite one.

See the [FreshPatch walkthrough](docs/freshpatch/README.md) for container and
trusted-local evaluation examples.

## Why this is not another AI wrapper

The technical work is inspectable and testable:

- AST-assisted source-to-sink analysis detects model output reaching dangerous
  execution APIs.
- A suppression format, stable rule identifiers, confidence levels, and SARIF
  output make findings usable in engineering workflows.
- Aggregate byte and finding ceilings make incomplete source coverage explicit.
- Public URL scanning enforces DNS/IP safety at every fetch and never performs
  exploitation or payload injection.
- FreshPatch records commit provenance, a reference-patch checksum, a
  digest-pinned runner, versioned schemas, tests, and effective execution policy.
- Task qualification proves the buggy baseline fails and the recorded repair
  passes before a benchmark case is admitted.
- Candidate patches may change only the task's recorded `changed_files`, and
  common test, fixture, snapshot, and test-runner configuration paths remain
  protected even if the reference commit changed them.
- The benchmark runner produces machine-readable results and distinguishes
  failed tests from evaluator errors and timeouts.

## Repository map

```text
apps/dashboard/       React + TypeScript review interface
src/aisec/            Source and passive URL security scanner
src/freshpatch/       Repair-task builder and evaluator
src/patchwork_api/    Local FastAPI service
examples/             Safe demonstration fixtures
tests/                Python and API test suites
docs/                 Architecture, methodology, and threat model
```

## Safety and authorization

Only scan systems you own or are authorized to assess. AI Security Checker is a
review assistant, not a penetration test or a guarantee of safety. See
[SECURITY.md](SECURITY.md) and [the threat model](docs/threat-model.md).

FreshPatch treats benchmark repositories as untrusted. Its default execution
backend requires Docker and applies network, capability, process, CPU, and
memory restrictions. Docker seeds a bounded writable workspace from a read-only
prepared source mount; the recorded `tmpfs_size` independently bounds both the
workspace and `/tmp`. The local backend is deliberately marked unsafe and must
be enabled explicitly.

Reports and benchmark logs can contain paths, source evidence, URLs, or
repository output. Secret matches are redacted, but redaction cannot recognize
every sensitive or transformed value; review artifacts before publishing them.

## Evaluation philosophy

Every rule needs a vulnerable fixture and a safe fixture. Every benchmark task
must be reconstructable from recorded inputs. Reports preserve scanner version,
timestamp, target metadata, rule identifiers, and evidence so results can be
reviewed and compared without relying on screenshots.

See [FreshPatch methodology](docs/benchmark-methodology.md) for the task and
result model.

## Development

```bash
make test
make lint
make typecheck
make scan-self
```

Contributions should describe their false-positive or reproducibility tradeoff.
See [CONTRIBUTING.md](CONTRIBUTING.md).

## License

MIT
