# Changelog

All notable changes to Patchwork Security Lab are documented here.

## 0.1.0 — 2026-07-18

Initial public release.

### Sentinel and AISec

- Added bounded, read-only source and passive public-URL scanning.
- Added AI-specific data-flow, secret, unsafe loading, TLS, CORS, output-handling, cookie, form, and browser-header checks.
- Added explicit complete, partial, and failed coverage states.
- Added text, JSON, standalone HTML, and SARIF reports with rule-specific impact and verification guidance.
- Added audited exclusions, scoped suppressions, redacted secret evidence, deterministic fingerprints, and CI severity policy.
- Added an accessible responsive React dashboard and hardened loopback FastAPI adapter.

### FreshPatch

- Added deterministic repair-task construction from local Git commits.
- Added strict versioned task, result, and qualification schemas.
- Added digest-pinned Docker execution with a read-only source seed, bounded
  writable workspace and temporary filesystems, plus network, capability,
  process, CPU, memory, output, and timeout bounds.
- Added explicit trusted-local execution warnings and durable unsafe-local evidence.
- Added task qualification that proves a buggy baseline fails and the reference repair passes under the same environment.
- Added candidate evaluation restricted to recorded changed paths, with common
  test-harness paths protected even inside that surface and JSON or Markdown
  aggregation from JSON and JSON Lines inputs.

### Release engineering

- Added locked Python and npm dependencies, clean-wheel dashboard packaging, hardened container deployment, and GitHub Actions coverage across Python 3.9 and 3.12.
- Added architecture, threat-model, benchmark-methodology, contribution, security, and complete usage documentation.
