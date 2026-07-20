# Changelog

All notable changes to Patchwork Security Lab are documented here.

## 0.2.0 — 2026-07-19

### SignalLab

- Added strict, bounded long-format OHLCV ingestion and point-in-time technical,
  relative-momentum, volatility, volume, drawdown, and beta features.
- Added a deterministic, dependency-free ensemble of regularized logistic
  regression and gradient-boosted decision stumps for predicting forward excess
  performance relative to a benchmark.
- Added purged chronological train, validation, and held-out test periods,
  validation-only blending and calibration, constant-baseline comparison, and
  accuracy, balanced-accuracy, Brier-score, ROC-AUC, and horizon-aware effective
  window evidence.
- Added strict versioned JSON model artifacts with data digests, feature schema,
  training cutoff, split provenance, model parameters, and evaluation metrics.
- Added a SignalLab CLI, local API endpoints, deterministic synthetic demo, and
  accessible dashboard workspace with factor explanations and explicit model
  limitations.
- Added defensive limits for data files and artifacts, finite-number validation,
  non-executable serialization, and research-only disclosures throughout the
  interface and documentation.

### Product integration

- Added a top-level dashboard workspace switch while preserving the existing
  Sentinel source and public-website review flows.
- Extended Python 3.9/3.12, dashboard, wheel, and container checks to cover the
  model and its packaged interface.

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
