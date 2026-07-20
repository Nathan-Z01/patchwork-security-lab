# Contributing

Contributions are welcome through focused issues and pull requests.

1. Create a branch from `main`.
2. Run `make setup`.
3. Add tests for behavioral changes.
4. Run `make test lint typecheck`.
5. Explain the threat model, benchmark implication, or false-positive tradeoff
   for changes to rules and evaluators.

Security rules must include a vulnerable fixture, a safe fixture, remediation,
confidence, and a stable identifier. Benchmark changes must preserve task
reproducibility and record any migration in the task schema version.

SignalLab changes must preserve point-in-time feature construction and
chronological split purging. Include deterministic tests for leakage boundaries,
artifact validation, probability bounds, and malformed data. Compare model
changes against the recorded constant-probability baseline on a held-out test
period; do not select features, thresholds, or hyperparameters using that period.
Any schema or feature-contract change requires a version change and documented
migration. Do not add claims of guaranteed performance or personalized trading
advice.
