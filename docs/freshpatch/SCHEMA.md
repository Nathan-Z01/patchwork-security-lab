# FreshPatch artifact schemas

FreshPatch uses explicit, independently versioned schemas. Task artifacts use
`1.1`, evaluation results use `1.2`, qualification artifacts use `1.1`, and
aggregate reports use `1.1`. Readers reject unsupported artifact versions
rather than guessing how to interpret them. The machine-readable contracts are
[`task.schema.json`](task.schema.json), [`result.schema.json`](result.schema.json),
and [`qualification.schema.json`](qualification.schema.json).

## Task

The top-level fields are:

| Field | Meaning |
| --- | --- |
| `schema_version` | Task schema version; currently `1.1` |
| `id` | Lowercase, repository-friendly stable identifier |
| `title`, `description`, `labels` | Human review context |
| `repository` | Source locator, full buggy/fixed commits, and changed paths |
| `test` | Argument array, timeout, relative working directory, and environment |
| `reference_patch` | Git diff, format, and SHA-256 content digest |
| `provenance` | Fixed commit subject/timestamp and builder version |
| `runner` | Digest-pinned image and the required Docker isolation/resource policy |

Paths in `changed_files` and `test.working_directory` must remain inside the
repository. `repository.changed_files` is also the complete allowed patch
surface: candidate and reference patches are rejected if their staged diff
contains another path. Candidate patches receive an additional defense-in-depth
check that rejects common test, fixture, snapshot, and test-runner configuration
paths even when a path was listed in `changed_files`. The trusted recorded
reference patch is exempt from that test-harness check so a source commit may
legitimately update tests, but it remains bound to `changed_files`.

A task can store a remote source for publication, but the evaluator requires a
trusted local override and does not fetch it.

`repository.changed_files` must contain at least one path. Every documented
object is closed: misspelled or unknown properties are rejected with their exact
JSON path instead of being ignored. The runner image must include an immutable
`@sha256:...` digest. Its policy fixes network isolation, a read-only root,
dropped capabilities, `no-new-privileges`, and CPU, memory, PID, and temporary
filesystem limits. `runner.policy.tmpfs_size` is applied independently to both
the writable `/workspace` copy and `/tmp`; it is not a combined quota.

`test.environment` is public, non-secret reproducibility metadata. Runtime
validation rejects credential-like names, recognizable private-key or token
values, and values containing CR or LF characters; secret-dependent tasks are
not supported.

Task artifacts are public reproducibility metadata, not a secret store. Environment
names that look credential-bearing (for example `*_TOKEN`, `*_API_KEY`,
`*_SECRET`, `*_PASSWORD`, and `*CREDENTIAL*`) and recognizable token/private-key
values are rejected. `TOKENIZERS_PARALLELISM` remains valid because `TOKENIZERS`
is not a `TOKEN` name component. Secret-dependent tasks are unsupported.

### Canonical task identity

Every result is bound to the exact task value by `task_sha256`. FreshPatch
computes this digest as SHA-256 over the UTF-8 bytes of `task.to_dict()` encoded
as JSON with keys sorted, no insignificant whitespace, and non-ASCII characters
preserved. Presentation whitespace in a task file therefore does not affect the
digest, while any task field change does.

## Evaluation result

The result schema version is `1.2`. A result contains:

| Field | Meaning |
| --- | --- |
| `task_id` | Task that was evaluated |
| `task_sha256` | Canonical SHA-256 binding to the exact task value |
| `status` | `passed`, `failed`, `timeout`, or `error` |
| `backend` | `docker` or explicitly enabled `local` |
| `duration_seconds`, `started_at` | Timing evidence |
| `environment` | Effective image, controller identity, unsafe-local marker, and actual policy |
| `patch` | Kind, SHA-256 digest, and whether application completed |
| `process` | Exact argv, exit code, and bounded output streams |

Durations must be finite and nonnegative, timestamps must be RFC3339 with a
timezone, and status/exit-code combinations must agree. A Docker result always
records a digest-pinned image and the enforced isolation policy. An explicitly
authorized local result instead records `image: null`, `unsafe_local: true`, host
network/filesystem access, and the limits that FreshPatch can still enforce.

## Qualification

`freshpatch verify` emits a qualification artifact with schema version `1.1`.
It records the task ID and canonical task SHA-256, plus two complete evaluation
results made under the same environment:

1. `baseline` checks the unpatched buggy revision and must return `failed`;
2. `reference` applies the recorded reference patch and must return `passed`.

Both nested results must match the qualification artifact's task ID and task
SHA-256. Only that exact pair produces `status: "qualified"`. A timeout,
infrastructure error, already-passing baseline, or failing reference produces a
reviewable `rejected` artifact and a nonzero CLI exit status.

The report schema version is `1.1`. It wraps a summary, stable `task_bindings`
entries, and an array of unchanged result objects. Aggregation rejects evidence
that uses one task ID with different task digests. Pass rate is `passed / total`;
infrastructure errors and timeouts are not counted as passes.
