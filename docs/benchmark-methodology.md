# FreshPatch benchmark methodology

## Task construction

A task starts from a bug-fix commit pair in a public or local Git repository.
The builder verifies commit provenance, records the pre-fix commit so its tree
can be reconstructed from a trusted local repository, records the gold patch,
and stores the command used to determine correctness. The gold-patch checksum
makes silent patch mutation detectable. A canonical task SHA-256 binds each
result and qualification check to the exact complete task definition, not only
its human-readable ID. The task also records a digest-pinned runtime image and
the complete Docker resource/isolation policy.

Good tasks have a deterministic test, a focused patch, a license compatible
with redistribution, and enough issue context to understand expected behavior.
Tasks with network-dependent, flaky, destructive, or secret-dependent tests
should be excluded.

Every task should be qualified before inclusion. `freshpatch verify` reconstructs
the buggy revision twice under the same effective environment: the unpatched
baseline must fail, and the recorded reference patch must pass. Any other pair
is rejected and retained as structured evidence rather than treated as a valid
benchmark case.

## Evaluation

Candidate patches are applied to the pre-fix tree and tested under the same
resource policy. Their exact staged path set must be a non-empty subset of the
task's recorded `repository.changed_files`. Candidate changes to common test,
fixture, snapshot, golden-output, and test-runner configuration paths are
rejected even when listed in that surface. The trusted reference patch is
exempt from this test-harness heuristic, allowing tasks whose fix commit also
updated tests, but remains restricted to `changed_files`.

For Docker runs, the prepared host tree is mounted read-only as a seed. A fixed
FreshPatch bootstrap copies it into a writable `/workspace` tmpfs before
executing the test argument array; `/workspace` and `/tmp` each receive the
recorded independent tmpfs size limit. Candidate code therefore cannot mutate
the host seed and cannot grow either disposable filesystem without bound.

A result has one of four statuses:

1. `passed` — the patch applied and the test command passed;
2. `failed` — the patch applied but tests failed;
3. `timeout` — evaluation exceeded the task timeout;
4. `error` — the patch could not be applied or the runner could not establish a
   valid environment.

The default aggregate pass rate is passed tasks divided by all result artifacts.
Status counts remain available so analyses can report an eligible-task rate that
excludes evaluator errors. Reports should state which denominator they use and
may additionally include wall time and externally supplied inference cost.
Aggregation rejects results that reuse one task ID with different canonical
task digests, preventing stale task definitions from being silently combined.

## Contamination and freshness

FreshPatch records the fixed commit timestamp as its freshness signal. Recency
reduces, but cannot prove the absence of, model-training contamination. Reports
should therefore state the benchmark cutoff separately and avoid claims that a
high score measures general software-engineering ability in isolation.

## Reproducibility checklist

- Immutable repository URL and commit IDs
- Task schema and builder versions
- Canonical task SHA-256 on every result and qualification check
- Gold patch checksum
- Test command and timeout
- Candidate path surface and protected test-harness policy
- Runtime image, read-only source seed, bounded workspace, and resource policy
- Qualification artifact showing a failing baseline and passing reference
- Candidate patch checksum
- Bounded stdout/stderr tail and exit status
- Explicit treatment of timed-out and evaluator-error tasks
