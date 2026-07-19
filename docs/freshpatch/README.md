# FreshPatch

FreshPatch turns a real bug-fix commit into a reproducible code-repair task, executes a candidate patch against the buggy revision, and exports evidence suitable for review. It is intentionally small, Python 3.9-compatible, and built with the standard library.

A passing result means the configured test process exited successfully. It does **not** prove that a patch is complete, regression-free, or secure.

## What a task records

- Full buggy and fixed Git commit IDs
- Changed paths and a digest-verified reference patch
- The test process as an argument array that is never interpolated into shell text
- Timeout, working directory, and non-secret environment values
- A digest-pinned runner image and explicit isolation/resource policy
- Stable source-commit provenance and a versioned JSON schema

Task JSON is deterministic, so regenerated artifacts produce useful Git diffs.
Evaluation evidence binds the exact task value with a canonical SHA-256 digest.
Task files are public reproducibility metadata. FreshPatch rejects credential-like
environment names, recognizable private-key or token values, and environment
values containing CR or LF characters. Tasks that require secrets are
intentionally unsupported. Never place credentials in a task file.

## Quick demonstration

From the monorepo root, create the deterministic two-commit example:

```console
$ PYTHONPATH=src python3 examples/freshpatch/bootstrap_sample.py /tmp/freshpatch-sample
/tmp/freshpatch-sample/freshpatch-task.json
```

The checked-in [`sample_task.json`](../../examples/freshpatch/sample_task.json) is the expected artifact. The bootstrap script refuses to overwrite an existing destination.

Validate and normalize it. Runtime validation rejects unknown keys and reports
their exact JSON path:

```console
$ PYTHONPATH=src python3 -m freshpatch validate /tmp/freshpatch-sample/freshpatch-task.json
```

Before publishing or scoring a task, qualify it. The default runner is recorded
in the task as an immutable image digest. FreshPatch deliberately sets
`--pull never`, so acquiring that exact image is a separate, visible action:

```console
$ docker pull python:3.12-slim@sha256:57cd7c3a7a273101a6485ba99423ee568157882804b1124b4dd04266317710de
$ PYTHONPATH=src python3 -m freshpatch verify \
    --task /tmp/freshpatch-sample/freshpatch-task.json \
    --output /tmp/qualification.json
```

Qualification succeeds only when the buggy baseline fails and the recorded
reference patch passes. The JSON artifact includes both commands, statuses,
timings, output evidence, the exact effective environment, and the canonical
task SHA-256 shared by both checks. It is suitable for code review or CI
retention.

To evaluate a repair produced by a model or another tool:

```console
$ PYTHONPATH=src python3 -m freshpatch evaluate \
    --task task.json \
    --patch candidate.patch \
    --output candidate-result.json
```

Aggregate individual results, JSON arrays, JSON Lines, or earlier report files:

```console
$ PYTHONPATH=src python3 -m freshpatch report \
    baseline.json candidate-result.json \
    --format markdown \
    --output report.md
```

## Build a task from local commits

The fixed revision must descend from the buggy revision and must contain a non-empty diff:

```console
$ PYTHONPATH=src python3 -m freshpatch build \
    --repo /path/to/local/repository \
    --buggy BUGGY_COMMIT \
    --fixed FIXED_COMMIT \
    --test-command "python3 -m unittest -q" \
    --id parser-empty-input \
    --label python \
    --timeout 120 \
    --output tasks/parser-empty-input.json
```

`--test-command` uses shell-style quoting only to split text into an argument
array. Local evaluation passes that array directly to the operating system with
`shell=False`. Docker evaluation passes it as positional arguments to a fixed
FreshPatch bootstrap; task values are never interpolated into the bootstrap
script. Use `--published-source` to record a public clone URL in a distributable
artifact. Evaluation will still require an explicit trusted local `--repo`
override rather than fetching the remote source.

`build` records the default digest-pinned Python runner. For another ecosystem,
pass an immutable image with `--runner-image NAME@sha256:DIGEST`; CPU, memory,
PID, and temporary-filesystem limits can also be recorded with `--cpus`,
`--memory`, `--pids-limit`, and `--tmpfs-size`. The tmpfs size is enforced as an
independent limit on both `/tmp` and `/workspace`. Docker evaluation uses the recorded values.
Per-run overrides remain available, but the result artifact records the effective
values so deviations are visible.

## Execution safety

Docker evaluation applies these defaults:

- No network
- No Linux capabilities and `no-new-privileges`
- Read-only container root filesystem
- A read-only repository seed mounted at `/freshpatch-source`
- Separate, size-bounded tmpfs filesystems for `/workspace` and `/tmp`
- CPU, memory, process-count, and wall-clock limits
- Disabled Docker log persistence
- No implicit image pull

The task artifact records these controls and the immutable image. At container
startup, a fixed FreshPatch-owned script copies the read-only seed into the
writable `/workspace` tmpfs, changes to the recorded relative directory, and
uses `exec "$@"` to launch the exact test argument array. Patched test code can
write only the disposable in-container copy, not the prepared host workspace.
Every result records the effective values actually used, plus the controller
OS, architecture, and Python version.

Task environment values are written to a mode-`0600` file inside FreshPatch's
private temporary directory. Docker receives only that file's path in its argument
array, and the file is deleted with the temporary workspace. In particular, task
values for `PATH` or `DOCKER_HOST` cannot change the Docker client FreshPatch runs.
The `docker-command` preview uses a non-secret placeholder for this temporary path.

Inspect the bounded command shape without running it:

```console
$ PYTHONPATH=src python3 -m freshpatch docker-command \
    --task task.json \
    --workspace /absolute/prepared/workspace
```

Docker is an isolation boundary, but it is not a virtual machine. Anyone who can control the Docker daemon is highly privileged. Use a dedicated runner for hostile code and keep Docker patched.

FreshPatch performs Git reconstruction and patch application on the host before
test execution. It assumes the selected local repository is trusted; patches
are bounded to 10 MiB and applied by Git without hooks. The exact staged path
set must be a non-empty subset of `repository.changed_files`. Candidate patches
are additionally rejected when they modify common test directories, test files,
fixtures, snapshots, or test-runner configuration, even if those paths appear
in `changed_files`. This heuristic is defense in depth, not a complete semantic
proof that production code cannot influence the test oracle. The trusted
reference patch is exempt from the test-harness heuristic but remains surface
bound. Remote sources are never fetched automatically.

### Unsafe local backend

Local execution is useful for a tiny trusted fixture or a tightly controlled CI runner, but it executes repository code with the caller's host permissions. It is rejected unless the warning is acknowledged explicitly:

```console
$ PYTHONPATH=src python3 -m freshpatch evaluate \
    --task /tmp/freshpatch-sample/freshpatch-task.json \
    --reference \
    --backend local \
    --allow-unsafe-local
```

Do not use that backend for downloaded tasks, model-generated repositories, or unreviewed test commands.

The same opt-in is required for qualification of trusted local fixtures:

```console
$ PYTHONPATH=src python3 -m freshpatch verify \
    --task /tmp/freshpatch-sample/freshpatch-task.json \
    --backend local \
    --allow-unsafe-local \
    --output /tmp/qualification.json
```

Local evidence explicitly records `unsafe_local: true`, no container image,
host network/filesystem access, and the wall-clock/output limits FreshPatch did
enforce. It cannot be mistaken for an isolated Docker run.

## Result interpretation

Each result records the task ID and canonical task SHA-256, backend, effective environment and resource policy,
patch kind and SHA-256 digest, patch-application state, exact argument array,
exit code, RFC3339 start time, finite duration, and bounded stdout/stderr.
FreshPatch continuously drains process output while retaining only a bounded
tail, including during timeouts. Explicit task environment values are redacted
from durable commands and output as defense in depth. Status values are:

- `passed`: test exit code was zero
- `failed`: test process ran and returned a non-zero code
- `timeout`: the configured wall-clock limit expired
- `error`: reconstruction, patching, or process startup failed

Redaction cannot recognize transformed values or secrets obtained from repository
contents. Outputs may still contain repository secrets or personal data. Review
artifacts before publishing them.

Reports include stable task-ID-to-digest bindings and reject input evidence that
reuses one task ID for different task digests. This prevents stale results for a
previous task definition from being silently aggregated with current evidence.

## Run the offline tests

The suite needs Git and Python, but not Docker or network access:

```console
$ PYTHONPATH=src python3 -m unittest discover -s tests/freshpatch -v
```
