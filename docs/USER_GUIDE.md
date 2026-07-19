# Patchwork Security Lab user guide

Patchwork Security Lab contains two tools in one repository:

- **Sentinel / `aisec`** reviews source code and bounded public website responses for AI and web-security risks.
- **FreshPatch / `freshpatch`** creates, qualifies, and evaluates reproducible code-repair benchmark tasks.

The dashboard is a local interface for Sentinel. Both command-line tools work independently of the dashboard.

## 1. Install the project

### Requirements

- Git
- GNU Make
- Python 3.9 or newer
- [`uv`](https://docs.astral.sh/uv/)
- Node.js 20.19+, 22.12+, or newer, with npm
- Docker only for isolated FreshPatch execution or the containerized dashboard

The commands below target macOS, Linux, or WSL. On native Windows, use WSL or
translate the shell and virtual-environment path syntax. Node.js is needed for
the dashboard, not for the standard-library CLIs. Without installing the
project, inspect their module forms with:

```bash
PYTHONPATH=src python3 -m aisec --help
PYTHONPATH=src python3 -m freshpatch --help
```

Clone the repository and enter its root directory:

```bash
git clone https://github.com/Nathan-Z01/patchwork-security-lab.git
cd patchwork-security-lab
```

Confirm that you are in the right directory. `Makefile`, `pyproject.toml`, and `apps/` should be present:

```bash
pwd
ls Makefile pyproject.toml
make doctor
```

Install the locked Python and JavaScript dependencies:

```bash
make setup
```

The first setup requires network access to download the locked dependencies.
After setup, the local CLIs and deterministic FreshPatch fixture can run
offline; public-URL scans still require network access to their target.

Run the complete local test suite if you want to verify the checkout:

```bash
make test
```

## 2. Use the Sentinel dashboard

Start the local API and bundled dashboard from the repository root:

```bash
make dev
```

Open [http://127.0.0.1:8765](http://127.0.0.1:8765). Stop the server with `Ctrl-C`.
The equivalent server entry point documents its bind options with:

```bash
uv run patchwork-api --help
```

The server binds to loopback by default. The source path in the dashboard is a path on the machine running the API, not a path uploaded by the browser. A relative path such as `.` is resolved beneath `PATCHWORK_WORKSPACE_ROOT`. By default, that root is the directory where the server starts.

To review another local project while running Patchwork from this checkout:

```bash
PATCHWORK_WORKSPACE_ROOT="/absolute/path/to/project" make dev
```

Then leave the dashboard source field as `.` or enter a path below that root. Paths that escape the configured root are rejected.

The dashboard offers three useful flows:

1. **Load sample** displays clearly labeled demonstration evidence without scanning anything.
2. **Source repository** reviews a server-local file or directory.
3. **Public website** performs passive, bounded HTTP checks against an authorized public site.

Results are ordered by severity. Select a finding to review its location, evidence, likely impact, remediation, and a verification step. JSON and SARIF export buttons preserve the result for review or automation. The API retains only the latest 100 scans in memory; restarting the server clears that list, so export evidence you need to keep.

Exports can contain absolute paths, source evidence, URLs, or repository data.
Secret matches are redacted, but redaction cannot recognize every sensitive or
transformed value. Review reports and benchmark logs before uploading or
publishing them.

### Dashboard configuration

The available environment variables are:

| Variable | Default | Purpose |
| --- | --- | --- |
| `PATCHWORK_WORKSPACE_ROOT` | current directory | Highest directory the dashboard may scan |
| `PATCHWORK_HOST` | `127.0.0.1` | API bind address |
| `PATCHWORK_PORT` | `8765` | API and dashboard port |
| `PATCHWORK_MAX_CONCURRENT_SCANS` | `4` | Concurrent source/URL scan limit, clamped to 1–32 |
| `PATCHWORK_CORS_ORIGINS` | local Vite origins | Comma-separated development origins |

Configuration is read from the process environment. `.env.example` is a
reference file and neither Make nor `patchwork-api` loads `.env` automatically.
Export a value or prefix the launch command, as in the workspace example above.

Patchwork is designed as a local tool. Do not expose it as an unauthenticated internet service. A remote deployment needs an authenticated reverse proxy, authorization, request limits, TLS, and an intentionally scoped workspace.

## 3. Scan source code with `aisec`

Run a human-readable review:

```bash
uv run aisec source /absolute/path/to/project
```

The scanner is read-only. It skips common VCS, dependency, cache, virtual-environment, and build directories, does not follow symlinks, and applies file-count, per-file, aggregate-byte, and finding limits.

Export other formats:

```bash
uv run aisec source . --format json --output reports/local/scan.json
uv run aisec source . --format html --output reports/local/scan.html
uv run aisec source . --format sarif --output reports/local/scan.sarif
```

Use an explicit severity policy in CI:

```bash
uv run aisec source . \
  --format sarif \
  --output reports/local/scan.sarif \
  --fail-on high
```

`--fail-on high` returns status 1 for high or critical findings. Without `--fail-on`, findings are reported but do not by themselves make the command fail.

### Understand coverage and exit status

Every report has one of three coverage states:

- `complete`: the requested work finished within its bounds;
- `partial`: a bound or recoverable acquisition problem left some work unchecked;
- `failed`: the target could not be meaningfully checked.

Zero findings are not a clean bill of health, especially for partial or failed scans.

The CLI exit statuses are:

- `0`: a complete scan, or an explicitly allowed partial scan, finished and no configured finding policy failed;
- `1`: a finding met the explicit `--fail-on` threshold;
- `2`: invalid input, output failure, failed scan, or a partial scan that was not explicitly allowed.

`--allow-partial` accepts status `partial` for a workflow that deliberately tolerates incomplete coverage. It never converts a failed scan into success.

### Tune scan bounds

```bash
uv run aisec source . \
  --max-files 5000 \
  --max-file-bytes 750000 \
  --max-total-bytes 25000000 \
  --max-findings 500
```

Use narrower values for a fast pre-commit check and larger values only when the target requires them. A reached aggregate-byte or finding limit is recorded and produces partial coverage.

### Exclude generated files and suppress reviewed findings

Repeat `--exclude` for generated paths:

```bash
uv run aisec source . \
  --exclude 'generated/**' \
  --exclude 'tests/fixtures/**'
```

For a version-controlled policy, add `.aisecignore` at the scan root:

```text
# Exclude a path.
generated/**

# Suppress one rule everywhere.
AISEC104

# Suppress one rule only in a reviewed fixture.
AISEC001 tests/fixtures/**
```

Rule IDs are validated; a typo fails rather than silently changing policy. Negated ignore patterns are not supported. Inline source suppressions apply to the annotated line or the immediately following line:

```python
# aisec: ignore[AISEC104] -- trusted artifact; digest verified above
model = torch.load(verified_path)
```

Prefer narrow, documented suppressions and review them like code. List the rule catalog with:

```bash
uv run aisec rules
```

## 4. Review a public website

Only scan a site you own or are authorized to assess:

```bash
uv run aisec url https://example.com
uv run aisec url https://example.com \
  --max-pages 5 \
  --max-depth 1 \
  --format html \
  --output reports/local/example.html
```

The URL scanner sends bounded `GET` requests only. It does not submit forms, execute page JavaScript, send cookies, attempt authentication, inject payloads, or probe discovered APIs. It blocks embedded credentials, non-public addresses, unsafe ports, cross-host redirects, HTTPS downgrades, and private DNS answers. A same-host HTTP-to-HTTPS upgrade is the only cross-origin redirect exception.

The review covers observable browser-security headers, CORS response policy, cookie flags, password-form transport/origin, and AI-integration details present in returned HTML. It is not a penetration test.

## 5. Build and evaluate FreshPatch tasks

FreshPatch expects a local Git repository with a known buggy commit and a descendant fixed commit. It never fetches the repository recorded in a task.

### Build a task

```bash
uv run freshpatch build \
  --repo /absolute/path/to/repository \
  --buggy BUGGY_COMMIT \
  --fixed FIXED_COMMIT \
  --test-command "python3 -m unittest -q" \
  --id parser-empty-input \
  --title "Repair empty parser input" \
  --label python \
  --timeout 120 \
  --published-source https://github.com/example/project \
  --output tasks/parser-empty-input.json
```

The task records full commit IDs, changed paths, a checksum-protected reference patch, the test command as an argument array, an immutable runner image, and the isolation/resource policy. Task environment variables must not contain credentials.

Validate the artifact before using it:

```bash
uv run freshpatch validate tasks/parser-empty-input.json
```

`validate` does not modify the task. It writes normalized JSON to standard
output; redirect that output if you want to save a normalized copy.

### Qualify a task

Qualification runs the same test in two states and admits the task only when the buggy baseline fails and the recorded reference repair passes.

The default Docker runner is digest-pinned and never pulled implicitly. Pull the exact image recorded in the task, then verify:

```bash
docker pull python:3.12-slim@sha256:57cd7c3a7a273101a6485ba99423ee568157882804b1124b4dd04266317710de

uv run freshpatch verify \
  --task tasks/parser-empty-input.json \
  --repo /absolute/path/to/repository \
  --output qualifications/parser-empty-input.json
```

The qualification artifact records both outcomes, timings, output evidence, and the exact effective environment.

### Evaluate a candidate patch

Create a standard Git diff between the task's buggy revision and the candidate
revision, then evaluate it against the buggy revision:

```bash
git -C /absolute/path/to/repository \
  diff --binary BUGGY_COMMIT..CANDIDATE_COMMIT -- \
  > candidate.patch

uv run freshpatch evaluate \
  --task tasks/parser-empty-input.json \
  --repo /absolute/path/to/repository \
  --patch candidate.patch \
  --output results/parser-empty-input-candidate.json
```

Use `--reference` instead of `--patch` to evaluate the recorded repair. Result statuses are `passed`, `failed`, `timeout`, or `error`; they distinguish test failure from evaluator failure. Passing only means the configured test process exited successfully.

Candidate diffs may modify only paths recorded in
`repository.changed_files`. FreshPatch rejects additions, deletions, renames,
or edits outside that surface before running tests. Candidate patches also may
not modify common test, fixture, snapshot, or test-runner configuration paths,
even if the reference commit changed one; the trusted reference patch alone is
exempt from that additional heuristic. Docker receives the prepared source as
a read-only seed, copies it into a size-bounded `tmpfs` workspace, and executes
the task argument array there. The task's recorded `tmpfs_size` (128 MiB by
default) applies independently to `/workspace` and `/tmp`. Repository checkout,
patch validation, and preparation still happen on the host, so use only a
trusted local repository as the source override.

FreshPatch command exit statuses are:

- `evaluate`: `0` passed, `1` produced a failed/timeout/error result, and `2` rejected input or configuration before producing a result;
- `verify`: `0` qualified, `1` rejected, and `2` indicates invalid task/configuration or CLI I/O failure; and
- `build`, `validate`, `docker-command`, and `report`: `0` on success and `2` for a usage or domain error.

Aggregate one or more result artifacts:

```bash
uv run freshpatch report results/*-candidate.json \
  --format markdown \
  --output results/report.md
```

### Trusted local demonstration

The repository includes a deterministic offline fixture. Choose a destination
that does not already exist; the bootstrap script refuses to overwrite one:

```bash
uv run python examples/freshpatch/bootstrap_sample.py /tmp/freshpatch-sample
uv run freshpatch validate /tmp/freshpatch-sample/freshpatch-task.json
uv run freshpatch verify \
  --task /tmp/freshpatch-sample/freshpatch-task.json \
  --backend local \
  --allow-unsafe-local \
  --output /tmp/freshpatch-qualification.json
```

The local backend executes repository code with your host permissions. Use it only for code you trust. Docker is the default for unreviewed repositories or candidate patches; a disposable VM is stronger isolation for hostile workloads.

## 6. Run the dashboard with Docker

Build and start the hardened local container:

```bash
docker compose up --build
```

Open [http://127.0.0.1:8765](http://127.0.0.1:8765). The Compose service mounts the Patchwork checkout read-only at `/workspace`, drops Linux capabilities, enables `no-new-privileges`, uses a read-only root filesystem, and provides a bounded temporary directory. The supplied Compose file can scan only that mounted checkout.

To scan another project, build the image and mount that project as the
read-only workspace while preserving the container controls:

```bash
docker build --tag patchwork-security-lab .
docker run --rm \
  --read-only \
  --tmpfs /tmp:rw,size=64m,noexec,nosuid,nodev \
  --cap-drop ALL \
  --security-opt no-new-privileges:true \
  --pids-limit 256 \
  --cpus 1 \
  --memory 1g \
  --volume "/absolute/path/to/project:/workspace:ro" \
  --publish 127.0.0.1:8765:8000 \
  patchwork-security-lab
```

Then enter `.` in the source field. This container runs the Sentinel dashboard;
FreshPatch launches its own per-evaluation Docker container and policy.

Stop it with `Ctrl-C`, or run `docker compose down` if it was started in the background.

## 7. Use the API directly

Interactive OpenAPI documentation is available at [http://127.0.0.1:8765/docs](http://127.0.0.1:8765/docs) while the server is running.

Examples:

```bash
curl --fail http://127.0.0.1:8765/api/health

curl --fail \
  --header 'Content-Type: application/json' \
  --data '{"path":".","max_files":5000}' \
  http://127.0.0.1:8765/api/scans/source

curl --fail \
  --header 'Content-Type: application/json' \
  --data '{"url":"https://example.com","timeout_seconds":10}' \
  http://127.0.0.1:8765/api/scans/url
```

Fetch a stored result or export by scan ID:

```bash
curl --fail http://127.0.0.1:8765/api/scans/SCAN_ID
curl --fail --output scan.sarif \
  http://127.0.0.1:8765/api/scans/SCAN_ID/export/sarif
```

## 8. Troubleshooting

### `make: getcwd: Operation not permitted`

The shell's current directory is unavailable. This commonly happens after a directory is moved/deleted or when the terminal lacks permission to access a protected folder. Move to a known readable directory, then enter the clone again:

```bash
cd "$HOME"
cd "/absolute/path/to/patchwork-security-lab"
pwd
ls Makefile
```

On macOS, if the clone is in Desktop, Documents, or another protected folder, allow your terminal application to access that folder in **System Settings → Privacy & Security**, or move the clone to a developer directory you can read. `pwd` must work before `make` can work.

### `make: No rule to make target 'dev'`

You are not in this repository's root, or the checkout is incomplete. Confirm:

```bash
pwd
ls Makefile pyproject.toml apps
make help
```

If `Makefile` is absent, `cd` into the cloned `patchwork-security-lab` directory. Do not run `make dev` from `apps/dashboard`; that directory contains only the frontend package.

After moving to any readable directory, you can also name the checkout
explicitly:

```bash
make -C "/absolute/path/to/patchwork-security-lab" doctor
make -C "/absolute/path/to/patchwork-security-lab" dev
```

### Development environment is missing

Run:

```bash
make setup
make doctor
make dev
```

### Port 8765 is already in use

Choose another loopback port:

```bash
PATCHWORK_PORT=8766 make dev
```

Then open `http://127.0.0.1:8766`.

### Dashboard changes are not visible

Rebuild and synchronize the packaged assets, then restart the server:

```bash
make web-build
make dev
```

### A source path is rejected by the dashboard

The resolved path must be beneath `PATCHWORK_WORKSPACE_ROOT`. Stop the server, set that root to the project you intend to review, and restart it. Symlink escapes are rejected after resolution.

### A public URL is rejected

Loopback, private, link-local, reserved, multicast, credential-bearing, or otherwise non-public destinations are blocked intentionally. Use the source scanner for a local application. Do not weaken the URL boundary to reach internal services.

### FreshPatch says the runner image is unavailable

FreshPatch uses Docker with `--pull never`. Pull the exact digest recorded under `runner.image` in the task. Do not replace the digest with a mutable tag if you need reproducible evidence.

### A scan exits with status 2

Read the terminal error and the report's `completeness`, `warnings`, and bounds. Correct invalid input, narrow the target, or deliberately adjust the relevant limit. Use `--allow-partial` only when your workflow can safely accept incomplete coverage.

### uv reports a cache permission error

Direct `uv run` commands use uv's user cache, while the Makefile uses a
repository-local cache. From the repository root, select the same writable
cache for the current shell:

```bash
export UV_CACHE_DIR="$PWD/.cache/uv"
```

After `make setup`, you can also run `.venv/bin/aisec` and
`.venv/bin/freshpatch` directly without asking uv to synchronize the project.

## 9. Developer checks

Before opening a pull request, run:

```bash
make test
make lint
make typecheck
make web-build
make scan-self
```

`make clean` removes known generated test and frontend build artifacts. It does not delete the virtual environment, npm dependency directory, source code, reports, or benchmark evidence.
