"""Command-line interface for creating and evaluating FreshPatch tasks."""

from __future__ import annotations

import argparse
import shlex
import sys
from collections.abc import Sequence
from pathlib import Path

from . import __version__
from .builder import build_task
from .errors import FreshPatchError
from .evaluator import DockerConfig, build_docker_command, dumps_result, evaluate
from .qualification import dumps_qualification, qualify, write_qualification
from .reporting import load_results, render_json, render_markdown
from .schema import DEFAULT_RUNNER_IMAGE, RunnerSpec, Task, dumps_task, load_task, write_task


def _environment(values: Sequence[str]) -> dict[str, str]:
    parsed: dict[str, str] = {}
    for value in values:
        if "=" not in value:
            raise ValueError("environment values must use NAME=VALUE syntax")
        name, item = value.split("=", 1)
        if name in parsed:
            raise ValueError(f"duplicate environment value: {name}")
        parsed[name] = item
    return parsed


def _test_command(value: str) -> list[str]:
    command = shlex.split(value)
    if not command:
        raise ValueError("test command must not be empty")
    return command


def _write_or_print(content: str, output: Path | None) -> None:
    if output is None:
        sys.stdout.write(content)
        return
    output.parent.mkdir(parents=True, exist_ok=True)
    with output.open("w", encoding="utf-8", newline="\n") as handle:
        handle.write(content)


def _docker_config(task: Task, arguments: argparse.Namespace) -> DockerConfig:
    runner = task.runner
    return DockerConfig(
        image=getattr(arguments, "image", None) or runner.image,
        cpus=getattr(arguments, "cpus", None) or runner.cpus,
        memory=getattr(arguments, "memory", None) or runner.memory,
        pids_limit=getattr(arguments, "pids_limit", None) or runner.pids_limit,
        tmpfs_size=getattr(arguments, "tmpfs_size", None) or runner.tmpfs_size,
    )


def _add_execution_arguments(command: argparse.ArgumentParser) -> None:
    command.add_argument("--backend", choices=("docker", "local"), default="docker")
    command.add_argument(
        "--allow-unsafe-local",
        action="store_true",
        help="acknowledge that local tests can execute arbitrary host code",
    )
    command.add_argument("--repo", type=Path, help="trusted local repository override")
    command.add_argument(
        "--image",
        help="override the task's digest-pinned Docker image (must also be digest-pinned)",
    )
    command.add_argument("--cpus", help="override the recorded Docker CPU limit")
    command.add_argument("--memory", help="override the recorded Docker memory limit")
    command.add_argument("--pids-limit", type=int, help="override the recorded process limit")
    command.add_argument(
        "--tmpfs-size",
        help="override each independent /tmp and /workspace size limit",
    )
    command.add_argument("--output", "-o", type=Path)


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="freshpatch",
        description="Build and execute reproducible code-repair benchmarks.",
    )
    parser.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    commands = parser.add_subparsers(dest="subcommand", required=True)

    build = commands.add_parser("build", help="build a task from two local Git commits")
    build.add_argument("--repo", required=True, type=Path, help="local source repository")
    build.add_argument("--buggy", required=True, help="known-buggy revision")
    build.add_argument("--fixed", required=True, help="known-fixed descendant revision")
    build.add_argument(
        "--test-command",
        required=True,
        help='quoted command parsed into argv, for example "python -m unittest -q"',
    )
    build.add_argument("--id", dest="task_id")
    build.add_argument("--title")
    build.add_argument("--description", default="")
    build.add_argument("--timeout", type=int, default=300)
    build.add_argument("--workdir", default=".")
    build.add_argument("--env", action="append", default=[], metavar="NAME=VALUE")
    build.add_argument("--label", action="append", default=[])
    build.add_argument("--published-source", help="source locator stored instead of the local path")
    build.add_argument(
        "--runner-image",
        default=DEFAULT_RUNNER_IMAGE,
        help="digest-pinned Docker image recorded in the task",
    )
    build.add_argument("--cpus", default="1.0", help="Docker CPU limit recorded in the task")
    build.add_argument("--memory", default="1g", help="Docker memory limit recorded in the task")
    build.add_argument("--pids-limit", type=int, default=256)
    build.add_argument(
        "--tmpfs-size",
        default="128m",
        help="size recorded independently for /tmp and /workspace",
    )
    build.add_argument("--output", "-o", required=True, type=Path)

    validate = commands.add_parser("validate", help="validate and normalize a task artifact")
    validate.add_argument("task", type=Path)

    run = commands.add_parser("evaluate", help="execute one repair task")
    run.add_argument("--task", required=True, type=Path)
    patch_selection = run.add_mutually_exclusive_group()
    patch_selection.add_argument("--patch", type=Path, help="candidate git-diff patch")
    patch_selection.add_argument(
        "--reference",
        action="store_true",
        help="evaluate the recorded reference patch",
    )
    _add_execution_arguments(run)

    verify = commands.add_parser(
        "verify",
        help="qualify a task by proving its baseline fails and reference patch passes",
    )
    verify.add_argument("--task", required=True, type=Path)
    _add_execution_arguments(verify)

    plan = commands.add_parser(
        "docker-command",
        help="print a bounded Docker command without executing it",
    )
    plan.add_argument("--task", required=True, type=Path)
    plan.add_argument("--workspace", required=True, type=Path)
    plan.add_argument("--image", help="digest-pinned runner image override")
    plan.add_argument("--cpus")
    plan.add_argument("--memory")
    plan.add_argument("--pids-limit", type=int)
    plan.add_argument(
        "--tmpfs-size",
        help="override each independent /tmp and /workspace size limit",
    )

    report = commands.add_parser("report", help="aggregate result artifacts")
    report.add_argument("results", nargs="+", type=Path)
    report.add_argument("--format", choices=("markdown", "json"), default="markdown")
    report.add_argument("--title", default="FreshPatch evaluation report")
    report.add_argument("--output", "-o", type=Path)
    return parser


def _run(arguments: argparse.Namespace) -> int:
    if arguments.subcommand == "build":
        task = build_task(
            arguments.repo,
            arguments.buggy,
            arguments.fixed,
            _test_command(arguments.test_command),
            task_id=arguments.task_id,
            title=arguments.title,
            description=arguments.description,
            timeout_seconds=arguments.timeout,
            working_directory=arguments.workdir,
            environment=_environment(arguments.env),
            labels=arguments.label,
            published_source=arguments.published_source,
            runner=RunnerSpec(
                image=arguments.runner_image,
                cpus=arguments.cpus,
                memory=arguments.memory,
                pids_limit=arguments.pids_limit,
                tmpfs_size=arguments.tmpfs_size,
            ),
        )
        write_task(task, arguments.output)
        sys.stdout.write(f"wrote {arguments.output}\n")
        return 0

    if arguments.subcommand == "validate":
        sys.stdout.write(dumps_task(load_task(arguments.task)))
        return 0

    if arguments.subcommand == "evaluate":
        task = load_task(arguments.task)
        if arguments.reference:
            candidate_patch = task.reference_patch.diff
            patch_kind = "reference"
        elif arguments.patch is not None:
            candidate_patch = arguments.patch.read_text(encoding="utf-8")
            patch_kind = "candidate"
        else:
            candidate_patch = None
            patch_kind = "candidate"
        result = evaluate(
            task,
            candidate_patch=candidate_patch,
            patch_kind=patch_kind,
            backend=arguments.backend,
            allow_unsafe_local=arguments.allow_unsafe_local,
            repository_override=arguments.repo,
            task_base_directory=arguments.task.parent,
            docker_config=(
                _docker_config(task, arguments) if arguments.backend == "docker" else None
            ),
        )
        _write_or_print(dumps_result(result), arguments.output)
        return 0 if result.status.value == "passed" else 1

    if arguments.subcommand == "verify":
        task = load_task(arguments.task)
        artifact = qualify(
            task,
            backend=arguments.backend,
            allow_unsafe_local=arguments.allow_unsafe_local,
            repository_override=arguments.repo,
            task_base_directory=arguments.task.parent,
            docker_config=(
                _docker_config(task, arguments) if arguments.backend == "docker" else None
            ),
        )
        if arguments.output is None:
            sys.stdout.write(dumps_qualification(artifact))
        else:
            write_qualification(artifact, arguments.output)
        return 0 if artifact.qualified else 1

    if arguments.subcommand == "docker-command":
        task = load_task(arguments.task)
        command = build_docker_command(
            arguments.workspace,
            task.test,
            _docker_config(task, arguments),
        )
        sys.stdout.write(shlex.join(command) + "\n")
        return 0

    if arguments.subcommand == "report":
        results = load_results(arguments.results)
        if arguments.format == "json":
            content = render_json(results)
        else:
            content = render_markdown(results, title=arguments.title)
        _write_or_print(content, arguments.output)
        return 0
    raise AssertionError("unhandled command")


def main(argv: Sequence[str] | None = None) -> int:
    parser = _parser()
    arguments = parser.parse_args(argv)
    try:
        return _run(arguments)
    except (FreshPatchError, OSError, ValueError) as exc:
        sys.stderr.write(f"freshpatch: error: {exc}\n")
        return 2


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
