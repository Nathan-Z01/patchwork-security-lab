# ruff: noqa: E501, UP006, UP007, UP035, UP045 -- Python 3.9 typing and regex clarity.
"""Bounded, read-only source tree scanner for AI-specific security risks."""

from __future__ import annotations

import ast
import fnmatch
import os
import re
import shlex
import stat
from collections.abc import Iterable, Iterator, Sequence
from dataclasses import dataclass
from pathlib import Path
from re import Pattern
from typing import Callable, Dict, List, Optional, Set, Tuple, Union

from .models import Confidence, Finding, Location, ScanReport, Severity
from .rules import get_rule
from .suppressions import Suppressions, coerce_suppressions

DEFAULT_EXCLUDED_DIRS = frozenset(
    {
        ".git",
        ".hg",
        ".cache",
        ".svn",
        ".mypy_cache",
        ".pytest_cache",
        ".ruff_cache",
        ".tox",
        ".venv",
        "__pycache__",
        "bower_components",
        "build",
        "coverage",
        "dist",
        "node_modules",
        "target",
        "vendor",
        "venv",
    }
)

TEXT_EXTENSIONS = frozenset(
    {
        ".bash",
        ".cfg",
        ".conf",
        ".css",
        ".env",
        ".go",
        ".h",
        ".htm",
        ".html",
        ".ini",
        ".ipynb",
        ".java",
        ".js",
        ".json",
        ".jsx",
        ".md",
        ".php",
        ".py",
        ".rb",
        ".rs",
        ".sh",
        ".svelte",
        ".toml",
        ".ts",
        ".tsx",
        ".txt",
        ".vue",
        ".xml",
        ".yaml",
        ".yml",
        ".zsh",
    }
)

CREDENTIAL_TEXT_NAMES = frozenset(
    {
        ".git-credentials",
        ".netrc",
        ".npmrc",
        ".pypirc",
        "_netrc",
        "credentials",
        "id_dsa",
        "id_ecdsa",
        "id_ed25519",
        "id_rsa",
    }
)

SPECIAL_TEXT_NAMES = (
    frozenset({"dockerfile", "gemfile", "makefile", "pipfile", "procfile"}) | CREDENTIAL_TEXT_NAMES
)


@dataclass(frozen=True)
class RegexCheck:
    rule_id: str
    pattern: Pattern[str]
    kind: str = "generic"
    confidence: Optional[Confidence] = None


REGEX_CHECKS: Tuple[RegexCheck, ...] = (
    RegexCheck(
        "AISEC002",
        re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH |DSA )?PRIVATE KEY-----"),
        "private-key",
    ),
    RegexCheck(
        "AISEC001",
        re.compile(
            r"\b(?:AKIA|ASIA)[A-Z0-9]{16}\b|"
            r"\bgh[oprsu]_[A-Za-z0-9]{30,255}\b|"
            r"\bgithub_pat_[A-Za-z0-9_]{40,255}\b|"
            r"\bsk-(?:proj-)?[A-Za-z0-9_-]{20,}\b|"
            r"\bnpm_[A-Za-z0-9]{20,}\b|"
            r"\bpypi-[A-Za-z0-9_-]{20,}\b"
        ),
        "secret",
    ),
    RegexCheck(
        "AISEC001",
        re.compile(
            r"(?i)\b(api[_-]?key|access[_-]?token|auth[_-]?token|client[_-]?secret|"
            r"password|secret[_-]?key)\b\s*[:=]\s*[\"']([^\"'\r\n]{8,})[\"']"
        ),
        "generic-secret",
        Confidence.MEDIUM,
    ),
    RegexCheck(
        "AISEC001",
        re.compile(
            r"(?im)(?:^|[:\s])(_?(?:auth[_-]?token|password)|token)"
            r"\s*(?:[:=]\s*|\s+)([^\s#]+)"
        ),
        "credential-secret",
        Confidence.HIGH,
    ),
    RegexCheck(
        "AISEC101",
        re.compile(
            r"(?i)\b(?:eval|Function)\s*\(\s*(?:llm|ai|model|assistant|completion|chat)"
            r"[_A-Za-z0-9.\[\]]*(?:output|response|content|text|result)?"
        ),
        "code-sink",
    ),
    RegexCheck(
        "AISEC102",
        re.compile(
            r"(?i)\b(?:child_process\.)?(?:exec|execSync|spawn)\s*\(\s*"
            r"(?:llm|ai|model|assistant|completion|chat)[_A-Za-z0-9.\[\]]*"
        ),
        "command-sink",
    ),
    RegexCheck(
        "AISEC103",
        re.compile(
            r"(?i)\b(?:system|developer|admin|privileged)[_-]?prompt\b\s*(?:=|\+=).*"
            r"(?:request\.|req\.|user[_-]?(?:input|query|message)|input\s*\()"
        ),
        "prompt-mix",
    ),
    RegexCheck(
        "AISEC104",
        re.compile(
            r"\b(?:pickle|dill|joblib|cloudpickle)\.loads?\s*\(|"
            r"\btorch\.load\s*\(|"
            r"\btrust_remote_code\s*=\s*True\b"
        ),
        "unsafe-load",
    ),
    RegexCheck(
        "AISEC104",
        re.compile(r"\byaml\.load\s*\((?![^\n]*(?:SafeLoader|safe_load))"),
        "unsafe-load",
    ),
    RegexCheck(
        "AISEC105",
        re.compile(
            r"(?i)\bverify\s*=\s*False\b|"
            r"\bCERT_NONE\b|"
            r"NODE_TLS_REJECT_UNAUTHORIZED\s*=\s*[\"']?0"
        ),
        "tls",
    ),
    RegexCheck(
        "AISEC201",
        re.compile(
            r"(?i)\b(?:innerHTML|outerHTML)\s*=|"
            r"\bdocument\.write(?:ln)?\s*\(|"
            r"dangerouslySetInnerHTML\s*=|"
            r"\.insertAdjacentHTML\s*\("
        ),
        "xss",
    ),
    RegexCheck(
        "AISEC202",
        re.compile(
            r"(?i)(?:access-control-allow-origin[\"']?\s*[:=]\s*[\"']\*|"
            r"allow_origins\s*=\s*\[[\"']\*[\"']\]|"
            r"origins\s*=\s*[\"']\*[\"'])"
        ),
        "cors",
    ),
)


_PLACEHOLDER_SECRET = re.compile(
    r"(?i)^(?:<[^>]+>|\$\{|example|sample|dummy|test|changeme|replace[_-]?me|"
    r"your[_-]?|xxx|none|null|false)"
)

_REDACT_ASSIGNMENT = re.compile(
    r"(?i)(\b(?:api[_-]?key|access[_-]?token|auth[_-]?token|client[_-]?secret|"
    r"password|secret[_-]?key)\b\s*[:=]\s*[\"'])([^\"']+)([\"'])"
)
_REDACT_CREDENTIAL_ASSIGNMENT = re.compile(
    r"(?i)((?:_?(?:auth[_-]?token|password)|token)\s*(?:[:=]\s*|\s+))([^\s#]+)"
)
_REDACT_TOKENS = re.compile(
    r"\b(?:AKIA|ASIA)[A-Z0-9]{16}\b|"
    r"\bgh[oprsu]_[A-Za-z0-9]{20,255}\b|"
    r"\bgithub_pat_[A-Za-z0-9_]{20,255}\b|"
    r"\bsk-(?:proj-)?[A-Za-z0-9_-]{12,}\b|"
    r"\bnpm_[A-Za-z0-9]{12,}\b|"
    r"\bpypi-[A-Za-z0-9_-]{12,}\b"
)


def _redact_evidence(value: str, limit: int = 240) -> str:
    compact = " ".join(value.strip().split())
    compact = _REDACT_ASSIGNMENT.sub(r"\1<redacted>\3", compact)
    compact = _REDACT_CREDENTIAL_ASSIGNMENT.sub(r"\1<redacted>", compact)
    compact = _REDACT_TOKENS.sub("<redacted-token>", compact)
    if len(compact) > limit:
        compact = compact[: limit - 1] + "…"
    return compact


def _looks_like_text(path: Path) -> bool:
    return (
        path.suffix.lower() in TEXT_EXTENSIONS
        or path.name.lower() in SPECIAL_TEXT_NAMES
        or path.name.lower().startswith(".env")
    )


def _relative_uri(path: Path, root: Path) -> str:
    if root.is_file():
        return path.name
    try:
        return path.relative_to(root).as_posix()
    except ValueError:
        return path.as_posix()


def _iter_files(
    target: Path,
    excluded_dirs: Set[str],
    exclude_patterns: Sequence[str],
    on_safety_skip: Optional[Callable[[Path, str], None]] = None,
) -> Iterator[Path]:
    if target.is_file():
        if target.is_symlink():
            if on_safety_skip is not None:
                on_safety_skip(target, "symbolic link")
        elif _looks_like_text(target) and not _path_excluded(target.name, exclude_patterns):
            yield target
        return
    for directory, dirnames, filenames in os.walk(str(target), followlinks=False):
        retained_directories = []
        for name in sorted(dirnames):
            path = Path(directory, name)
            relative = path.relative_to(target).as_posix()
            if name in excluded_dirs or _path_excluded(relative, exclude_patterns):
                continue
            if path.is_symlink():
                if on_safety_skip is not None:
                    on_safety_skip(path, "symbolic link directory")
                continue
            retained_directories.append(name)
        dirnames[:] = retained_directories
        for filename in sorted(filenames):
            path = Path(directory, filename)
            relative = path.relative_to(target).as_posix()
            if _path_excluded(relative, exclude_patterns):
                continue
            if path.is_symlink():
                if on_safety_skip is not None:
                    on_safety_skip(path, "symbolic link")
                continue
            if not _looks_like_text(path):
                continue
            yield path


def _path_excluded(relative_path: str, patterns: Sequence[str]) -> bool:
    normalized = relative_path.replace("\\", "/").lstrip("./")
    for raw_pattern in patterns:
        pattern = raw_pattern.strip().replace("\\", "/").lstrip("./")
        if not pattern:
            continue
        prefix = pattern.rstrip("/")
        if prefix.endswith("/**"):
            prefix = prefix[:-3].rstrip("/")
        if (
            fnmatch.fnmatch(normalized, pattern)
            or normalized == prefix
            or normalized.startswith(prefix + "/")
        ):
            return True
    return False


_RULE_LIKE = re.compile(r"^(?:AISEC|\*)", re.IGNORECASE)


def _load_ignore_file(filename: Path, policy: Suppressions) -> List[str]:
    """Load path excludes and optional rule suppressions from .aisecignore."""

    patterns: List[str] = []
    for number, raw_line in enumerate(filename.read_text(encoding="utf-8").splitlines(), start=1):
        line = raw_line.strip()
        if not line or line.startswith("#"):
            continue
        try:
            fields = shlex.split(line, comments=True)
        except ValueError as exc:
            raise ValueError(f"invalid ignore entry at {filename}:{number}: {exc}") from exc
        if len(fields) == 1 and _RULE_LIKE.match(fields[0]):
            policy.add(fields[0], context=f"{filename}:{number}")
        elif len(fields) == 1:
            patterns.append(fields[0])
        elif len(fields) == 2 and _RULE_LIKE.match(fields[0]):
            policy.add(fields[0], fields[1], context=f"{filename}:{number}")
        else:
            raise ValueError(
                f"invalid ignore entry at {filename}:{number}; expected GLOB, RULE_ID, or RULE_ID GLOB"
            )
    return patterns


def _target_names(target: ast.AST) -> Iterable[str]:
    if isinstance(target, ast.Name):
        yield target.id
    elif isinstance(target, (ast.Tuple, ast.List)):
        for element in target.elts:
            yield from _target_names(element)


def _call_name(node: ast.AST) -> str:
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        prefix = _call_name(node.value)
        return (prefix + "." if prefix else "") + node.attr
    if isinstance(node, ast.Subscript):
        return _call_name(node.value)
    return ""


_LLM_NAME = re.compile(
    r"(?i)(?:(?:llm|model|ai|assistant|completion|chat).*(?:output|response|content|"
    r"text|result)|(?:output|response|result).*(?:llm|model|ai|assistant|completion|chat))"
)

_STRING_TRANSFORMS = frozenset(
    {
        "capitalize",
        "casefold",
        "center",
        "decode",
        "encode",
        "expandtabs",
        "format",
        "format_map",
        "join",
        "ljust",
        "lower",
        "lstrip",
        "partition",
        "removeprefix",
        "removesuffix",
        "replace",
        "rjust",
        "rpartition",
        "rsplit",
        "rstrip",
        "split",
        "splitlines",
        "strip",
        "swapcase",
        "title",
        "translate",
        "upper",
        "zfill",
    }
)


def _is_llm_call(name: str) -> bool:
    lowered = name.lower()
    if any(
        marker in lowered
        for marker in (
            "chat.completions.create",
            "completions.create",
            "responses.create",
            "openai.chat",
            "anthropic.messages.create",
            "generate_content",
            "query_llm",
            "ask_llm",
            "ask_model",
            "call_model",
        )
    ):
        return True
    if lowered.endswith((".invoke", ".generate", ".complete")):
        return any(
            marker in lowered for marker in ("llm", "model", "chain", "agent", "chat", "client")
        )
    return False


class _LLMTaintVisitor(ast.NodeVisitor):
    """Small intra-scope heuristic, intentionally not a full data-flow engine."""

    def __init__(self, text: str, uri: str) -> None:
        self.text = text
        self.uri = uri
        self.tainted: Set[str] = set()
        self.taint_sources: Dict[str, Dict[str, object]] = {}
        self.matches: List[Tuple[str, ast.Call, Severity, Confidence, Dict[str, object]]] = []

    def _direct_source(self, node: ast.AST, symbol: str) -> Dict[str, object]:
        return {
            "kind": "source",
            "line": getattr(node, "lineno", 1),
            "symbol": symbol or "llm-output",
        }

    def _taint_source(self, node: ast.AST) -> Optional[Dict[str, object]]:
        if isinstance(node, ast.Name):
            if node.id in self.taint_sources:
                return dict(self.taint_sources[node.id])
            if node.id in self.tainted or _LLM_NAME.search(node.id):
                return self._direct_source(node, node.id)
            return None
        if isinstance(node, ast.Await):
            return self._taint_source(node.value)
        if isinstance(node, ast.Call):
            call_name = _call_name(node.func)
            if _is_llm_call(call_name):
                return self._direct_source(node, call_name)
            if (
                isinstance(node.func, ast.Attribute)
                and node.func.attr.lower() in _STRING_TRANSFORMS
            ):
                source = self._taint_source(node.func.value)
                if source is not None:
                    return source
            for argument in node.args:
                source = self._taint_source(argument)
                if source is not None:
                    return source
            for keyword in node.keywords:
                source = self._taint_source(keyword.value)
                if source is not None:
                    return source
            return None
        if isinstance(node, ast.Attribute):
            source = self._taint_source(node.value)
            if source is not None:
                return source
            name = _call_name(node)
            return self._direct_source(node, name) if _LLM_NAME.search(name) else None
        if isinstance(node, ast.Subscript):
            return self._taint_source(node.value)
        if isinstance(node, ast.BinOp):
            return self._taint_source(node.left) or self._taint_source(node.right)
        if isinstance(node, ast.JoinedStr):
            for value in node.values:
                if isinstance(value, ast.FormattedValue):
                    source = self._taint_source(value.value)
                    if source is not None:
                        return source
            return None
        if isinstance(node, (ast.List, ast.Tuple, ast.Set)):
            for element in node.elts:
                source = self._taint_source(element)
                if source is not None:
                    return source
            return None
        if isinstance(node, ast.Dict):
            for value in node.values:
                source = self._taint_source(value)
                if source is not None:
                    return source
        return None

    def _is_tainted(self, node: ast.AST) -> bool:
        return self._taint_source(node) is not None

    def _set_taint(self, name: str, source: Optional[Dict[str, object]]) -> None:
        if source is None:
            self.tainted.discard(name)
            self.taint_sources.pop(name, None)
            return
        self.tainted.add(name)
        self.taint_sources[name] = dict(source)

    def _trace(
        self, source_node: ast.AST, sink_node: ast.Call, sink: str
    ) -> List[Dict[str, object]]:
        source = self._taint_source(source_node) or self._direct_source(source_node, "llm-output")
        return [
            source,
            {
                "kind": "sink",
                "line": getattr(sink_node, "lineno", 1),
                "symbol": sink,
            },
        ]

    def visit_Assign(self, node: ast.Assign) -> None:
        self.visit(node.value)
        source = self._taint_source(node.value)
        for target in node.targets:
            for name in _target_names(target):
                self._set_taint(name, source)

    def visit_AnnAssign(self, node: ast.AnnAssign) -> None:
        if node.value is not None:
            self.visit(node.value)
            for name in _target_names(node.target):
                self._set_taint(name, self._taint_source(node.value))

    def _visit_function(self, node: Union[ast.FunctionDef, ast.AsyncFunctionDef]) -> None:
        previous = self.tainted
        previous_sources = self.taint_sources
        self.tainted = {
            argument.arg
            for argument in list(node.args.args)
            + list(node.args.kwonlyargs)
            + list(getattr(node.args, "posonlyargs", []))
            if _LLM_NAME.search(argument.arg)
        }
        self.taint_sources = {
            argument.arg: self._direct_source(argument, argument.arg)
            for argument in list(node.args.args)
            + list(node.args.kwonlyargs)
            + list(getattr(node.args, "posonlyargs", []))
            if _LLM_NAME.search(argument.arg)
        }
        for statement in node.body:
            self.visit(statement)
        self.tainted = previous
        self.taint_sources = previous_sources

    def visit_FunctionDef(self, node: ast.FunctionDef) -> None:
        self._visit_function(node)

    def visit_AsyncFunctionDef(self, node: ast.AsyncFunctionDef) -> None:
        self._visit_function(node)

    def visit_Call(self, node: ast.Call) -> None:
        name = _call_name(node.func).lower()
        positional = node.args[0] if node.args else None
        source_keyword = next(
            (keyword.value for keyword in node.keywords if keyword.arg == "source"),
            None,
        )
        code_argument = positional or source_keyword
        if (
            name
            in {
                "eval",
                "exec",
                "compile",
                "builtins.eval",
                "builtins.exec",
            }
            and code_argument is not None
            and self._is_tainted(code_argument)
        ):
            self.matches.append(
                (
                    "AISEC101",
                    node,
                    Severity.CRITICAL,
                    Confidence.HIGH,
                    {"sink": name, "trace": self._trace(code_argument, node, name)},
                )
            )
        shell_keyword = next(
            (
                keyword
                for keyword in node.keywords
                if keyword.arg == "shell"
                and isinstance(keyword.value, ast.Constant)
                and keyword.value.value is True
            ),
            None,
        )
        command_sink = name in {"os.system", "os.popen"} or name in {
            "subprocess.run",
            "subprocess.call",
            "subprocess.popen",
            "subprocess.check_call",
            "subprocess.check_output",
        }
        args_keyword = next(
            (
                keyword.value
                for keyword in node.keywords
                if keyword.arg in {"args", "command", "cmd"}
            ),
            None,
        )
        command_argument = positional or args_keyword
        if command_sink and command_argument is not None and self._is_tainted(command_argument):
            severity = (
                Severity.CRITICAL
                if name in {"os.system", "os.popen"} or shell_keyword is not None
                else Severity.HIGH
            )
            self.matches.append(
                (
                    "AISEC102",
                    node,
                    severity,
                    Confidence.HIGH,
                    {
                        "sink": name,
                        "shell": shell_keyword is not None,
                        "trace": self._trace(command_argument, node, name),
                    },
                )
            )
        self.generic_visit(node)


class SourceScanner:
    """Read-only scanner with deterministic resource bounds."""

    def __init__(
        self,
        *,
        suppressions: Optional[Suppressions] = None,
        max_files: int = 10_000,
        max_file_bytes: int = 1_000_000,
        max_total_bytes: int = 50_000_000,
        max_findings: int = 1_000,
        excluded_dirs: Optional[Iterable[str]] = None,
        exclude_patterns: Optional[Iterable[str]] = None,
        ignore_file: Optional[str] = None,
    ) -> None:
        if min(max_files, max_file_bytes, max_total_bytes, max_findings) < 1:
            raise ValueError("source scan limits must be positive")
        self.suppressions = suppressions or Suppressions()
        self.max_files = max_files
        self.max_file_bytes = max_file_bytes
        self.max_total_bytes = max_total_bytes
        self.max_findings = max_findings
        self.excluded_dirs = set(excluded_dirs or DEFAULT_EXCLUDED_DIRS)
        self.exclude_patterns = list(exclude_patterns or ())
        self.ignore_file = ignore_file

    def _finding(
        self,
        rule_id: str,
        uri: str,
        line: int,
        evidence: str,
        lines: Sequence[str],
        *,
        severity: Optional[Severity] = None,
        confidence: Optional[Confidence] = None,
        metadata: Optional[Dict[str, object]] = None,
        column: Optional[int] = None,
        end_line: Optional[int] = None,
    ) -> Optional[Finding]:
        if self.suppressions.is_suppressed(rule_id, uri, line, lines):
            return None
        return Finding.from_rule(
            get_rule(rule_id),
            Location(uri, line, column, end_line),
            _redact_evidence(evidence),
            severity=severity,
            confidence=confidence,
            metadata=metadata,
        )

    def _regex_findings(self, text: str, lines: Sequence[str], uri: str) -> Iterator[Finding]:
        seen: Set[Tuple[str, int]] = set()
        for check in REGEX_CHECKS:
            if (
                check.kind == "credential-secret"
                and Path(uri).name.lower() not in CREDENTIAL_TEXT_NAMES
            ):
                continue
            for match in check.pattern.finditer(text):
                line_number = text.count("\n", 0, match.start()) + 1
                key = (check.rule_id, line_number)
                if key in seen:
                    continue
                if check.kind in {"generic-secret", "credential-secret"}:
                    secret = match.group(2).strip()
                    if _PLACEHOLDER_SECRET.match(secret):
                        continue
                if check.kind == "unsafe-load":
                    current = lines[line_number - 1] if line_number <= len(lines) else ""
                    if "torch.load" in current and re.search(r"weights_only\s*=\s*True", current):
                        continue
                seen.add(key)
                line_text = lines[line_number - 1] if line_number <= len(lines) else match.group(0)
                finding = self._finding(
                    check.rule_id,
                    uri,
                    line_number,
                    line_text,
                    lines,
                    confidence=check.confidence,
                    column=match.start() - text.rfind("\n", 0, match.start()),
                    metadata={"analysis": "regex"},
                )
                if finding is not None:
                    yield finding

    def _ast_findings(
        self, text: str, lines: Sequence[str], uri: str
    ) -> Tuple[List[Finding], Optional[str]]:
        try:
            tree = ast.parse(text, filename=uri)
        except (SyntaxError, ValueError) as exc:
            return [], f"Could not parse {uri} for AST analysis: {exc}"
        visitor = _LLMTaintVisitor(text, uri)
        visitor.visit(tree)
        findings: List[Finding] = []
        seen: Set[Tuple[str, int]] = set()
        for rule_id, node, severity, confidence, metadata in visitor.matches:
            line = getattr(node, "lineno", 1)
            key = (rule_id, line)
            if key in seen:
                continue
            seen.add(key)
            segment = ast.get_source_segment(text, node)
            if not segment and 1 <= line <= len(lines):
                segment = lines[line - 1]
            finding = self._finding(
                rule_id,
                uri,
                line,
                segment or _call_name(node.func),
                lines,
                severity=severity,
                confidence=confidence,
                metadata={"analysis": "python-ast-taint", **metadata},
                column=getattr(node, "col_offset", 0) + 1,
                end_line=getattr(node, "end_lineno", None),
            )
            if finding is not None:
                findings.append(finding)
        return findings, None

    def scan(self, path: str) -> ScanReport:
        target = Path(path).expanduser()
        if not target.exists():
            raise FileNotFoundError(f"source target does not exist: {target}")
        if not target.is_file() and not target.is_dir():
            raise ValueError("source target must be a regular file or directory")
        resolved = target.resolve()
        report = ScanReport(str(resolved), "source")
        ignore_path: Optional[Path] = None
        if self.ignore_file:
            ignore_path = Path(self.ignore_file).expanduser()
            if not ignore_path.is_file():
                raise FileNotFoundError(f"ignore file does not exist: {ignore_path}")
        else:
            candidate = (
                resolved / ".aisecignore" if resolved.is_dir() else resolved.parent / ".aisecignore"
            )
            if candidate.is_file():
                ignore_path = candidate
        active_excludes = list(self.exclude_patterns)
        if ignore_path is not None:
            active_excludes.extend(_load_ignore_file(ignore_path, self.suppressions))
        report.metadata.update(
            {
                "max_files": self.max_files,
                "max_file_bytes": self.max_file_bytes,
                "max_total_bytes": self.max_total_bytes,
                "max_findings": self.max_findings,
                "total_bytes_scanned": 0,
                "analysis": ["regex", "python-ast-taint"],
                "exclude_patterns": active_excludes,
                "ignore_file": str(ignore_path) if ignore_path else None,
            }
        )
        total_bytes_scanned = 0
        finding_indexes: Dict[str, int] = {}
        finding_limit_reached = False

        def record_safety_skip(path: Path, reason: str) -> None:
            report.skipped += 1
            report.warnings.append(f"Skipped {path}: {reason} was not followed.")

        for index, file_path in enumerate(
            _iter_files(
                resolved,
                self.excluded_dirs,
                active_excludes,
                on_safety_skip=record_safety_skip,
            ),
            start=1,
        ):
            if index > self.max_files:
                report.warnings.append(
                    f"Stopped after max_files={self.max_files}; remaining files were not scanned."
                )
                break
            try:
                file_stat = os.lstat(file_path)
            except OSError as exc:
                report.skipped += 1
                report.warnings.append(f"Skipped {file_path}: {exc}")
                continue
            if not stat.S_ISREG(file_stat.st_mode):
                report.skipped += 1
                report.warnings.append(f"Skipped {file_path}: not a regular file.")
                continue
            size = file_stat.st_size
            if size > self.max_file_bytes:
                report.skipped += 1
                report.warnings.append(f"Skipped {file_path}: file exceeds max_file_bytes.")
                continue
            if total_bytes_scanned + size > self.max_total_bytes:
                report.warnings.append(
                    f"Stopped before {file_path}: max_total_bytes={self.max_total_bytes} "
                    "would be exceeded."
                )
                report.mark_partial()
                break
            try:
                with file_path.open("rb") as handle:
                    raw = handle.read(size)
                    observed_size = os.fstat(handle.fileno()).st_size
            except OSError as exc:
                report.skipped += 1
                report.warnings.append(f"Skipped {file_path}: {exc}")
                continue
            total_bytes_scanned += len(raw)
            report.metadata["total_bytes_scanned"] = total_bytes_scanned
            if observed_size != size or len(raw) != size:
                report.warnings.append(
                    f"File changed while it was being scanned and coverage may be incomplete: {file_path}"
                )
                report.mark_partial()
            if b"\x00" in raw[:8192]:
                report.skipped += 1
                continue
            text = raw.decode("utf-8", "replace")
            lines = text.splitlines()
            uri = _relative_uri(file_path, resolved)
            report.files_scanned += 1
            for finding in self._regex_findings(text, lines, uri):
                if finding.fingerprint in finding_indexes:
                    report.findings[finding_indexes[finding.fingerprint]] = finding
                    continue
                finding_indexes[finding.fingerprint] = len(report.findings)
                report.findings.append(finding)
                if len(report.findings) >= self.max_findings:
                    finding_limit_reached = True
                    break
            if finding_limit_reached:
                report.warnings.append(
                    f"Stopped after max_findings={self.max_findings}; remaining checks were not run."
                )
                report.mark_partial()
                break
            if file_path.suffix.lower() == ".py":
                ast_findings, warning = self._ast_findings(text, lines, uri)
                for finding in ast_findings:
                    if finding.fingerprint in finding_indexes:
                        report.findings[finding_indexes[finding.fingerprint]] = finding
                        continue
                    finding_indexes[finding.fingerprint] = len(report.findings)
                    report.findings.append(finding)
                    if len(report.findings) >= self.max_findings:
                        finding_limit_reached = True
                        break
                if warning:
                    report.warnings.append(warning)
                if finding_limit_reached:
                    report.warnings.append(
                        f"Stopped after max_findings={self.max_findings}; remaining checks were not run."
                    )
                    report.mark_partial()
                    break
        if report.files_scanned == 0:
            if not report.warnings:
                if resolved.is_file():
                    report.warnings.append(
                        f"Target is not a supported regular text file: {resolved}"
                    )
                else:
                    report.warnings.append(
                        f"Target directory contained no supported regular text files: {resolved}"
                    )
            report.mark_failed()
        return report.finish()


def scan_source(
    path: str,
    *,
    suppressions: Optional[Suppressions] = None,
    suppressed_rules: Optional[Iterable[str]] = None,
    suppression_file: Optional[str] = None,
    max_files: int = 10_000,
    max_file_bytes: int = 1_000_000,
    max_total_bytes: int = 50_000_000,
    max_findings: int = 1_000,
    excluded_dirs: Optional[Iterable[str]] = None,
    exclude_patterns: Optional[Iterable[str]] = None,
    ignore_file: Optional[str] = None,
) -> ScanReport:
    """Scan a local source file or directory without modifying it."""

    policy = coerce_suppressions(suppressions, suppressed_rules, suppression_file)
    return SourceScanner(
        suppressions=policy,
        max_files=max_files,
        max_file_bytes=max_file_bytes,
        max_total_bytes=max_total_bytes,
        max_findings=max_findings,
        excluded_dirs=excluded_dirs,
        exclude_patterns=exclude_patterns,
        ignore_file=ignore_file,
    ).scan(path)
