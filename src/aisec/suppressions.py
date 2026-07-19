# ruff: noqa: UP006, UP035, UP045 -- Retain Python 3.9-compatible typing syntax.
"""Narrow, auditable suppressions for accepted scanner findings."""

from __future__ import annotations

import fnmatch
import re
import shlex
from collections.abc import Iterable, Sequence
from dataclasses import dataclass, field
from pathlib import Path
from typing import List, Optional, Set, Tuple

from .rules import get_rule

INLINE_SUPPRESSION = re.compile(r"aisec:\s*ignore(?:\[([^\]]+)\])?", re.IGNORECASE)


def _normalize_rule_id(value: str, context: str) -> str:
    normalized = str(value).strip().upper()
    if normalized == "*":
        return normalized
    try:
        get_rule(normalized)
    except KeyError as exc:
        raise ValueError(
            f"unknown suppression rule ID {value!r} in {context}; run 'aisec rules' "
            "to list valid IDs"
        ) from exc
    return normalized


@dataclass
class Suppressions:
    """Rule and path-based exceptions.

    Suppression files contain either ``RULE_ID`` or ``RULE_ID path/glob`` per
    line. Source can also use ``aisec: ignore[AISEC123]`` on the finding line
    or the immediately preceding line. Bare inline ``aisec: ignore`` is
    supported but the explicit form is preferred for reviewability.
    """

    rule_ids: Set[str] = field(default_factory=set)
    path_rules: List[Tuple[str, str]] = field(default_factory=list)

    def __post_init__(self) -> None:
        self.validate()

    def validate(self) -> None:
        """Normalize and validate all configured rule identifiers."""

        self.rule_ids = {_normalize_rule_id(value, "suppression policy") for value in self.rule_ids}
        self.path_rules = [
            (_normalize_rule_id(rule_id, "suppression policy"), pattern)
            for rule_id, pattern in self.path_rules
        ]

    def add(self, rule_id: str, pattern: Optional[str] = None, *, context: str) -> None:
        """Add one validated global or path-scoped suppression."""

        normalized = _normalize_rule_id(rule_id, context)
        if pattern is None:
            self.rule_ids.add(normalized)
        else:
            self.path_rules.append((normalized, pattern))

    @classmethod
    def from_values(
        cls,
        rule_ids: Optional[Iterable[str]] = None,
        suppression_file: Optional[str] = None,
    ) -> Suppressions:
        policy = cls()
        for value in rule_ids or ():
            policy.add(value, context="--suppress")
        if suppression_file:
            policy.extend_file(suppression_file)
        return policy

    def extend_file(self, filename: str) -> None:
        path = Path(filename)
        for number, raw_line in enumerate(path.read_text(encoding="utf-8").splitlines(), start=1):
            line = raw_line.strip()
            if not line or line.startswith("#"):
                continue
            try:
                fields = shlex.split(line, comments=True)
            except ValueError as exc:
                raise ValueError(f"invalid suppression at {path}:{number}: {exc}") from exc
            if len(fields) == 1:
                self.add(fields[0], context=f"{path}:{number}")
            elif len(fields) == 2:
                self.add(fields[0], fields[1], context=f"{path}:{number}")
            else:
                raise ValueError(f"invalid suppression at {path}:{number}; expected RULE_ID [GLOB]")

    def is_suppressed(
        self,
        rule_id: str,
        uri: str,
        line: Optional[int] = None,
        source_lines: Optional[Sequence[str]] = None,
    ) -> bool:
        normalized_rule = rule_id.upper()
        if normalized_rule in self.rule_ids or "*" in self.rule_ids:
            return True
        normalized_uri = uri.replace("\\", "/")
        for candidate_rule, pattern in self.path_rules:
            if candidate_rule not in (normalized_rule, "*"):
                continue
            if fnmatch.fnmatch(normalized_uri, pattern) or fnmatch.fnmatch(
                normalized_uri.lstrip("./"), pattern
            ):
                return True
        if source_lines is not None and line is not None:
            for line_number in (line, line - 1):
                if line_number < 1 or line_number > len(source_lines):
                    continue
                match = INLINE_SUPPRESSION.search(source_lines[line_number - 1])
                if not match:
                    continue
                listed = match.group(1)
                if listed is None:
                    return True
                ids = {
                    _normalize_rule_id(value, f"inline suppression at {uri}:{line_number}")
                    for value in re.split(r"[,\s]+", listed)
                    if value.strip()
                }
                if normalized_rule in ids or "*" in ids:
                    return True
        return False


def coerce_suppressions(
    suppressions: Optional[Suppressions] = None,
    suppressed_rules: Optional[Iterable[str]] = None,
    suppression_file: Optional[str] = None,
) -> Suppressions:
    if suppressions is not None:
        if suppressed_rules or suppression_file:
            raise ValueError(
                "pass either suppressions or suppressed_rules/suppression_file, not both"
            )
        suppressions.validate()
        return suppressions
    return Suppressions.from_values(suppressed_rules, suppression_file)
