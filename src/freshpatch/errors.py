"""FreshPatch exception hierarchy.

The public exceptions are intentionally small so callers can distinguish malformed
artifacts, repository problems, and execution-policy failures without parsing error
messages.
"""


class FreshPatchError(Exception):
    """Base class for all expected FreshPatch failures."""


class SchemaError(FreshPatchError, ValueError):
    """Raised when a task or result artifact is malformed."""


class RepositoryError(FreshPatchError):
    """Raised when a Git repository cannot produce a benchmark task."""


class EvaluationError(FreshPatchError):
    """Raised when an evaluation cannot be prepared or launched."""


class UnsafeExecutionError(EvaluationError):
    """Raised when local execution was requested without explicit consent."""
