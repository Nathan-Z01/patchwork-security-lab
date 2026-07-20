"""Errors raised by SignalLab's validation and modeling boundaries."""

from __future__ import annotations


class SignalLabError(Exception):
    """Base class for expected SignalLab failures."""


class DataValidationError(SignalLabError):
    """The supplied market data is malformed, unsafe, or insufficient."""


class TrainingError(SignalLabError):
    """A leakage-safe model could not be trained from the supplied data."""


class ArtifactError(SignalLabError):
    """A model artifact violates the strict JSON contract."""
