"""Typed exception hierarchy for redeye.

All public errors descend from :class:`RedEyeError` so that callers can
catch the whole family with a single ``except`` clause if they want to.
"""

from __future__ import annotations


class RedEyeError(Exception):
    """Root of the redeye exception tree."""


class ConfigError(RedEyeError):
    """Raised when a profile / config file is invalid or missing."""


class BackendError(RedEyeError):
    """Raised when an LLM backend fails to produce a usable response."""


class PipelineError(RedEyeError):
    """Raised when the pipeline cannot continue (a required stage failed)."""


class CredentialError(BackendError):
    """Raised when a backend cannot authenticate."""


class BudgetExceededError(PipelineError):
    """Raised when a stage's max_budget_usd is exceeded."""
