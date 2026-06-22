"""redeye — agentic SAST harness.

Public API surface is intentionally tiny. Most users interact with the CLI
(`redeye`); programmatic users should depend only on the symbols
re-exported here, since everything else is internal.
"""

from __future__ import annotations

__version__ = "0.3.0"

from redeye.errors import (
    BackendError,
    ConfigError,
    PipelineError,
    RedEyeError,
)
from redeye.schema import Finding, Severity

__all__ = [
    "__version__",
    "RedEyeError",
    "BackendError",
    "ConfigError",
    "PipelineError",
    "Finding",
    "Severity",
]
