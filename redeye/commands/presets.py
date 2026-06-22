"""Scan presets -- one-flag substitutes for the common scan-flag combinations.

A *preset* is a named tuple of default values for the ``scan`` flags. When
``--preset NAME`` is given, the preset's values fill in for any scan flag the
user did **not** pass explicitly on the command line. Explicit user flags
always win -- the preset is only a default-overlay.

This design preserves the no-outcome-change guarantee: passing only
``--preset pr`` should produce the exact same scan as typing out all of the
expanded flags by hand, and adding any explicit flag overrides just that one
slot.

The preset shapes are deliberately conservative -- they match what an
experienced operator would type for that scenario.
"""

from __future__ import annotations

from typing import Any

# Public preset registry. Each value is a dict of {scan_flag_name: value}.
# Flag names match the parameter names on the ``scan`` callback.
PRESETS: dict[str, dict[str, Any]] = {
    "pr": {
        # PR-scan: only changed files, DoS limits, strict on hallucinations,
        # standard exclusions. Mirrors what the bundled GitHub Actions
        # workflow uses for `pull_request` events.
        "diff_only": True,
        "pr_base": "origin/main",
        "max_files": 100,
        "max_file_bytes": 500_000,
        "max_total_bytes": 5_242_880,
        "exclude_paths": ["test", "tests", "vendor", "node_modules", "__tests__", "dist", "build"],
        "strict_grounding": True,
        "store_findings": True,
        "use_feedback": True,
    },
    "ci": {
        # CI full-repo scan, but bounded so it can't run away. Useful for
        # `workflow_dispatch` jobs and nightly cron.
        "max_files": 300,
        "max_file_bytes": 1_000_000,
        "max_total_bytes": 20_971_520,  # 20 MB
        "exclude_paths": ["test", "tests", "vendor", "node_modules", "__tests__", "dist", "build", ".next", "coverage"],
        "strict_grounding": True,
        "store_findings": True,
    },
    "deep": {
        # Research mode: spend more, keep weakly-grounded findings as triage
        # candidates instead of dropping them. Operator reviews the report.
        "max_files": 0,
        "max_file_bytes": 0,
        "max_total_bytes": 0,
        "exclude_paths": ["node_modules", "vendor", "dist", "build"],
        "strict_grounding": False,
        "require_poc": False,
        "store_findings": True,
    },
    "quick": {
        # Try-it-out demo: mock backend, tiny scope. Zero LLM cost.
        # Good for first-time installs and CI smoke tests.
        "profile": "mock",
        "max_files": 20,
        "max_file_bytes": 100_000,
        "max_total_bytes": 1_500_000,
        "exclude_paths": ["test", "tests", "vendor", "node_modules"],
        "strict_grounding": False,
    },
}


def apply_preset(
    name: str,
    *,
    explicit_flags: set[str],
    current_kwargs: dict[str, Any],
) -> dict[str, Any]:
    """Return a new kwargs dict with the preset overlay applied.

    Parameters
    ----------
    name :
        Preset name. Must exist in :data:`PRESETS`.
    explicit_flags :
        Names of flags that were explicitly set on the command line. The
        preset will NOT overwrite these.
    current_kwargs :
        The kwargs the CLI parsed. We mutate a copy and return it.
    """
    if name not in PRESETS:
        raise ValueError(f"unknown preset {name!r}; choose from: {', '.join(PRESETS)}")
    out = dict(current_kwargs)
    for flag, value in PRESETS[name].items():
        if flag in explicit_flags:
            continue
        # Special case: list-typed flags (exclude_paths). If the user passed
        # their own list explicitly we already skipped above; otherwise we
        # adopt the preset's list outright.
        out[flag] = value
    return out


def list_presets() -> list[tuple[str, str]]:
    """Return [(name, one-line description), ...] for help text."""
    return [
        ("pr", "diff-only PR scan with strict grounding (mirrors the GHA workflow)"),
        ("ci", "full-repo CI scan, bounded by DoS limits"),
        ("deep", "research mode -- unlimited scope, keep weak-evidence findings"),
        ("quick", "60-second mock-backend demo, zero LLM cost"),
    ]
