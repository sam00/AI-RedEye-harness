"""S1 skill -- map the attack surface."""

from __future__ import annotations

from pathlib import Path
from typing import Any

from redeye.backends.base import BackendBase, CompletionResult
from redeye.skills._helpers import extract_json, short_repo_summary

_SYSTEM = """\
You are a senior application-security engineer. Given a brief snapshot of a
codebase, list the entrypoints (HTTP, CLI, message queues, scheduled jobs),
the auth boundaries you can see, and the sensitive sinks that look interesting
to attack. Reply with a single JSON object: {entrypoints: [...], auth_boundaries: [...], sensitive_sinks: [...], summary: "..."}.
"""


def map_attack_surface(
    *,
    target: Path,
    backend: BackendBase,
    model: str,
    temperature: float | None,
    max_tokens: int,
    max_budget_usd: float,
) -> tuple[dict[str, Any], CompletionResult]:
    repo_blob = short_repo_summary(target)
    completion = backend.complete(
        system=_SYSTEM,
        user=f"Repository snapshot:\n\n{repo_blob}\n\nProduce the attack surface map.",
        model=model,
        max_tokens=max_tokens,
        temperature=temperature,
    )
    parsed = extract_json(completion.text) or {}
    if not isinstance(parsed, dict):
        parsed = {"summary": str(parsed)[:500]}
    return parsed, completion
