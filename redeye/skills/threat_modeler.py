"""S2 skill -- STRIDE/OWASP threat modeling against the S1 attack surface."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from redeye.backends.base import BackendBase, CompletionResult
from redeye.skills._helpers import extract_json

_SYSTEM = """\
You are doing STRIDE threat modeling for a service. Given the attack surface
JSON, return a JSON object with: actors (list), trust_boundaries (list),
stride (list of {category, asset, score, note}), top_risks (list of strings).
Be terse. The downstream consumer is automated tooling, not humans.
"""


def build_threat_model(
    *,
    target: Path,
    attack_surface: dict[str, Any],
    backend: BackendBase,
    model: str,
    temperature: float | None,
    max_tokens: int,
    max_budget_usd: float,
) -> tuple[dict[str, Any], CompletionResult]:
    completion = backend.complete(
        system=_SYSTEM,
        user="Attack surface:\n\n" + json.dumps(attack_surface, indent=2)[:6000],
        model=model,
        max_tokens=max_tokens,
        temperature=temperature,
    )
    parsed = extract_json(completion.text) or {}
    if not isinstance(parsed, dict):
        parsed = {"summary": str(parsed)[:500]}
    return parsed, completion
