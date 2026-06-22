"""S3 skill -- pick a small set of high-yield research strategies."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from redeye.backends.base import BackendBase, CompletionResult
from redeye.skills._helpers import extract_json

_SYSTEM = """\
You are a vulnerability research strategist. Given the threat model JSON,
choose at most 5 specific research questions worth answering with a deep
read of the code. Each question should name a concrete file path or
function pattern to start from. Return JSON: {strategies: [{name, why, where}]}.
"""


def plan_research(
    *,
    target: Path,
    threat_model: dict[str, Any],
    backend: BackendBase,
    model: str,
    temperature: float | None,
    max_tokens: int,
    max_budget_usd: float,
) -> tuple[dict[str, Any], CompletionResult]:
    completion = backend.complete(
        system=_SYSTEM,
        user="Threat model:\n\n" + json.dumps(threat_model, indent=2)[:6000],
        model=model,
        max_tokens=max_tokens,
        temperature=temperature,
    )
    parsed = extract_json(completion.text) or {}
    if not isinstance(parsed, dict):
        parsed = {"strategies": []}
    return parsed, completion
