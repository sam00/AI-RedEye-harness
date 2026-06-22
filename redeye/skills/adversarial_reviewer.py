"""S6 skill -- adversarial reviewer.

Per finding, ask the adversarial role to write the reachability trace and
confirm/reject the report. The adversarial pass *refines* the finding (it
appends to the attack chain and may bump confidence) but does not delete
findings -- voting in :mod:`redeye.pipeline.voting` is what decides what
survives to S7.
"""

from __future__ import annotations

import json
from pathlib import Path

from redeye.backends.base import BackendBase
from redeye.schema import Finding
from redeye.skills._helpers import CompletionTotals, extract_json

_SYSTEM = """\
You are an adversarial reviewer. For the given candidate finding, write the
reachability trace from an external attacker to the sink. If reachability
is implausible, say so. Reply JSON: {confirm: bool, attack_chain: [...],
notes: "...", confidence: 0.0-1.0}.
"""


def review_findings(
    *,
    findings: list[Finding],
    target: Path,
    backend: BackendBase,
    model: str,
    temperature: float | None,
    max_tokens: int,
    max_budget_usd: float,
) -> tuple[list[Finding], CompletionTotals]:
    refined: list[Finding] = []
    totals = CompletionTotals()
    for f in findings:
        prompt = (
            f"Title: {f.title}\nSeverity: {f.severity.value}\nCWE: {f.cwe or 'unknown'}\n"
            f"Locations: " + "; ".join(f"{loc.path}:{loc.start_line}" for loc in f.locations)
            + f"\n\nDescription:\n{f.description}\n\n"
            f"Existing attack chain:\n" + json.dumps(f.attack_chain, indent=2)
        )
        completion = backend.complete(
            system=_SYSTEM,
            user=prompt,
            model=model,
            max_tokens=max_tokens,
            temperature=temperature,
        )
        totals.add(
            tokens_in=completion.tokens_in,
            tokens_out=completion.tokens_out,
            cost_usd=completion.cost_usd,
        )
        parsed = extract_json(completion.text) or {}
        if isinstance(parsed, dict):
            chain = parsed.get("attack_chain") or []
            if isinstance(chain, list):
                f.attack_chain = [str(x) for x in chain][:30]
            note = parsed.get("notes")
            if note:
                f.description = (f.description + f"\n\nAdversarial review: {note}")[:4000]
            new_conf = parsed.get("confidence")
            if isinstance(new_conf, (int, float)):
                f.confidence = max(0.0, min(1.0, float(new_conf)))
            f.revision += 1
        refined.append(f)
    return refined, totals
