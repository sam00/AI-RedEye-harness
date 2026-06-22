"""Multi-agent voting for false-positive suppression.

Each finding is shown to N voter roles. A finding survives if at least
``quorum`` voters return ``confirm``. Voters whose backend rejects
``temperature`` (e.g. the `cli` backend) are skipped silently — voting
needs sampling diversity to be meaningful.

The output is two lists: ``kept`` (above quorum) and ``dropped``
(below quorum). Dropped findings are not deleted — they go into the
report's appendix so reviewers can second-guess the model.
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass

from redeye.backends import BACKENDS, BackendBase
from redeye.config import Profile
from redeye.schema import Finding, Vote

_VOTE_SYSTEM = """\
You are an adversarial reviewer of a candidate security finding produced by another AI.
Decide whether the finding is a true positive (return "confirm"), a false positive
("reject"), or genuinely uncertain ("uncertain"). Be conservative: only "confirm" if
the reachability is plausible and the impact is real.

Reply ONLY with a JSON object: {"verdict": "confirm|reject|uncertain", "rationale": "..."}.
"""


@dataclass
class VotingOutcome:
    kept: list[Finding]
    dropped: list[Finding]


def _parse_verdict(text: str) -> tuple[str, str]:
    """Pull the JSON object out of a possibly-noisy LLM reply."""
    m = re.search(r"\{[^{}]*\"verdict\"[^{}]*\}", text, flags=re.DOTALL)
    if not m:
        return "uncertain", text.strip()[:500]
    try:
        obj = json.loads(m.group(0))
        v = str(obj.get("verdict", "uncertain")).lower()
        if v not in {"confirm", "reject", "uncertain"}:
            v = "uncertain"
        return v, str(obj.get("rationale", ""))[:1500]
    except json.JSONDecodeError:
        return "uncertain", text.strip()[:500]


def _backend_for(role_name: str, profile: Profile) -> tuple[BackendBase, str, float | None, int]:
    role = profile.roles[role_name]
    factory = BACKENDS[role.via]
    backend = factory({})
    return backend, role.model, role.temperature, role.max_tokens


def vote_on_findings(findings: list[Finding], profile: Profile) -> VotingOutcome:
    """Run the configured voters across each finding, partitioning by quorum.

    If voting is disabled in the profile (or the profile names no voters),
    every finding is kept untouched.
    """
    cfg = profile.voting
    if not cfg.enabled or not cfg.voters or not findings:
        return VotingOutcome(kept=list(findings), dropped=[])

    kept: list[Finding] = []
    dropped: list[Finding] = []
    for finding in findings:
        confirms = 0
        for voter_role in cfg.voters:
            if voter_role not in profile.roles:
                continue
            backend, model, temperature, max_tokens = _backend_for(voter_role, profile)
            user_prompt = (
                f"Finding title: {finding.title}\n"
                f"Severity: {finding.severity.value}\n"
                f"CWE: {finding.cwe or 'unknown'}\n"
                f"Locations: "
                + "; ".join(f"{loc.path}:{loc.start_line}" for loc in finding.locations)
                + f"\n\nDescription:\n{finding.description}\n\n"
                f"Attack chain:\n- " + "\n- ".join(finding.attack_chain or ["(none provided)"])
            )
            try:
                result = backend.complete(
                    system=_VOTE_SYSTEM,
                    user=user_prompt,
                    model=model,
                    max_tokens=max_tokens,
                    temperature=temperature,
                )
            except Exception as exc:  # noqa: BLE001
                finding.votes.append(
                    Vote(role=voter_role, model=model, verdict="uncertain", rationale=f"backend error: {exc}")
                )
                continue
            verdict, rationale = _parse_verdict(result.text)
            finding.votes.append(Vote(role=voter_role, model=model, verdict=verdict, rationale=rationale))
            if verdict == "confirm":
                confirms += 1

        if confirms >= cfg.quorum:
            kept.append(finding)
        else:
            dropped.append(finding)
    return VotingOutcome(kept=kept, dropped=dropped)
