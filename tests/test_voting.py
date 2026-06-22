"""Voting partition tests."""

from __future__ import annotations

from redeye.config import load_profile
from redeye.pipeline.voting import vote_on_findings
from redeye.schema import Finding, Location, Severity


def _f(idx: int) -> Finding:
    return Finding(
        id=f"F-{idx:04d}",
        title=f"finding {idx}",
        severity=Severity.HIGH,
        cwe="CWE-89",
        description="x",
        locations=[Location(path="src/x.py", start_line=1)],
        attack_chain=["entry", "sink"],
        remediation="parameterize",
        confidence=0.6,
    )


def test_voting_disabled_keeps_everything() -> None:
    profile = load_profile("default")  # voting disabled in default
    findings = [_f(1), _f(2)]
    outcome = vote_on_findings(findings, profile)
    assert len(outcome.kept) == 2
    assert outcome.dropped == []


def test_voting_enabled_partitions() -> None:
    profile = load_profile("mock")  # voting enabled, quorum=1, mock voters
    findings = [_f(1), _f(2)]
    outcome = vote_on_findings(findings, profile)
    # Mock backend always emits "confirm" for adversarial-style prompts,
    # so all findings should be kept.
    assert len(outcome.kept) + len(outcome.dropped) == 2
    for f in outcome.kept:
        assert f.votes  # each kept finding records its votes
