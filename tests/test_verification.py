"""Tests for the deterministic outcome-verification core (S8c)."""

from __future__ import annotations

import pytest

from redeye.pipeline.verification import (
    VerificationConfig,
    deterministic_signals,
    verify_finding,
    verify_findings,
)
from redeye.schema import (
    Finding,
    Location,
    ProofOfConcept,
    Severity,
    TaintFlow,
    Vote,
)


def _finding(**kw) -> Finding:
    base = dict(
        id="F-0001",
        title="SQL injection in users handler",
        severity=Severity.HIGH,
        description="Unsanitized request param flows into a SQL string.",
        locations=[Location(path="app/users.py", start_line=42)],
    )
    base.update(kw)
    return Finding(**base)


def _strong_finding() -> Finding:
    return _finding(
        grounded=True,
        reachability=0.9,
        taint=TaintFlow(source="request.json['q']", sink="db.execute(...)"),
        poc=ProofOfConcept(payload="' OR '1'='1", invocation="curl ...", is_concrete=True),
        votes=[Vote(role="adversary", model="m", verdict="confirm", rationale="reachable")],
    )


def test_all_signals_pass_is_verified():
    sig = deterministic_signals(_strong_finding())
    assert all(sig.values())
    res = verify_finding(_strong_finding())
    assert res.verified is True
    assert res.score == 1.0
    assert res.method == "deterministic"
    assert set(res.signals) == {
        "grounded",
        "taint_complete",
        "concrete_poc",
        "reachable",
        "vote_confirmed",
    }


def test_empty_finding_not_verified():
    res = verify_finding(_finding())
    assert res.verified is False
    assert res.score == 0.0


def test_threshold_boundary():
    # exactly 3 signals: grounded + taint_complete + vote_confirmed
    f = _finding(
        grounded=True,
        taint=TaintFlow(source="x", sink="y"),
        votes=[Vote(role="a", model="m", verdict="confirm", rationale="")],
    )
    assert verify_finding(f, VerificationConfig(threshold=3)).verified is True
    assert verify_finding(f, VerificationConfig(threshold=4)).verified is False


def test_reachable_threshold():
    f = _finding(reachability=0.4)
    assert deterministic_signals(f, reachable_threshold=0.5)["reachable"] is False
    assert deterministic_signals(f, reachable_threshold=0.3)["reachable"] is True


def test_validator_confirm_counts_as_vote():
    assert deterministic_signals(_finding(validator_verdict="confirm"))["vote_confirmed"] is True
    assert deterministic_signals(_finding(validator_verdict="reject"))["vote_confirmed"] is False


def test_grounding_via_evidence_helper():
    from redeye.schema import Evidence

    f = _finding(evidence=[Evidence(kind="snippet_match", check="pass", detail="line 42")])
    assert deterministic_signals(f)["grounded"] is True


def test_verify_findings_attaches_in_place():
    findings = [_strong_finding(), _finding()]
    out = verify_findings(findings)
    assert out is findings
    assert findings[0].verification is not None and findings[0].verification.verified
    assert findings[1].verification is not None and not findings[1].verification.verified


def test_invalid_threshold_raises():
    with pytest.raises(ValueError):
        VerificationConfig(threshold=99)
    with pytest.raises(ValueError):
        VerificationConfig(threshold=0)
