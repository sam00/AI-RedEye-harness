"""Two-key HIGH/CRITICAL promotion tests.

The policy is applied at S8c (not the S5 policy gate) because its keys depend
on signals produced by later stages: validator/voter verdicts (S6/S6b) and
external corroboration or a demonstrated PoC (S8b/S8c). These tests run the
real S8c stage with ``two_key_high_severity`` enabled and check that a finding
holding both keys keeps its severity while an uncorroborated one is capped to
MEDIUM (never dropped).
"""

from __future__ import annotations

from types import SimpleNamespace
from typing import Any

from redeye.pipeline.stages import s8c_verify
from redeye.schema import Finding, Location, Severity


def _finding(fid: str, **overrides: Any) -> Finding:
    base: dict[str, Any] = dict(
        id=fid,
        title="t",
        severity=Severity.HIGH,
        cwe="CWE-89",
        description="d",
        locations=[Location(path="src/app.py", start_line=10)],
        remediation="fix",
        confidence=0.9,
    )
    base.update(overrides)
    return Finding(**base)


def _ctx(findings: list[Finding], params: dict[str, Any]) -> SimpleNamespace:
    stage_cfg = SimpleNamespace(skill="outcome_verifier", params=params)
    profile = SimpleNamespace(stages={"s8c_verify": stage_cfg})
    return SimpleNamespace(
        stage_id="s8c_verify", profile=profile, findings=findings, external_scans=[]
    )


def test_two_key_caps_uncorroborated_high_but_keeps_corroborated() -> None:
    corroborated = _finding("F-0001", validator_verdict="confirm", externally_corroborated=True)
    uncorroborated = _finding("F-0002")
    ctx = _ctx(
        [corroborated, uncorroborated],
        {"threshold": 3, "strict": False, "two_key_high_severity": True},
    )

    result = s8c_verify.run(ctx)

    # Both keys present (validator confirm + external corroboration): untouched.
    assert corroborated.severity == Severity.HIGH
    assert "capped:two-key" not in corroborated.tags
    # Neither key: capped to MEDIUM, tagged, but never dropped.
    assert uncorroborated.severity == Severity.MEDIUM
    assert "capped:two-key" in uncorroborated.tags
    assert {f.id for f in result.findings} == {"F-0001", "F-0002"}
    assert result.artifacts["verification_metrics"]["two_key_capped"] == 1


def test_two_key_accepts_demonstrated_poc_as_second_key() -> None:
    finding = _finding("F-0001", validator_verdict="confirm", poc_demonstrated=True)
    s8c_verify.run(_ctx([finding], {"two_key_high_severity": True}))
    assert finding.severity == Severity.HIGH
    assert "capped:two-key" not in finding.tags


def test_two_key_disabled_leaves_high_severity_alone() -> None:
    finding = _finding("F-0001")
    s8c_verify.run(_ctx([finding], {"threshold": 3, "strict": False}))
    assert finding.severity == Severity.HIGH
    assert "capped:two-key" not in finding.tags
