"""Confidence calibration from reviewer feedback."""

from __future__ import annotations

from redeye.calibration import build_reliability, calibrate_findings
from redeye.schema import Finding, Severity


def _finding(cwe: str, skill: str, confidence: float) -> Finding:
    return Finding(
        id="F-0001",
        title="t",
        severity=Severity.MEDIUM,
        cwe=cwe,
        description="d",
        confidence=confidence,
        skill=skill,
    )


def test_no_feedback_is_noop() -> None:
    f = _finding("CWE-89", "language", 0.7)
    metrics = calibrate_findings([f], [])
    assert metrics == {"calibrated": 0, "boosted": 0, "reduced": 0}
    assert f.confidence == 0.7


def test_reliability_smoothing_threshold() -> None:
    # One mark is below MIN_OBSERVATIONS -> no usable ratio.
    rel = build_reliability([{"verdict": "FP", "cwe": "CWE-79", "skill": "language"}])
    assert rel.reliability_for(cwe="CWE-79", skill="language") is None


def test_many_fps_reduce_confidence() -> None:
    feedback = [{"verdict": "FP", "cwe": "CWE-79", "skill": "language"} for _ in range(6)]
    f = _finding("CWE-79", "language", 0.8)
    metrics = calibrate_findings([f], feedback)
    assert metrics["reduced"] == 1
    assert f.confidence < 0.8
    assert any(t.startswith("calibrated:") for t in f.tags)


def test_many_tps_boost_confidence() -> None:
    feedback = [{"verdict": "TP", "cwe": "CWE-89", "skill": "language"} for _ in range(6)]
    f = _finding("CWE-89", "language", 0.5)
    metrics = calibrate_findings([f], feedback)
    assert metrics["boosted"] == 1
    assert f.confidence > 0.5


def test_deterministic_findings_are_not_calibrated() -> None:
    feedback = [{"verdict": "FP", "cwe": "CWE-89", "skill": "language"} for _ in range(6)]
    f = _finding("CWE-89", "language", 0.9)
    f.tags.append("deterministic")
    calibrate_findings([f], feedback)
    assert f.confidence == 0.9
