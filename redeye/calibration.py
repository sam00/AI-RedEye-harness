"""Confidence calibration from the reviewer feedback store.

RedEye persists reviewer TP/FP marks (see :mod:`redeye.feedback.store`). Prior
versions only injected those marks into lens prompts as free text. This module
turns them into a *numeric* prior: per-CWE and per-lens reliability learned
from history, used to nudge each finding's ``confidence`` up or down before the
voting threshold and report.

The maths is deliberately simple and conservative:

- Reliability is a Laplace-smoothed true-positive rate, ``(tp + 1) / (tp + fp + 2)``,
  so a category with no history sits at the neutral 0.5.
- A key (CWE or skill) only influences a finding once it has at least
  ``MIN_OBSERVATIONS`` reviewed marks -- one angry reviewer can't tank a class.
- The adjustment is bounded: ``confidence += GAIN * (reliability - 0.5)``,
  combining the CWE and skill signals, then clamped to ``[0, 1]``.

This is a *prior*, not a verdict: a low historical TP-rate lowers confidence
(and may tip a finding below the voting threshold) but never drops it outright.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

MIN_OBSERVATIONS = 2
GAIN = 0.4
# Cap how far a single calibration can move confidence, for stability.
MAX_DELTA = 0.3


@dataclass
class Reliability:
    """TP/FP tallies keyed by CWE and by producing skill (lens)."""

    by_cwe: dict[str, list[int]] = field(default_factory=dict)  # cwe -> [tp, fp]
    by_skill: dict[str, list[int]] = field(default_factory=dict)  # skill -> [tp, fp]

    def _ratio(self, counts: list[int] | None) -> float | None:
        if not counts:
            return None
        tp, fp = counts
        if tp + fp < MIN_OBSERVATIONS:
            return None
        return (tp + 1) / (tp + fp + 2)

    def reliability_for(self, *, cwe: str | None, skill: str | None) -> float | None:
        """Combined reliability in [0, 1], or None when there's no usable history."""
        ratios = [
            r
            for r in (
                self._ratio(self.by_cwe.get((cwe or "").upper())),
                self._ratio(self.by_skill.get(skill or "")),
            )
            if r is not None
        ]
        if not ratios:
            return None
        return sum(ratios) / len(ratios)


def build_reliability(feedback: list[dict[str, Any]]) -> Reliability:
    """Aggregate reviewer marks (each with ``verdict`` TP/FP, ``cwe``, ``skill``)."""
    rel = Reliability()
    for row in feedback or []:
        verdict = str(row.get("verdict") or "").upper()
        if verdict not in {"TP", "FP"}:
            continue
        idx = 0 if verdict == "TP" else 1
        cwe = (row.get("cwe") or "").upper()
        skill = row.get("skill") or ""
        if cwe:
            rel.by_cwe.setdefault(cwe, [0, 0])[idx] += 1
        if skill:
            rel.by_skill.setdefault(skill, [0, 0])[idx] += 1
    return rel


def calibrate_findings(findings: list, feedback: list[dict[str, Any]]) -> dict[str, int]:
    """Adjust ``finding.confidence`` in place from learned reliability.

    Returns metrics: ``{"calibrated", "boosted", "reduced"}``. A no-op (all
    zeros) when there's no usable feedback.
    """
    rel = build_reliability(feedback)
    if not rel.by_cwe and not rel.by_skill:
        return {"calibrated": 0, "boosted": 0, "reduced": 0}

    calibrated = boosted = reduced = 0
    for f in findings:
        # Never re-weight a deterministically-confirmed finding.
        if "deterministic" in (getattr(f, "tags", []) or []):
            continue
        r = rel.reliability_for(cwe=getattr(f, "cwe", None), skill=getattr(f, "skill", None))
        if r is None:
            continue
        delta = GAIN * (r - 0.5)
        delta = max(-MAX_DELTA, min(MAX_DELTA, delta))
        if abs(delta) < 0.01:
            continue
        old = float(getattr(f, "confidence", 0.0) or 0.0)
        new = max(0.0, min(1.0, old + delta))
        if new == old:
            continue
        f.confidence = round(new, 4)
        f.tags.append(f"calibrated:{'+' if delta >= 0 else ''}{round(delta, 3)}")
        calibrated += 1
        if delta >= 0:
            boosted += 1
        else:
            reduced += 1
    return {"calibrated": calibrated, "boosted": boosted, "reduced": reduced}
