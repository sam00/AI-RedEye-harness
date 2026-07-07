"""S5 — Policy gate.

Cheap, deterministic guard rails that don't need a full adversarial review:

- Drop findings outside the configured severity floor.
- Drop findings whose only location is in a test file or vendor directory
  (these are usually false positives in coverage tooling).
- Drop findings whose remediation field is empty (a sign the lens didn't
  finish).

This is intentionally a *non-LLM* stage: it costs nothing and gives
operators a stable knob to silence whole classes of noise.
"""

from __future__ import annotations

import logging

from redeye.schema import Finding, Severity, StageResult

log = logging.getLogger(__name__)

_TEST_PATH_HINTS = ("/test/", "/tests/", "/__tests__/", "/spec/", "_test.py", "_spec.rb")
_VENDOR_HINTS = ("/vendor/", "/node_modules/", "/third_party/", "/external/")


def _drop(finding: Finding, reason: str) -> None:
    finding.tags.append(f"dropped:s5:{reason}")


def _second_key(f: Finding) -> bool:
    """The corroborating 'second key': an independent scanner agreed, or an
    exploit was concretely demonstrated (syntactically or by the oracle)."""
    return bool(
        f.has_external_corroboration()
        or f.has_concrete_poc()
        or getattr(f, "poc_demonstrated", False)
    )


def _first_key(f: Finding) -> bool:
    """The primary 'first key': a distinct validator/adversary confirmed it."""
    return f.validator_verdict == "confirm" or any(v.verdict == "confirm" for v in f.votes)


def _apply_two_key(findings: list[Finding]) -> int:
    """Improvement #9: a finding may only *report* at HIGH/CRITICAL when it has
    two independent keys — a model confirmation AND (corroboration OR a
    demonstrated PoC). Otherwise its severity is capped at MEDIUM (never
    dropped) and it is tagged for the reviewer. Deterministic, zero LLM cost.
    Returns the number of findings capped.
    """
    capped = 0
    for f in findings:
        if f.severity.numeric < Severity.HIGH.numeric:
            continue
        if _first_key(f) and _second_key(f):
            continue
        f.severity = Severity.MEDIUM
        if "capped:two-key" not in f.tags:
            f.tags.append("capped:two-key")
        capped += 1
    return capped


def run(ctx) -> StageResult:  # type: ignore[no-untyped-def]
    stage_cfg = ctx.profile.stages[ctx.stage_id]
    severity_floor_str = stage_cfg.params.get("severity_floor", "low")
    two_key = bool(stage_cfg.params.get("two_key_high_severity", False))
    try:
        severity_floor = Severity(severity_floor_str).numeric
    except ValueError:
        severity_floor = Severity.LOW.numeric

    # Enterprise two-key promotion runs first so the severity floor sees the
    # capped severity, not the model's optimistic one.
    capped = _apply_two_key(ctx.findings) if two_key else 0

    kept: list[Finding] = []
    for f in ctx.findings:
        if f.severity.numeric < severity_floor:
            _drop(f, "below_floor")
            continue
        # Test-file / vendor heuristic
        primary_path = f.locations[0].path.replace("\\", "/").lower() if f.locations else ""
        if any(h in primary_path for h in _TEST_PATH_HINTS):
            _drop(f, "test_path")
            continue
        if any(h in primary_path for h in _VENDOR_HINTS):
            _drop(f, "vendor_path")
            continue
        if not f.remediation:
            _drop(f, "no_remediation")
            continue
        kept.append(f)

    log.info("S5 policy gate kept %d / %d findings", len(kept), len(ctx.findings))
    return StageResult(
        stage_id=ctx.stage_id,
        skill=stage_cfg.skill,
        findings=kept,
        artifacts={
            "input_count": len(ctx.findings),
            "kept_count": len(kept),
            "two_key_capped": capped,
        },
    )
