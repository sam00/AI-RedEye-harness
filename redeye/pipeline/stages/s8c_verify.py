"""S8c -- outcome verification.

Runs after S8b (PoC gate) and before S9 (emit). Attaches a deterministic,
temperature-free K-of-N verdict to every finding (see
:mod:`redeye.pipeline.verification`). In non-strict mode it only *flags*
findings; under ``params.strict`` (a.k.a. ``--require-verified``) it drops
the ones that don't clear the bar so the report contains only corroborated
findings.

Because the verdict is computed from signals other stages already produced
(grounding, taint completeness, PoC, reachability, votes), it adds no LLM
cost and works on every backend -- including ones that reject ``temperature``
where multi-agent voting is a no-op.
"""

from __future__ import annotations

import logging

from redeye.pipeline.verification import (
    SIGNAL_NAMES,
    VerificationConfig,
    verify_findings,
)
from redeye.schema import Finding, Severity, StageResult

log = logging.getLogger(__name__)


def _first_key(f: Finding) -> bool:
    """The primary 'first key': a distinct validator/adversary confirmed it."""
    return f.validator_verdict == "confirm" or any(v.verdict == "confirm" for v in f.votes)


def _second_key(f: Finding) -> bool:
    """The corroborating 'second key': an independent scanner agreed, or an
    exploit was concretely demonstrated (syntactically or by the oracle)."""
    return bool(
        f.has_external_corroboration()
        or f.has_concrete_poc()
        or getattr(f, "poc_demonstrated", False)
    )


def _apply_two_key(findings: list[Finding]) -> int:
    """Improvement #9: a finding may only *report* at HIGH/CRITICAL when it has
    two independent keys — a model confirmation AND (corroboration OR a
    demonstrated PoC). Otherwise its severity is capped at MEDIUM (never
    dropped) and it is tagged for the reviewer. Deterministic, zero LLM cost.

    Applied here at S8c — not at the S5 policy gate — because both keys depend
    on signals produced by later stages: validator/voter verdicts (S6/S6b) and
    corroboration or a demonstrated PoC (S8b/S8c). At S5 those are always
    empty, so every HIGH/CRITICAL finding would be capped.
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
    params = stage_cfg.params or {}

    n = len(SIGNAL_NAMES)
    threshold = max(1, min(int(params.get("threshold", 3)), n))
    reachable_threshold = float(params.get("reachable_threshold", 0.5))
    strict = bool(params.get("strict", params.get("require_verified", False)))
    cfg = VerificationConfig(threshold=threshold, reachable_threshold=reachable_threshold)

    # Improvement #2: fold independent-scanner agreement into the K-of-N verdict
    # *before* verifying, so corroboration counts as a signal. Zero LLM cost;
    # never aborts a scan if an external feed is malformed.
    corroborated = 0
    if getattr(ctx, "external_scans", None):
        try:
            from redeye.corroboration import annotate_findings
            from redeye.external import load_external_reports

            report = load_external_reports(ctx.external_scans)
            line_tol = int(params.get("corroboration_line_tol", 3))
            corroborated = annotate_findings(ctx.findings, report.findings, line_tol=line_tol)
        except Exception as exc:  # noqa: BLE001 - corroboration must never abort a scan
            log.warning("S8c corroboration skipped (%s)", exc)

    # Attach a VerificationResult to each finding (in place).
    verify_findings(ctx.findings, cfg)
    verified = [f for f in ctx.findings if f.verification and f.verification.verified]
    unverified_count = len(ctx.findings) - len(verified)
    kept = verified if strict else list(ctx.findings)

    # Improvement #9: two-key HIGH/CRITICAL promotion. Runs after annotation
    # and verification above so both keys (validator/votes; corroboration or
    # demonstrated PoC) are actually observable.
    two_key = bool(params.get("two_key_high_severity", False))
    if not two_key:
        # Back-compat: honour the flag if a profile still sets it on S5.
        s5_cfg = ctx.profile.stages.get("s5_policy_gate")
        s5_params = s5_cfg.params if s5_cfg is not None else {}
        two_key = bool(s5_params.get("two_key_high_severity", False))
    two_key_capped = _apply_two_key(kept) if two_key else 0

    metrics = {
        "considered": len(ctx.findings),
        "verified": len(verified),
        "unverified": unverified_count,
        "dropped": unverified_count if strict else 0,
        "corroborated": corroborated,
        "two_key_capped": two_key_capped,
        "threshold": threshold,
        "strict": strict,
    }
    return StageResult(
        stage_id=ctx.stage_id,
        skill=stage_cfg.skill,
        findings=kept,
        artifacts={"verification_metrics": metrics},
    )
