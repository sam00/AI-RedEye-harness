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
from redeye.schema import StageResult

log = logging.getLogger(__name__)


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

    metrics = {
        "considered": len(ctx.findings),
        "verified": len(verified),
        "unverified": unverified_count,
        "dropped": unverified_count if strict else 0,
        "corroborated": corroborated,
        "threshold": threshold,
        "strict": strict,
    }
    return StageResult(
        stage_id=ctx.stage_id,
        skill=stage_cfg.skill,
        findings=kept,
        artifacts={"verification_metrics": metrics},
    )
