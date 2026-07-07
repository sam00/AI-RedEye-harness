"""S6.5 -- single-pass validator (TP/FP gate).

Optional stage. If the profile doesn't list ``s6b_validator`` it's skipped
entirely. If it's present, runs after multi-agent voting and before dedupe.
"""

from __future__ import annotations

from pathlib import Path

from redeye.schema import StageResult
from redeye.skills.validator import validate_findings


def _check_quoted_verdicts(findings, target: Path) -> int:
    """Improvement #7: a 'confirm' verdict should quote real source. Tag any
    confirm whose rationale doesn't quote code that actually exists in the
    cited file as ``unquoted-verdict`` so reviewers know the judge asserted
    without grounding. Tag-only; never drops. Returns count tagged.
    """
    from redeye.precision import quote_is_grounded

    tagged = 0
    for f in findings:
        if f.validator_verdict != "confirm" or not f.validator_rationale or not f.locations:
            continue
        loc = f.locations[0]
        cited = (target / loc.path).resolve()
        try:
            cited.relative_to(target.resolve())
            source = cited.read_text(encoding="utf-8", errors="replace")
        except (OSError, ValueError):
            continue
        if not quote_is_grounded(f.validator_rationale, source):
            if "unquoted-verdict" not in f.tags:
                f.tags.append("unquoted-verdict")
            tagged += 1
    return tagged


def run(ctx) -> StageResult:  # type: ignore[no-untyped-def]
    stage_cfg = ctx.profile.stages[ctx.stage_id]
    params = stage_cfg.params or {}
    backend, model, temperature, max_tokens = ctx.get_backend(stage_cfg.role)

    kept, rejected, totals = validate_findings(
        findings=ctx.findings,
        target=ctx.target,
        backend=backend,
        model=model,
        temperature=temperature,
        max_tokens=max_tokens,
        max_budget_usd=stage_cfg.max_budget_usd,
    )

    unquoted = 0
    if bool(params.get("require_quoted_verdict", False)):
        unquoted = _check_quoted_verdicts(kept, ctx.target)

    return StageResult(
        stage_id=ctx.stage_id,
        skill=stage_cfg.skill,
        findings=kept,
        artifacts={
            "validator_kept": len(kept),
            "validator_rejected": len(rejected),
            "rejected_ids": [f.id for f in rejected],
            "unquoted_verdicts": unquoted,
        },
        tokens_in=totals.tokens_in,
        tokens_out=totals.tokens_out,
        cost_usd=totals.cost_usd,
    )
