"""S6.5 -- single-pass validator (TP/FP gate).

Optional stage. If the profile doesn't list ``s6b_validator`` it's skipped
entirely. If it's present, runs after multi-agent voting and before dedupe.
"""

from __future__ import annotations

from redeye.schema import StageResult
from redeye.skills.validator import validate_findings


def run(ctx) -> StageResult:  # type: ignore[no-untyped-def]
    stage_cfg = ctx.profile.stages[ctx.stage_id]
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

    return StageResult(
        stage_id=ctx.stage_id,
        skill=stage_cfg.skill,
        findings=kept,
        artifacts={
            "validator_kept": len(kept),
            "validator_rejected": len(rejected),
            "rejected_ids": [f.id for f in rejected],
        },
        tokens_in=totals.tokens_in,
        tokens_out=totals.tokens_out,
        cost_usd=totals.cost_usd,
    )
