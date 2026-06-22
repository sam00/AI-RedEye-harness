"""S6 — Adversarial verification.

Runs the adversarial reviewer skill against each surviving finding to
produce an exploit chain and a confirm/reject judgement. The orchestrator
then runs the *separate* multi-agent voter on the same set in
:mod:`redeye.pipeline.voting`. Splitting the two means voting can be
configured independently of the per-finding adversarial pass.
"""

from __future__ import annotations

from redeye.schema import StageResult
from redeye.skills.adversarial_reviewer import review_findings


def run(ctx) -> StageResult:  # type: ignore[no-untyped-def]
    stage_cfg = ctx.profile.stages[ctx.stage_id]
    backend, model, temperature, max_tokens = ctx.get_backend(stage_cfg.role)

    refined, total = review_findings(
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
        findings=refined,
        tokens_in=total.tokens_in,
        tokens_out=total.tokens_out,
        cost_usd=total.cost_usd,
    )
