"""S3 — Strategize and prioritize the hunt.

Picks a small set of high-yield strategies (taint paths, authz boundaries,
input handlers, etc.) given the threat model. The artefact is consumed by
S4 to scope each research lens.
"""

from __future__ import annotations

from redeye.schema import StageResult
from redeye.skills.research_strategist import plan_research


def run(ctx) -> StageResult:  # type: ignore[no-untyped-def]
    stage_cfg = ctx.profile.stages[ctx.stage_id]
    backend, model, temperature, max_tokens = ctx.get_backend(stage_cfg.role)

    threat_model = ctx.artifacts.get("threat_model", {})

    plan, completion = plan_research(
        target=ctx.target,
        threat_model=threat_model,
        backend=backend,
        model=model,
        temperature=temperature,
        max_tokens=max_tokens,
        max_budget_usd=stage_cfg.max_budget_usd,
    )

    return StageResult(
        stage_id=ctx.stage_id,
        skill=stage_cfg.skill,
        artifacts={"research_plan": plan},
        tokens_in=completion.tokens_in,
        tokens_out=completion.tokens_out,
        cost_usd=completion.cost_usd,
    )
