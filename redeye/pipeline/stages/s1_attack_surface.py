"""S1 — Explore the attack surface.

The first stage walks the target repo, identifies entrypoints, sensitive
sinks, auth boundaries, and any CMDB metadata, then asks the surveyor LLM
to summarise. Its only output is an ``artifacts["attack_surface"]`` map that
S2 and S3 read.
"""

from __future__ import annotations

from redeye.schema import StageResult
from redeye.skills.attack_surface_mapper import map_attack_surface


def run(ctx) -> StageResult:  # type: ignore[no-untyped-def]
    stage_cfg = ctx.profile.stages[ctx.stage_id]
    backend, model, temperature, max_tokens = ctx.get_backend(stage_cfg.role)

    surface, completion = map_attack_surface(
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
        artifacts={"attack_surface": surface},
        tokens_in=completion.tokens_in,
        tokens_out=completion.tokens_out,
        cost_usd=completion.cost_usd,
    )
