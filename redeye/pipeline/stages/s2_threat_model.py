"""S2 — Threat-model the attack surface.

Consumes the surface produced by S1 and emits a STRIDE/OWASP-aligned threat
model that S3 uses to pick research strategies.
"""

from __future__ import annotations

from redeye.schema import StageResult
from redeye.skills.threat_modeler import build_threat_model


def run(ctx) -> StageResult:  # type: ignore[no-untyped-def]
    stage_cfg = ctx.profile.stages[ctx.stage_id]

    # `enabled: false` skips threat modeling entirely (no LLM call).
    if stage_cfg.params.get("enabled", True) is False:
        return StageResult(
            stage_id=ctx.stage_id,
            skill=stage_cfg.skill,
            artifacts={"threat_model": {}, "threat_model_skipped": True},
        )

    backend, model, temperature, max_tokens = ctx.get_backend(stage_cfg.role)

    # S1 attack surface + S1b structural index are read off the running
    # artifacts the orchestrator propagates forward.
    surface = ctx.artifacts.get("attack_surface", {})
    structural_index = ctx.artifacts.get("structural_index", {})

    model_doc, completion = build_threat_model(
        target=ctx.target,
        attack_surface=surface,
        backend=backend,
        model=model,
        temperature=temperature,
        max_tokens=max_tokens,
        max_budget_usd=stage_cfg.max_budget_usd,
        structural_index=structural_index,
        params=stage_cfg.params,
    )

    return StageResult(
        stage_id=ctx.stage_id,
        skill=stage_cfg.skill,
        artifacts={"threat_model": model_doc},
        tokens_in=completion.tokens_in,
        tokens_out=completion.tokens_out,
        cost_usd=completion.cost_usd,
    )
