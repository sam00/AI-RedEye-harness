"""S2 — Threat-model the attack surface.

Consumes the surface produced by S1 and emits a STRIDE/OWASP-aligned threat
model that S3 uses to pick research strategies.
"""

from __future__ import annotations

from redeye.schema import StageResult
from redeye.skills.threat_modeler import build_threat_model


def run(ctx) -> StageResult:  # type: ignore[no-untyped-def]
    stage_cfg = ctx.profile.stages[ctx.stage_id]
    backend, model, temperature, max_tokens = ctx.get_backend(stage_cfg.role)

    # Pull S1's artifact off the context. Stages pass artifacts via the
    # orchestrator's running list of stage results, but for this minimal
    # implementation we re-derive what we need from the target.
    surface = ctx.artifacts.get("attack_surface", {})

    model_doc, completion = build_threat_model(
        target=ctx.target,
        attack_surface=surface,
        backend=backend,
        model=model,
        temperature=temperature,
        max_tokens=max_tokens,
        max_budget_usd=stage_cfg.max_budget_usd,
    )

    return StageResult(
        stage_id=ctx.stage_id,
        skill=stage_cfg.skill,
        artifacts={"threat_model": model_doc},
        tokens_in=completion.tokens_in,
        tokens_out=completion.tokens_out,
        cost_usd=completion.cost_usd,
    )
