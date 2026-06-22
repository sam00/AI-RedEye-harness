"""S8b -- PoC gate.

Runs after S8 (chain) and before S9 (emit). Demands a concrete exploit
demonstration; placeholder PoCs trigger a one-notch severity downgrade.
"""

from __future__ import annotations

from redeye.schema import StageResult
from redeye.skills.poc_gate import gate_findings


def run(ctx) -> StageResult:  # type: ignore[no-untyped-def]
    stage_cfg = ctx.profile.stages[ctx.stage_id]
    strict = bool(stage_cfg.params.get("strict", False))
    backend, model, temperature, max_tokens = ctx.get_backend(stage_cfg.role)

    findings, totals, metrics = gate_findings(
        findings=ctx.findings,
        target=ctx.target,
        backend=backend,
        model=model,
        temperature=temperature,
        max_tokens=max_tokens,
        max_budget_usd=stage_cfg.max_budget_usd,
    )

    if strict:
        kept = [f for f in findings if f.has_concrete_poc()]
        metrics["dropped_for_no_poc"] = len(findings) - len(kept)
    else:
        kept = findings

    return StageResult(
        stage_id=ctx.stage_id,
        skill=stage_cfg.skill,
        findings=kept,
        artifacts={"poc_metrics": metrics, "strict": strict},
        tokens_in=totals.tokens_in,
        tokens_out=totals.tokens_out,
        cost_usd=totals.cost_usd,
    )
