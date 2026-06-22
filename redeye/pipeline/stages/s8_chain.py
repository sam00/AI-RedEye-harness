"""S8 — Chain construction & remediation polish.

Walks each finding and (a) ensures it has a coherent attack chain narrative,
(b) fills in remediation guidance if S4 left it sparse, and (c) tags any
findings that look like they could chain into another (e.g. a CWE-79 in an
admin panel and a CWE-352 missing CSRF token combine for a stored-XSS-CSRF
worm chain).
"""

from __future__ import annotations

from redeye.schema import StageResult
from redeye.skills.exploit_strategist import enrich_findings


def run(ctx) -> StageResult:  # type: ignore[no-untyped-def]
    stage_cfg = ctx.profile.stages[ctx.stage_id]
    backend, model, temperature, max_tokens = ctx.get_backend(stage_cfg.role)

    enriched, total = enrich_findings(
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
        findings=enriched,
        tokens_in=total.tokens_in,
        tokens_out=total.tokens_out,
        cost_usd=total.cost_usd,
    )
