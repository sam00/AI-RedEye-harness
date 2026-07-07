"""S8b -- PoC gate.

Runs after S8 (chain) and before S9 (emit). Demands a concrete exploit
demonstration; placeholder PoCs trigger a one-notch severity downgrade.
"""

from __future__ import annotations

from redeye.poc_oracle import evaluate as oracle_evaluate
from redeye.schema import Evidence, StageResult
from redeye.skills.poc_gate import gate_findings


def _run_oracle(findings) -> int:
    """Improvement #6: prove the PoC payload actually subverts the sink.

    A ``demonstrated`` verdict sets ``poc_demonstrated`` and appends a passing
    ``poc_runnable`` Evidence row -- a strong TP signal consumed by S8c and the
    two-key promotion policy. Never drops a finding; only adds confidence.
    Returns the number of findings whose PoC the oracle demonstrated.
    """
    demonstrated = 0
    for f in findings:
        if not f.poc or not (f.poc.payload or "").strip():
            continue
        verdict = oracle_evaluate(f.poc.payload, f.cwe)
        if verdict.demonstrated:
            f.poc_demonstrated = True
            demonstrated += 1
            f.evidence.append(
                Evidence(
                    kind="poc_runnable",
                    check="pass",
                    detail=f"oracle[{verdict.vuln_class}]: {verdict.reason}",
                )
            )
            if "poc-demonstrated" not in f.tags:
                f.tags.append("poc-demonstrated")
        elif verdict.vuln_class not in ("unsupported", "empty"):
            f.evidence.append(
                Evidence(
                    kind="poc_runnable",
                    check="fail",
                    detail=f"oracle[{verdict.vuln_class}]: {verdict.reason}",
                )
            )
    return demonstrated


def run(ctx) -> StageResult:  # type: ignore[no-untyped-def]
    stage_cfg = ctx.profile.stages[ctx.stage_id]
    strict = bool(stage_cfg.params.get("strict", False))
    oracle_enabled = bool(stage_cfg.params.get("oracle", True))
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

    if oracle_enabled:
        metrics["poc_demonstrated"] = _run_oracle(findings)

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
