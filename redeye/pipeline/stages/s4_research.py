"""S4 — Research by specialized lens.

Runs each enabled lens (language / crypto / logic / access_control / iac)
against the target. Lenses are independent — they run sequentially in this
implementation but are easy to parallelise (``concurrent.futures``) once
budgets are wired.

Each lens emits zero or more :class:`Finding`s. They all flow into the
running set unmodified; deduplication and adversarial verification happen
later.
"""

from __future__ import annotations

from redeye.schema import Finding, StageResult
from redeye.skills import (
    lens_access_control,
    lens_crypto,
    lens_iac,
    lens_language,
    lens_logic,
)
from redeye.structural import derive_deterministic_findings

_LENSES = {
    "language": lens_language.run,
    "crypto": lens_crypto.run,
    "logic": lens_logic.run,
    "access_control": lens_access_control.run,
    "iac": lens_iac.run,
}


def run(ctx) -> StageResult:  # type: ignore[no-untyped-def]
    stage_cfg = ctx.profile.stages[ctx.stage_id]
    backend, model, temperature, max_tokens = ctx.get_backend(stage_cfg.role)
    enabled = stage_cfg.params.get("lenses") or list(_LENSES.keys())

    findings: list[Finding] = []
    total_in = total_out = 0
    total_cost = 0.0
    per_lens_count: dict[str, int] = {}

    next_id = len(ctx.findings)
    for lens_name in enabled:
        lens_fn = _LENSES.get(lens_name)
        if lens_fn is None:
            continue
        lens_findings, completion = lens_fn(
            target=ctx.target,
            attack_surface=ctx.artifacts.get("attack_surface", {}),
            research_plan=ctx.artifacts.get("research_plan", {}),
            backend=backend,
            model=model,
            temperature=temperature,
            max_tokens=max_tokens,
            max_budget_usd=stage_cfg.max_budget_usd / max(1, len(enabled)),
            extra_system=ctx.custom_prompt,
            feedback=ctx.feedback,
            # The structural pre-index produced by S1b. Lenses cite real
            # paths from this list rather than imagining them.
            structural_index=ctx.artifacts.get("structural_index"),
        )
        for f in lens_findings:
            next_id += 1
            f.id = f.id or f"F-{next_id:04d}"
            f.skill = lens_name
            f.stage = ctx.stage_id
            findings.append(f)
        per_lens_count[lens_name] = len(lens_findings)
        total_in += completion.tokens_in
        total_out += completion.tokens_out
        total_cost += completion.cost_usd

    # --- Deterministic high-signal detectors (no LLM cost) ----------------
    # The LLM lenses can be unreliable on weak/local models -- and the
    # single-pass validator may then veto their true positives. To guarantee
    # the unambiguous, regex-confirmable classes (hardcoded credentials,
    # string-formatted SQL reaching a sink, user-controlled file paths) are
    # always reported, we assert them deterministically here. They carry a
    # ``deterministic`` tag that the validator/PoC gates honour as a floor.
    det_count = 0
    if ctx.scope is not None and ctx.scope.files:
        existing = {
            (f.cwe, loc.path, loc.start_line)
            for f in findings
            for loc in f.locations
        }
        det_findings = derive_deterministic_findings(
            target=ctx.target, file_paths=ctx.scope.files
        )
        for f in det_findings:
            loc = f.locations[0]
            # Dedupe against a lens finding citing the same CWE within +/-3 lines.
            if any(
                k[0] == f.cwe and k[1] == loc.path and abs(k[2] - loc.start_line) <= 3
                for k in existing
            ):
                continue
            next_id += 1
            f.id = f"F-{next_id:04d}"
            findings.append(f)
            det_count += 1

    per_lens_count["deterministic"] = det_count

    return StageResult(
        stage_id=ctx.stage_id,
        skill=stage_cfg.skill,
        findings=findings,
        artifacts={"per_lens_count": per_lens_count},
        tokens_in=total_in,
        tokens_out=total_out,
        cost_usd=total_cost,
    )
