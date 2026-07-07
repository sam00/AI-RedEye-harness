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

# Lens gating -- a lens is skipped when the structural inventory has zero
# sinks/secrets whose CWE prefix matches the lens's interest. Saves an LLM
# call per empty category.
_LENS_RELEVANT_CWES: dict[str, frozenset[str]] = {
    "language": frozenset(
        {
            "CWE-89",
            "CWE-78",
            "CWE-95",
            "CWE-502",
            "CWE-22",
            "CWE-611",
            "CWE-918",
            "CWE-79",
            "CWE-943",
            "CWE-601",
            "CWE-1336",
        }
    ),
    "crypto": frozenset({"CWE-327", "CWE-329", "CWE-338", "CWE-295", "CWE-347", "CWE-798"}),
    "logic": frozenset(),  # always run -- logic bugs rarely have a regex signature
    "access_control": frozenset(),  # always run -- routes themselves are the trigger
    "iac": frozenset(),  # always run; gated below by file-extension presence
}


def _lens_should_run(lens_name: str, inventory: dict | None, scope) -> bool:  # type: ignore[no-untyped-def]
    """Decide whether to invoke ``lens_name`` given the structural inventory.

    Returns True if we don't know enough to skip (conservative default).
    """
    if not inventory:
        return True
    cwe_filter = _LENS_RELEVANT_CWES.get(lens_name)
    if cwe_filter is None or not cwe_filter:
        # No CWE filter -> always run. iac lens needs a file-extension check.
        if lens_name == "iac" and scope is not None:
            iac_exts = {".tf", ".yml", ".yaml"}
            iac_names = {"Dockerfile", "docker-compose.yml", "docker-compose.yaml"}
            for p in scope.files:
                if p.suffix.lower() in iac_exts or p.name in iac_names:
                    return True
            return False
        return True
    # Check the inventory's sinks + secrets for any CWE in cwe_filter
    sinks = inventory.get("sinks") or []
    for s in sinks:
        if s.get("cwe") in cwe_filter:
            return True
    if lens_name == "crypto":
        secrets = inventory.get("secrets") or []
        if secrets:
            return True
    return False


def run(ctx) -> StageResult:  # type: ignore[no-untyped-def]
    stage_cfg = ctx.profile.stages[ctx.stage_id]
    backend, model, temperature, max_tokens = ctx.get_backend(stage_cfg.role)
    enabled = stage_cfg.params.get("lenses") or list(_LENSES.keys())

    # Lens gating: drop lenses whose CWE family doesn't appear in the
    # structural inventory we built in S1b. The orchestrator still records
    # them under per_lens_count = 0 ("skipped") so operators see why.
    inventory = ctx.artifacts.get("structural_index")
    skipped: list[str] = []
    active = []
    for name in enabled:
        if _lens_should_run(name, inventory, ctx.scope):
            active.append(name)
        else:
            skipped.append(name)
    enabled = active

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
        existing = {(f.cwe, loc.path, loc.start_line) for f in findings for loc in f.locations}
        det_findings = derive_deterministic_findings(target=ctx.target, file_paths=ctx.scope.files)
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
    # Record what we skipped so the report can attribute "no findings" to
    # absence-of-sinks rather than absence-of-investigation.
    for s in skipped:
        per_lens_count[f"{s}:skipped"] = 0

    # --- Per-finding provenance (improvement #10, no LLM cost) -------------
    # Stamp every finding with model + prompt-context hash + sampling params +
    # structural-index hash so any finding is reproducible and auditable. The
    # stamp lands in Finding.provenance and flows into run_manifest.json.
    import json as _json

    from redeye.provenance import stamp_findings

    _structural = ctx.artifacts.get("structural_index")
    _prompt_ctx = _json.dumps(
        {
            "research_plan": ctx.artifacts.get("research_plan", {}),
            "custom_prompt": ctx.custom_prompt or "",
        },
        sort_keys=True,
        default=str,
    )
    stamp_findings(
        findings,
        model=model,
        prompt=_prompt_ctx,
        temperature=temperature,
        structural_index=_structural
        if isinstance(_structural, str)
        else _json.dumps(_structural, sort_keys=True, default=str),
    )

    # --- Closed-set citation enforcement (improvement #4, no LLM cost) -----
    # A lens finding may only cite a sink/source location that exists in the
    # S1b structural inventory. Default OFF (tag-only); with params.strict it
    # drops off-inventory findings so an invented sink can't reach the report.
    off_inventory = 0
    closed_set = bool(stage_cfg.params.get("closed_set_citations", False))
    if closed_set and isinstance(_structural, dict):
        try:
            from redeye.precision import in_closed_set

            inv = [
                (h["path"], int(h["line"]))
                for kind in ("sinks", "sources")
                for h in (_structural.get(kind) or [])
                if h.get("path") and h.get("line")
            ]
            strict_cs = bool(stage_cfg.params.get("closed_set_strict", False))
            survivors: list[Finding] = []
            for f in findings:
                loc = f.locations[0] if f.locations else None
                ok = loc is None or in_closed_set(loc.path, loc.start_line, inv)
                if ok:
                    survivors.append(f)
                else:
                    off_inventory += 1
                    if "off-inventory" not in f.tags:
                        f.tags.append("off-inventory")
                    if not strict_cs:
                        survivors.append(f)
            findings = survivors
        except Exception:  # noqa: BLE001 - closed-set must never abort a scan
            off_inventory = 0

    # --- Self-consistency knob (improvement #5) ---------------------------
    # Recognised here so profiles can request it; the sampling loop lives in
    # the lens runner (redeye.precision.self_consistency_keep is the pure
    # aggregator). samples<=1 is a no-op single pass.
    self_consistency_samples = int(stage_cfg.params.get("self_consistency_samples", 1))

    # --- Confidence calibration from reviewer feedback (no LLM cost) -------
    # Learn per-CWE / per-lens reliability from prior TP/FP marks and nudge
    # confidence so historically-noisy categories sit lower (and may fall
    # below the voting threshold) while reliable ones get a boost.
    from redeye.calibration import calibrate_findings

    calib_metrics = calibrate_findings(findings, ctx.feedback)

    return StageResult(
        stage_id=ctx.stage_id,
        skill=stage_cfg.skill,
        findings=findings,
        artifacts={
            "per_lens_count": per_lens_count,
            "lenses_skipped": skipped,
            "calibration": calib_metrics,
            "off_inventory": off_inventory,
            "self_consistency_samples": self_consistency_samples,
        },
        tokens_in=total_in,
        tokens_out=total_out,
        cost_usd=total_cost,
    )
