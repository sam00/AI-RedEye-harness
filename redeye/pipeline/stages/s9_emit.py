"""S9 — Emit Markdown report + SARIF + errors.jsonl.

This is the only stage that touches the filesystem deliberately (the
manifest is written by the orchestrator afterwards).
"""

from __future__ import annotations

from datetime import datetime, timezone

from redeye.output.markdown import write_markdown_report
from redeye.output.sarif import write_sarif
from redeye.schema import StageResult


def run(ctx) -> StageResult:  # type: ignore[no-untyped-def]
    stage_cfg = ctx.profile.stages[ctx.stage_id]
    ts = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    module_name = ctx.target.name or "scan"

    md_path = ctx.output_dir / f"{module_name}_{ts}_report.md"
    sarif_path = ctx.output_dir / f"{module_name}_{ts}_report.sarif"

    write_markdown_report(
        path=md_path,
        target=ctx.target,
        application_id=ctx.application_id,
        findings=ctx.findings,
        attack_surface=ctx.artifacts.get("attack_surface", {}),
        threat_model=ctx.artifacts.get("threat_model", {}),
        hallucination_metrics=ctx.artifacts.get("_hallucination_metrics") or {},
        structural_summary=ctx.artifacts.get("structural_summary"),
        external_summary=ctx.artifacts.get("external_summary"),
    )
    write_sarif(path=sarif_path, target=ctx.target, findings=ctx.findings)

    return StageResult(
        stage_id=ctx.stage_id,
        skill=stage_cfg.skill,
        findings=ctx.findings,
        artifacts={
            "report_md": str(md_path),
            "report_sarif": str(sarif_path),
        },
    )
