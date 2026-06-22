"""S4b -- grounding pass (no LLM).

Verifies every candidate finding from S4 against the actual source code:
file exists, line number resolves, snippet contains tokens consistent
with the claimed CWE family. Hallucinated findings are tagged (and, in
strict mode, dropped before they get adversarial-review tokens spent on
them).

This stage is the single biggest false-positive reducer in the pipeline.
"""

from __future__ import annotations

from redeye.grounding import ground_findings
from redeye.schema import StageResult


def run(ctx) -> StageResult:  # type: ignore[no-untyped-def]
    stage_cfg = ctx.profile.stages[ctx.stage_id]
    strict = bool(stage_cfg.params.get("strict", False))

    kept, dropped, report = ground_findings(
        findings=ctx.findings,
        target=ctx.target,
        strict=strict,
    )

    return StageResult(
        stage_id=ctx.stage_id,
        skill=stage_cfg.skill,
        findings=kept,
        artifacts={
            "grounding_report": report.to_dict(),
            "grounding_dropped_ids": [f.id for f in dropped],
            "strict": strict,
        },
    )
