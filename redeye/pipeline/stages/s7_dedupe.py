"""S7 — Deduplicate.

Findings from different lenses often describe the same root cause from
different angles. We collapse them with a simple but effective heuristic:

- Two findings are duplicates if they share a CWE *and* their primary
  location's file path matches *and* their start_line ranges overlap by
  more than 50%.
- When merging, we keep the highest-severity, highest-confidence record
  and concatenate the others' descriptions into its notes.

A skill-based variant could reorder this with embeddings; that's a planned
upgrade and lives in :mod:`redeye.skills.dedupe`.
"""

from __future__ import annotations

import logging
from collections import defaultdict

from redeye.schema import Finding, Severity, StageResult

log = logging.getLogger(__name__)


def _key(f: Finding) -> tuple[str, str]:
    cwe = f.cwe or "UNK"
    path = f.locations[0].path if f.locations else ""
    return (cwe, path)


def _ranges_overlap(a: Finding, b: Finding) -> bool:
    if not a.locations or not b.locations:
        return False
    a0 = a.locations[0]
    b0 = b.locations[0]
    a_start, a_end = a0.start_line, a0.end_line or a0.start_line
    b_start, b_end = b0.start_line, b0.end_line or b0.start_line
    overlap = max(0, min(a_end, b_end) - max(a_start, b_start) + 1)
    span = max(a_end - a_start + 1, b_end - b_start + 1, 1)
    return overlap / span > 0.5


def _merge(into: Finding, frm: Finding) -> Finding:
    if frm.severity.numeric > into.severity.numeric:
        into.severity = frm.severity
    into.confidence = max(into.confidence, frm.confidence)
    into.tags = sorted(set(into.tags + frm.tags + [f"merged_with:{frm.id}"]))
    extra = frm.description.strip()
    if extra and extra not in into.description:
        into.description = f"{into.description}\n\n— also reported by {frm.skill or 'lens'}: {extra}"
    into.revision += 1
    return into


def run(ctx) -> StageResult:  # type: ignore[no-untyped-def]
    stage_cfg = ctx.profile.stages[ctx.stage_id]
    buckets: dict[tuple[str, str], list[Finding]] = defaultdict(list)
    for f in ctx.findings:
        buckets[_key(f)].append(f)

    deduped: list[Finding] = []
    for items in buckets.values():
        items.sort(key=lambda f: (-f.severity.numeric, -f.confidence))
        primary = items[0]
        for other in items[1:]:
            if _ranges_overlap(primary, other):
                _merge(primary, other)
            else:
                deduped.append(other)
        deduped.append(primary)

    deduped.sort(key=lambda f: (-Severity(f.severity).numeric, -f.confidence, f.id))

    log.info("S7 dedupe: %d ? %d findings", len(ctx.findings), len(deduped))
    return StageResult(
        stage_id=ctx.stage_id,
        skill=stage_cfg.skill,
        findings=deduped,
        artifacts={"input_count": len(ctx.findings), "output_count": len(deduped)},
    )
