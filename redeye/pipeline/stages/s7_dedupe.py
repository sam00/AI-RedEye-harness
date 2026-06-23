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
        into.description = (
            f"{into.description}\n\n— also reported by {frm.skill or 'lens'}: {extra}"
        )
    into.revision += 1
    return into


_SYSTEMIC_CWE_THRESHOLD = 5
"""Minimum number of same-CWE findings in a directory before we cluster."""


def _module_of(path: str) -> str:
    """Return the top-level module (first dir) for clustering."""
    parts = path.replace("\\", "/").split("/")
    return parts[0] if parts else path


def _cluster_systemic(findings: list[Finding]) -> tuple[list[Finding], int]:
    """Collapse N+ same-CWE findings in the same module into a parent finding.

    The children stay in the report (preserved as ``tags: cluster-child``)
    but they get downgraded one severity notch so the cluster's severity
    is the headline number for execs. The cluster carries a
    ``cluster:systemic`` tag and a count of children.
    """
    by_cluster: dict[tuple[str, str], list[Finding]] = defaultdict(list)
    for f in findings:
        if not f.cwe or not f.locations:
            continue
        # Skip findings already marked as systemic (e.g. from S4b).
        if "systemic-sql-template" in f.tags:
            continue
        by_cluster[(f.cwe, _module_of(f.locations[0].path))].append(f)

    out: list[Finding] = []
    clustered_count = 0
    seen_ids: set[str] = set()

    for (cwe, module), group in by_cluster.items():
        if len(group) < _SYSTEMIC_CWE_THRESHOLD:
            for f in group:
                out.append(f)
                seen_ids.add(f.id)
            continue

        # Build a parent finding that summarises the cluster.
        group.sort(key=lambda f: (-f.severity.numeric, -f.confidence))
        head = group[0]
        cluster_id = f"C-{head.id}"
        cluster_locations = [head.locations[0]] + [
            f.locations[0]
            for f in group[1:6]  # cap representative locs at 5
        ]
        child_paths = sorted({f.locations[0].path for f in group})
        parent = Finding(
            id=cluster_id,
            title=f"Systemic {cwe} -- {len(group)} instances across {module}/",
            severity=head.severity,
            cwe=cwe,
            cvss_vector=head.cvss_vector,
            cvss_score=head.cvss_score,
            description=(
                f"This module exhibits {len(group)} findings of the same CWE "
                f"({cwe}). Treat as one systemic class-of-bug rather than {len(group)} "
                f"independent issues. Representative locations:\n"
                + "\n".join(f"  - {p}" for p in child_paths[:10])
            ),
            locations=cluster_locations,
            confidence=max(f.confidence for f in group),
            tags=sorted({"cluster:systemic", *head.tags}),
            skill=head.skill,
            stage=head.stage,
            remediation=head.remediation,
            grounded=any(f.grounded for f in group),
        )
        out.append(parent)
        clustered_count += 1
        seen_ids.add(cluster_id)

        # Children retained but tagged + downgraded one notch so the parent
        # leads the report.
        from redeye.schema import Severity as Sev

        demote = {
            Sev.CRITICAL: Sev.HIGH,
            Sev.HIGH: Sev.MEDIUM,
            Sev.MEDIUM: Sev.LOW,
            Sev.LOW: Sev.INFO,
            Sev.INFO: Sev.INFO,
        }
        for child in group:
            child.tags = sorted({*child.tags, f"cluster-child:{cluster_id}"})
            child.severity = demote[child.severity]
            out.append(child)
            seen_ids.add(child.id)

    return out, clustered_count


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

    # Systemic clustering pass: collapse repeated same-CWE findings in the
    # same top-level module into a parent issue (with children retained).
    clustered, n_clusters = _cluster_systemic(deduped)

    clustered.sort(key=lambda f: (-Severity(f.severity).numeric, -f.confidence, f.id))

    log.info(
        "S7 dedupe: %d -> %d findings, %d systemic clusters",
        len(ctx.findings),
        len(clustered),
        n_clusters,
    )
    return StageResult(
        stage_id=ctx.stage_id,
        skill=stage_cfg.skill,
        findings=clustered,
        artifacts={
            "input_count": len(ctx.findings),
            "output_count": len(clustered),
            "systemic_clusters": n_clusters,
        },
    )
