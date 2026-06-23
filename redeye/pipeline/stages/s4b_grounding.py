"""S4b -- grounding pass (no LLM).

Verifies every candidate finding from S4 against the actual source code:
file exists, line number resolves, snippet contains tokens consistent
with the claimed CWE family. Hallucinated findings are tagged (and, in
strict mode, dropped before they get adversarial-review tokens spent on
them).

This stage is the single biggest false-positive reducer in the pipeline.

In 0.3.x, the grounding pass also runs the AST intraprocedural taint
tracer over Python files. When the tracer can prove a source -> sink
flow for a candidate finding, we upgrade the finding from
"co-occurrence evidence" to "proven-flow" -- bump confidence, tag
``proven-flow``, attach the trace as evidence rows. If a sanitizer is
observed on the path, we tag ``sanitized`` and downgrade severity.

When a finding has no CVSS vector, we also auto-compute one from
``cwe`` + reachability (HTTP-route presence drives AV:N vs AV:L).
"""

from __future__ import annotations

import logging
from collections import defaultdict
from pathlib import Path

from redeye.analysis.cvss import compute_cvss
from redeye.analysis.sql_templates import find_sql_template_injections
from redeye.analysis.taint import TaintPath, trace_files
from redeye.grounding import ground_findings
from redeye.schema import Evidence, Finding, Location, Severity, StageResult, TaintFlow

log = logging.getLogger(__name__)


def _index_taint_paths(
    target: Path, scope_files: list[Path]
) -> dict[tuple[str, str], list[TaintPath]]:
    """Run the tracer once over all Python files in scope, then group the
    results by (file_path, cwe) so finding-attachment is O(1).
    """
    paths = trace_files(scope_files, only_python=True)
    out: dict[tuple[str, str], list[TaintPath]] = defaultdict(list)
    for p in paths:
        try:
            rel = str(p.path.relative_to(target))
        except ValueError:
            rel = str(p.path)
        out[(rel, p.cwe)].append(p)
    return out


def _attach_taint_to_finding(
    finding: Finding, paths_by_key: dict[tuple[str, str], list[TaintPath]]
) -> bool:
    """If we have a taint path for this finding's (file, cwe), attach it.

    Returns True if we attached a *proven* (non-sanitized) flow. Side-
    effect: mutates ``finding``.
    """
    if not finding.locations or not finding.cwe:
        return False
    primary = finding.locations[0]
    key = (primary.path, finding.cwe)
    candidates = paths_by_key.get(key, [])
    if not candidates:
        return False

    # Pick the path whose sink line is closest to the cited line; that's
    # the lens's claim. Prefer a proven (non-sanitized) match.
    target_line = primary.start_line
    candidates_sorted = sorted(
        candidates,
        key=lambda p: (p.sanitized, abs(p.sink_line - target_line)),
    )
    chosen = candidates_sorted[0]

    finding.taint = TaintFlow(
        source=chosen.source,
        source_location=Location(path=str(primary.path), start_line=chosen.source_line),
        sink=chosen.sink,
        sink_location=Location(path=str(primary.path), start_line=chosen.sink_line),
        sanitizer_missing=not chosen.sanitized,
        sanitizers_observed=list(chosen.sanitizers_observed),
        taint_path=[
            Location(path=str(primary.path), start_line=step.line) for step in chosen.steps
        ],
    )

    if chosen.is_proven:
        finding.evidence.append(
            Evidence(
                kind="ast_taint_proven",
                check="pass",
                detail=(
                    f"intraprocedural flow proven in {chosen.function_name}: "
                    f"{chosen.source} -> {chosen.sink}"
                ),
            )
        )
        finding.tags.append("proven-flow")
        # Strengthen confidence; cap at 0.95 to leave room for human review.
        finding.confidence = min(0.95, max(finding.confidence, 0.85))
        # Drop the weak-evidence tag if it was attached.
        finding.tags = [t for t in finding.tags if t != "weak-evidence"]
        return True
    else:
        finding.evidence.append(
            Evidence(
                kind="ast_taint_sanitized",
                check="fail",
                detail=(
                    f"intraprocedural flow exists in {chosen.function_name} but is "
                    f"sanitized by {', '.join(chosen.sanitizers_observed)}"
                ),
            )
        )
        finding.tags.append("sanitized")
        # Downgrade one severity notch -- it's not exploitable as-is.
        finding.severity = {
            Severity.CRITICAL: Severity.HIGH,
            Severity.HIGH: Severity.MEDIUM,
            Severity.MEDIUM: Severity.LOW,
            Severity.LOW: Severity.INFO,
            Severity.INFO: Severity.INFO,
        }[finding.severity]
        return False


def _has_http_route_in_scope(structural_index: dict | None) -> bool:
    if not structural_index:
        return False
    routes = structural_index.get("routes") or []
    return len(routes) > 0


def _autofill_cvss(finding: Finding, *, has_http_route: bool) -> None:
    """Compute a CVSS vector/score when the finding doesn't carry one yet."""
    if finding.cvss_vector and finding.cvss_score is not None:
        return
    authenticated = "authn" in finding.tags or "auth-required" in finding.tags
    vector, score = compute_cvss(
        cwe=finding.cwe,
        has_http_route=has_http_route,
        authenticated=authenticated,
        user_interaction=False,
    )
    if not finding.cvss_vector:
        finding.cvss_vector = vector
    if finding.cvss_score is None:
        finding.cvss_score = score
    finding.evidence.append(
        Evidence(
            kind="cvss_autocomputed", check="pass", detail=f"vector={vector} score={score:.1f}"
        )
    )


def _systemic_sql_findings(target: Path, scope_files: list[Path], next_id: int) -> list[Finding]:
    """Emit cross-file SQL-template injection findings as their own records."""
    injections = find_sql_template_injections(target, scope_files)
    out: list[Finding] = []
    for inj in injections:
        next_id += 1
        out.append(
            Finding(
                id=f"F-{next_id:04d}",
                title=f"SQL template injection: {inj.template_path} -> {inj.consumer_path}",
                severity=Severity.HIGH,
                cwe=inj.cwe,
                description=(
                    f"The SQL template at `{inj.template_path}:{inj.template_line}` uses "
                    f"`{{}}` placeholders that are filled via `.format()` in "
                    f"`{inj.consumer_path}:{inj.consumer_line}` and then passed to "
                    f"`{inj.sink_function}` without parameterisation. This is a "
                    "deterministic finding produced by the cross-file SQL template linker."
                ),
                locations=[
                    Location(path=inj.consumer_path, start_line=inj.consumer_line),
                    Location(path=inj.template_path, start_line=inj.template_line),
                ],
                confidence=inj.confidence,
                tags=["deterministic", "systemic-sql-template", "proven-flow"],
                skill="sql_template_linker",
                stage="s4b_grounding",
                taint=TaintFlow(
                    source="template placeholder bound via .format(attacker input)",
                    sink=inj.sink_function,
                    sanitizer_missing=True,
                ),
                evidence=[
                    Evidence(
                        kind="cross_file_link",
                        check="pass",
                        detail=(
                            f"template {inj.template_path}:{inj.template_line} -> "
                            f"consumer {inj.consumer_path}:{inj.consumer_line} -> "
                            f"sink {inj.sink_function}"
                        ),
                    )
                ],
                grounded=True,
                remediation=(
                    "Replace `.format(...)` template binding with a parameterised "
                    "execute (e.g. `cursor.execute(query, params)`)."
                ),
            )
        )
    return out


def run(ctx) -> StageResult:  # type: ignore[no-untyped-def]
    stage_cfg = ctx.profile.stages[ctx.stage_id]
    strict = bool(stage_cfg.params.get("strict", False))

    # Step 1: existing grounding (file exists, line resolves, snippet matches).
    kept, dropped, report = ground_findings(
        findings=ctx.findings,
        target=ctx.target,
        strict=strict,
    )

    # Step 2: AST taint trace over Python files in scope. Index once.
    scope_files = ctx.scope.files if ctx.scope is not None else []
    paths_by_key = _index_taint_paths(ctx.target, scope_files)

    has_http = _has_http_route_in_scope(ctx.artifacts.get("structural_index"))
    proven_count = 0
    sanitized_count = 0
    cvss_filled = 0

    for f in kept:
        if _attach_taint_to_finding(f, paths_by_key):
            proven_count += 1
        elif "sanitized" in f.tags:
            sanitized_count += 1
        # CVSS auto-fill regardless of taint outcome.
        before = (f.cvss_vector, f.cvss_score)
        _autofill_cvss(f, has_http_route=has_http)
        if (f.cvss_vector, f.cvss_score) != before:
            cvss_filled += 1

    # Step 3: deterministic systemic SQL-template injections (new findings).
    next_id = max(
        (int(f.id.split("-")[-1]) for f in (kept + dropped) if f.id.startswith("F-")),
        default=0,
    )
    systemic = _systemic_sql_findings(ctx.target, scope_files, next_id)
    kept.extend(systemic)

    return StageResult(
        stage_id=ctx.stage_id,
        skill=stage_cfg.skill,
        findings=kept,
        artifacts={
            "grounding_report": report.to_dict(),
            "grounding_dropped_ids": [f.id for f in dropped],
            "strict": strict,
            "taint_proven_count": proven_count,
            "taint_sanitized_count": sanitized_count,
            "cvss_autofilled_count": cvss_filled,
            "systemic_sql_findings": len(systemic),
        },
    )
