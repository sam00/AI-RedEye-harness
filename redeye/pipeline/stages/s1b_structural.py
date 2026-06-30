"""S1b -- structural pre-index (no LLM).

Builds the deterministic ground-truth inventory described in
:mod:`redeye.structural`. Runs after S1 (attack surface) and
before S2 (threat model), so the threat modeler and downstream stages
see *real* routes / sources / sinks instead of LLM-imagined ones.

Cost: zero LLM tokens. Just file I/O.
"""

from __future__ import annotations

from redeye.callgraph import build_cross_file_flows
from redeye.external import load_external_reports
from redeye.schema import StageResult
from redeye.structural import build_index, maybe_ast_routes, merge_external_findings


def run(ctx) -> StageResult:  # type: ignore[no-untyped-def]
    stage_cfg = ctx.profile.stages[ctx.stage_id]
    file_paths = ctx.scope.files if ctx.scope is not None else []

    index = build_index(target=ctx.target, file_paths=file_paths)
    # AST pass adds a few more routes; no harm if it duplicates.
    ast_routes = maybe_ast_routes(ctx.target, file_paths)
    index.routes.extend(ast_routes)

    # Lightweight cross-file taint: source-bearing function in one file calling
    # a sink-bearing function in another. Context for the lenses; not findings.
    flow_cap = int(stage_cfg.params.get("max_cross_file_flows", 50) or 50)
    index.cross_file_flows = build_cross_file_flows(
        target=ctx.target, file_paths=file_paths, cap=flow_cap
    )

    # External scanner ingestion (mapping enrichment). Paths come from the
    # stage params (config.yaml) and/or the CLI (--external-scan). Imported
    # findings become candidate sink hits; they still face grounding/voting/
    # verification downstream -- never promoted straight to the report.
    cfg_paths = list(stage_cfg.params.get("external_scanners", []) or [])
    scan_paths = [*cfg_paths, *getattr(ctx, "external_scans", [])]
    external_report = load_external_reports(scan_paths) if scan_paths else None

    artifacts: dict = {}
    if external_report is not None:
        stats = merge_external_findings(index, external_report.findings)
        artifacts["external_findings"] = [f.to_dict() for f in external_report.findings]
        artifacts["external_summary"] = {
            **external_report.summary(),
            "hits_added": stats["added"],
            "deduped": stats["deduped"],
            "reachable": stats["reachable"],
            "corroborated": stats["corroborated"],
        }

    artifacts["structural_index"] = index.to_compact_dict()
    artifacts["structural_summary"] = {
        "files_indexed": index.files_indexed,
        "routes": len(index.routes),
        "sources": len(index.sources),
        "sinks": len(index.sinks),
        "secrets": len(index.secrets),
        "cross_file_flows": len(index.cross_file_flows),
    }
    return StageResult(stage_id=ctx.stage_id, skill=stage_cfg.skill, artifacts=artifacts)
