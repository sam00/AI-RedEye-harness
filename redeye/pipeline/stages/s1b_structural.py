"""S1b -- structural pre-index (no LLM).

Builds the deterministic ground-truth inventory described in
:mod:`redeye.structural`. Runs after S1 (attack surface) and
before S2 (threat model), so the threat modeler and downstream stages
see *real* routes / sources / sinks instead of LLM-imagined ones.

Cost: zero LLM tokens. Just file I/O.
"""

from __future__ import annotations

from redeye.schema import StageResult
from redeye.structural import build_index, maybe_ast_routes


def run(ctx) -> StageResult:  # type: ignore[no-untyped-def]
    stage_cfg = ctx.profile.stages[ctx.stage_id]
    file_paths = ctx.scope.files if ctx.scope is not None else []

    index = build_index(target=ctx.target, file_paths=file_paths)
    # AST pass adds a few more routes; no harm if it duplicates.
    ast_routes = maybe_ast_routes(ctx.target, file_paths)
    index.routes.extend(ast_routes)

    return StageResult(
        stage_id=ctx.stage_id,
        skill=stage_cfg.skill,
        artifacts={
            "structural_index": index.to_compact_dict(),
            "structural_summary": {
                "files_indexed": index.files_indexed,
                "routes": len(index.routes),
                "sources": len(index.sources),
                "sinks": len(index.sinks),
                "secrets": len(index.secrets),
            },
        },
    )
