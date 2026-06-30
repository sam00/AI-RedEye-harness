"""Lightweight cross-file taint via a cheap Python call graph.

The structural pre-index (:mod:`redeye.structural`) is line-local: it knows a
sink exists at ``file:line`` but not that the tainted value arrived from a
*different* file. Many real bugs are multi-hop -- an HTTP handler reads
``request.args`` and passes it to a helper in another module that builds and
executes SQL.

This module adds a deliberately small, Python-only call graph so S4 lenses can
reason about those flows:

1. Parse each ``.py`` file's AST and split it into function definitions.
2. Tag each function as *source-bearing* (its body matches an untrusted-input
   pattern) and/or *sink-bearing* (its body matches a dangerous-sink pattern),
   reusing the structural regex catalog.
3. Record the simple names each function calls.
4. Emit a cross-file flow whenever a source-bearing function in one file calls
   a sink-bearing function defined in a *different* file.

It is intentionally conservative and approximate (name-based resolution, no
type inference). Flows are *context for the lenses*, never auto-promoted to
findings -- they still face grounding / voting / verification downstream.
"""

from __future__ import annotations

import ast
import logging
from dataclasses import dataclass, field
from pathlib import Path

from redeye.structural import _SINK_PATTERNS, _SOURCE_PATTERNS

log = logging.getLogger(__name__)


@dataclass
class _Func:
    name: str
    path: str
    line: int
    has_source: bool
    has_sink: bool
    cwe_hint: str | None
    calls: set[str] = field(default_factory=set)


def _segment(text: str, node: ast.AST) -> str:
    try:
        seg = ast.get_source_segment(text, node)
    except Exception:  # pragma: no cover - defensive
        seg = None
    return seg or ""


def _scan_segment(segment: str) -> tuple[bool, bool, str | None]:
    """Return (has_source, has_sink, sink_cwe) for a function body segment."""
    has_source = any(pat.search(segment) for pat, _ in _SOURCE_PATTERNS)
    sink_cwe: str | None = None
    has_sink = False
    for pat, _kind, cwe in _SINK_PATTERNS:
        if pat.search(segment):
            has_sink = True
            sink_cwe = sink_cwe or cwe
    return has_source, has_sink, sink_cwe


def _callee_names(node: ast.AST) -> set[str]:
    names: set[str] = set()
    for sub in ast.walk(node):
        if isinstance(sub, ast.Call):
            func = sub.func
            if isinstance(func, ast.Name):
                names.add(func.id)
            elif isinstance(func, ast.Attribute):
                names.add(func.attr)
    return names


def build_cross_file_flows(*, target: Path, file_paths: list[Path], cap: int = 50) -> list[dict]:
    """Return cross-file source->sink flows discovered by the call graph."""
    funcs: list[_Func] = []
    for fp in file_paths:
        if fp.suffix != ".py":
            continue
        try:
            text = fp.read_text(encoding="utf-8", errors="replace")
            tree = ast.parse(text)
        except (OSError, SyntaxError, ValueError):
            continue
        rel = str(fp.relative_to(target)) if fp.is_relative_to(target) else str(fp)
        for node in ast.walk(tree):
            if not isinstance(node, ast.FunctionDef | ast.AsyncFunctionDef):
                continue
            seg = _segment(text, node)
            if not seg:
                continue
            has_source, has_sink, cwe = _scan_segment(seg)
            funcs.append(
                _Func(
                    name=node.name,
                    path=rel,
                    line=node.lineno,
                    has_source=has_source,
                    has_sink=has_sink,
                    cwe_hint=cwe,
                    calls=_callee_names(node),
                )
            )

    # Index sink-bearing functions by name for resolution.
    sinks_by_name: dict[str, list[_Func]] = {}
    for f in funcs:
        if f.has_sink:
            sinks_by_name.setdefault(f.name, []).append(f)

    flows: list[dict] = []
    if cap <= 0:
        return flows
    seen: set[tuple[str, int, str, int]] = set()
    for src in funcs:
        if not src.has_source:
            continue
        for callee in src.calls:
            for sink in sinks_by_name.get(callee, []):
                if sink.path == src.path:
                    continue  # same-file flows are already line-local context
                key = (src.path, src.line, sink.path, sink.line)
                if key in seen:
                    continue
                seen.add(key)
                flows.append(
                    {
                        "source": {"path": src.path, "line": src.line, "func": src.name},
                        "sink": {"path": sink.path, "line": sink.line, "func": sink.name},
                        "via_call": callee,
                        "cwe": sink.cwe_hint,
                    }
                )
                if len(flows) >= cap:
                    return flows
    return flows
