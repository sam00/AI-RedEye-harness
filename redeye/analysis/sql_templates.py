"""Cross-file SQL-template injection linker.

A common-but-easy-to-miss SQL-injection pattern looks like this:

    # queries/lookup.sql  -- a .sql template with positional placeholders
    SELECT * FROM users WHERE name = '{}'

    # views.py
    with open("queries/lookup.sql") as fh:
        tmpl = fh.read()
    q = tmpl.format(request.args["name"])     # tainted .format()
    cursor.execute(q)                          # SQL injection sink

Neither file in isolation looks like much:
- The .sql file is "just a template" and has no Python code to scan.
- The Python view reads a file and calls execute -- which the regex
  layer can't easily prove is dangerous without knowing the file's
  content shape.

This linker walks the repo, finds .sql templates that contain ``{}``
or ``{name}`` placeholders, then finds Python files that read those
templates AND call ``.format(...)`` AND eventually call an execute-
shaped sink. When both halves match, we emit a high-confidence
systemic finding.

Output: a list of :class:`SQLTemplateInjection` records, one per
suspect .sql template that has a matching Python consumer. Zero LLM
cost. Used by the orchestrator as deterministic evidence.
"""

from __future__ import annotations

import ast
import logging
import re
from dataclasses import dataclass, field
from pathlib import Path

log = logging.getLogger(__name__)


_PLACEHOLDER_RE = re.compile(r"\{(\w*)\}")
_EXECUTE_NAME_HINTS = (
    "execute",
    "executemany",
    "executescript",
    "execute_query",
    "raw",
    "text",
)


@dataclass
class SQLTemplateInjection:
    """One detected cross-file SQL-template injection class."""

    template_path: str  # repo-relative path to the .sql file
    template_line: int  # line number of the first placeholder
    snippet: str  # the placeholder line, truncated
    consumer_path: str  # repo-relative path to the Python file that uses it
    consumer_line: int  # line number where .format() happens
    sink_function: str  # name of the sink (e.g. cursor.execute)
    confidence: float = 0.85
    cwe: str = "CWE-89"

    def to_dict(self) -> dict:
        return {
            "template_path": self.template_path,
            "template_line": self.template_line,
            "snippet": self.snippet,
            "consumer_path": self.consumer_path,
            "consumer_line": self.consumer_line,
            "sink_function": self.sink_function,
            "confidence": self.confidence,
            "cwe": self.cwe,
        }


@dataclass
class _TemplateRef:
    path: str
    line: int
    snippet: str


@dataclass
class _ConsumerHit:
    file: str
    template_ref: str  # the basename or relative path it referred to
    open_line: int
    format_line: int
    sink_line: int | None = None
    sink_name: str = ""
    references: list[ast.AST] = field(default_factory=list)


def _find_sql_templates(root: Path, file_paths: list[Path]) -> list[_TemplateRef]:
    """Walk .sql files, return ones with positional or named ``{}`` placeholders."""
    out: list[_TemplateRef] = []
    for p in file_paths:
        if p.suffix.lower() != ".sql":
            continue
        try:
            text = p.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        for ix, line in enumerate(text.splitlines(), start=1):
            if _PLACEHOLDER_RE.search(line):
                rel = str(p.relative_to(root)) if p.is_relative_to(root) else str(p)
                out.append(_TemplateRef(path=rel, line=ix, snippet=line.strip()[:200]))
                break  # one ref per file is enough
    return out


def _scan_python_consumers(
    root: Path, file_paths: list[Path], template_paths: set[str]
) -> list[_ConsumerHit]:
    """Find Python files that open one of ``template_paths``, call .format(),
    and pass the result to an execute-shaped sink.

    The matching is intentionally loose: we look at filename hints. A
    consumer that opens ``queries/lookup.sql`` matches any template
    whose path ends with ``lookup.sql``.
    """
    # Build a lookup of basename -> full template path. We match by
    # basename to tolerate string-construction in the file path.
    basename_to_template = {Path(t).name: t for t in template_paths}

    out: list[_ConsumerHit] = []
    for p in file_paths:
        if p.suffix != ".py":
            continue
        try:
            text = p.read_text(encoding="utf-8", errors="replace")
            tree = ast.parse(text)
        except (OSError, SyntaxError):
            continue
        rel = str(p.relative_to(root)) if p.is_relative_to(root) else str(p)

        # Step 1: find every ``open("...sql")`` call.
        opens: list[tuple[int, str]] = []  # (lineno, basename-referenced)
        for node in ast.walk(tree):
            if not isinstance(node, ast.Call):
                continue
            func_id = getattr(node.func, "id", None) or getattr(node.func, "attr", None)
            if func_id != "open" or not node.args:
                continue
            first = node.args[0]
            if not isinstance(first, ast.Constant) or not isinstance(first.value, str):
                continue
            opened = first.value
            base = Path(opened).name
            if base in basename_to_template:
                opens.append((node.lineno, base))

        if not opens:
            continue

        # Step 2: walk the file for any ``.format(...)`` call.
        format_lines: list[int] = []
        for node in ast.walk(tree):
            if isinstance(node, ast.Call):
                attr = getattr(node.func, "attr", None)
                if attr == "format":
                    format_lines.append(node.lineno)

        if not format_lines:
            continue

        # Step 3: walk for an execute-shaped sink.
        sink_lines: list[tuple[int, str]] = []
        for node in ast.walk(tree):
            if not isinstance(node, ast.Call):
                continue
            attr = getattr(node.func, "attr", None) or getattr(node.func, "id", None)
            if attr and any(hint in attr.lower() for hint in _EXECUTE_NAME_HINTS):
                sink_lines.append((node.lineno, attr))

        if not sink_lines:
            continue

        # One consumer per (open, template).
        for open_line, base in opens:
            target_template = basename_to_template[base]
            # Pick the nearest .format() and sink AFTER the open.
            format_after = [ln for ln in format_lines if ln >= open_line]
            sinks_after = [(ln, name) for ln, name in sink_lines if ln >= open_line]
            if not format_after or not sinks_after:
                continue
            sink_line, sink_name = sinks_after[0]
            out.append(
                _ConsumerHit(
                    file=rel,
                    template_ref=target_template,
                    open_line=open_line,
                    format_line=format_after[0],
                    sink_line=sink_line,
                    sink_name=sink_name,
                )
            )
    return out


def find_sql_template_injections(
    target: Path, file_paths: list[Path]
) -> list[SQLTemplateInjection]:
    """Top-level entry point. Returns findings; empty if nothing matched."""
    templates = _find_sql_templates(target, file_paths)
    if not templates:
        return []
    template_paths = {t.path for t in templates}
    consumers = _scan_python_consumers(target, file_paths, template_paths)
    if not consumers:
        return []

    by_template = {t.path: t for t in templates}
    out: list[SQLTemplateInjection] = []
    for c in consumers:
        t = by_template.get(c.template_ref)
        if not t:
            continue
        out.append(
            SQLTemplateInjection(
                template_path=t.path,
                template_line=t.line,
                snippet=t.snippet,
                consumer_path=c.file,
                consumer_line=c.format_line,
                sink_function=c.sink_name or "execute",
            )
        )
    return out
