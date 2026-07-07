"""AST-backed sink verification for the grounding pass (improvement #1).

The default grounding check (S4b, :mod:`redeye.grounding`) accepts a finding
when a CWE-family *token* appears within a few lines of the cited location.
That is cheap and language-agnostic but coarse: the word ``query`` near the
line passes even if there is no actual call, and aliased wrappers can be
missed.

For Python targets we can do better without an LLM: parse the file to an AST
and confirm the cited line actually contains a **call** to a function whose
name belongs to the claimed CWE's sink family. This upgrades grounding from
"a suggestive token is nearby" toward "the dangerous operation is really
there," which is a materially stronger anti-hallucination signal.

Pure standard-library ``ast`` -- no third-party dependency, no schema import,
fully unit-testable offline. Non-Python sources return ``None`` (unknown), so
the caller keeps the token check as the fallback.
"""

from __future__ import annotations

import ast

# Callable names (function or attribute tail) that represent the sink for each
# CWE family. Matched case-insensitively against the call target.
_SINK_CALLS: dict[str, frozenset[str]] = {
    "CWE-89": frozenset({"execute", "executemany", "executescript", "raw", "read_sql", "query"}),
    "CWE-78": frozenset(
        {"system", "popen", "run", "call", "check_output", "spawn", "exec", "execve"}
    ),
    "CWE-22": frozenset({"open", "read_text", "read_bytes", "fopen", "sendfile", "join"}),
    "CWE-502": frozenset({"loads", "load", "pickle", "unpickle", "from_yaml", "unserialize"}),
    "CWE-95": frozenset({"eval", "exec", "compile", "literal_eval"}),
    "CWE-918": frozenset({"get", "post", "request", "urlopen", "fetch", "send"}),
    "CWE-327": frozenset({"md5", "sha1", "des", "new", "encrypt", "decrypt"}),
}


def _call_name(node: ast.Call) -> str:
    """Return the callable's tail name: ``foo`` for ``foo(...)``, ``bar`` for
    ``x.y.bar(...)``."""
    func = node.func
    if isinstance(func, ast.Attribute):
        return func.attr
    if isinstance(func, ast.Name):
        return func.id
    return ""


def sink_call_on_line(source: str, line: int, cwe: str | None, *, window: int = 1) -> bool | None:
    """Return True/False if a sink-family call for ``cwe`` occurs within
    ``window`` lines of ``line``; ``None`` when we can't judge (non-CWE we
    don't model, unparseable source, or a non-Python file).
    """
    key = (cwe or "").upper().strip()
    wanted = _SINK_CALLS.get(key)
    if not wanted:
        return None
    try:
        tree = ast.parse(source)
    except (SyntaxError, ValueError):
        return None  # not Python / not parseable -> let the token check decide

    lo, hi = line - window, line + window
    for node in ast.walk(tree):
        if not isinstance(node, ast.Call):
            continue
        node_line = getattr(node, "lineno", None)
        if node_line is None or not (lo <= node_line <= hi):
            continue
        if _call_name(node).lower() in wanted:
            return True
    return False
