"""AST intraprocedural taint tracer for Python.

Walks each function body and answers a deterministic question for each
sink call: "does any attacker-controlled value reach this sink, and if
so, was it sanitized along the way?"

This is the deterministic layer that upgrades RedEye findings from
**co-occurrence evidence** ("a sink and a source pattern appear within
+/- 5 lines of each other") to **proven dataflow** ("variable v starts
at request.json['x'] on line 12, no sanitizer touches it, and it's
passed to cursor.execute on line 20"). Combined with the existing
structural index, this closes the VVAH precision gap without taking a
single LLM token.

Limitations (called out so callers don't overclaim):

- Python only (S1b structural patterns cover JS/Java/Go/etc., but only
  Python gets the AST taint proof). Cross-language proof is future work.
- Intraprocedural only -- a tainted value passed across a function
  boundary is not traced into the callee. Callable graphs in real
  applications are too dynamic for static cross-call proof without an
  IFDS solver.
- Tracks assignments, augmented assignments, f-strings, ``.format()``,
  ``%`` formatting, ``+`` concatenation, attribute access (`x.attr`),
  subscript (`x['k']`). Skips tuple/list unpacking, comprehension
  generators with complex predicates, and conditional ternary patterns
  conservatively.

When proof fails, the tracer falls back to "no proof"; the LLM lens may
still emit a finding from the co-occurrence layer, but it'll be tagged
``weak-evidence`` and the validator will downgrade severity. This is
the correct conservative behavior.
"""

from __future__ import annotations

import ast
import logging
from dataclasses import dataclass, field
from pathlib import Path

log = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Source / sink / sanitizer catalogs
# ---------------------------------------------------------------------------

# A *source pattern* is an attribute-or-call expression we treat as
# attacker-controlled when it appears on the right-hand side of an
# assignment. Conservative: only well-known web/CLI input handles.
SOURCE_PATTERNS: dict[str, str] = {
    "request.json": "HTTP request body (JSON)",
    "request.args": "HTTP query string",
    "request.form": "HTTP form data",
    "request.values": "HTTP form or query",
    "request.files": "HTTP file upload",
    "request.cookies": "HTTP cookie",
    "request.headers": "HTTP header",
    "request.data": "HTTP request body (raw)",
    "request.get_json": "HTTP request body (JSON)",
    "request.get_data": "HTTP request body (raw)",
    "req.body": "Express request body",
    "req.query": "Express query string",
    "req.params": "Express route params",
    "os.environ": "environment variable",
    "os.getenv": "environment variable",
    "sys.argv": "CLI argv",
    "input": "stdin input()",
}


# A *sink function* is a callable we treat as dangerous when an
# attacker-controlled value flows into one of its arguments. Each entry
# is (qualified-name-suffix, cwe, description). The match is a suffix
# check so ``cursor.execute`` matches ``db.cursor.execute`` etc.
SINK_FUNCTIONS: list[tuple[str, str, str]] = [
    # SQL execute family
    ("cursor.execute", "CWE-89", "SQL execute"),
    (".executemany", "CWE-89", "SQL executemany"),
    (".execute_query", "CWE-89", "SQL execute_query"),
    (".raw", "CWE-89", "Django/SQLAlchemy raw SQL"),
    (".text", "CWE-89", "SQLAlchemy text() raw SQL"),
    # Command injection
    ("subprocess.run", "CWE-78", "subprocess.run"),
    ("subprocess.call", "CWE-78", "subprocess.call"),
    ("subprocess.Popen", "CWE-78", "subprocess.Popen"),
    ("subprocess.check_output", "CWE-78", "subprocess.check_output"),
    ("os.system", "CWE-78", "os.system"),
    ("os.popen", "CWE-78", "os.popen"),
    # Code injection
    ("eval", "CWE-95", "Python eval()"),
    ("exec", "CWE-95", "Python exec()"),
    ("compile", "CWE-95", "Python compile()"),
    # Deserialization
    ("pickle.loads", "CWE-502", "pickle.loads (unsafe deser)"),
    ("pickle.load", "CWE-502", "pickle.load (unsafe deser)"),
    ("yaml.load", "CWE-502", "yaml.load (use safe_load)"),
    ("marshal.loads", "CWE-502", "marshal.loads"),
    # Path traversal
    ("open", "CWE-22", "open() on tainted path"),
    ("io.open", "CWE-22", "io.open() on tainted path"),
    (".send_from_directory", "CWE-22", "Flask send_from_directory"),
    # SSRF
    ("requests.get", "CWE-918", "requests.get on tainted URL"),
    ("requests.post", "CWE-918", "requests.post on tainted URL"),
    ("requests.put", "CWE-918", "requests.put on tainted URL"),
    ("requests.delete", "CWE-918", "requests.delete on tainted URL"),
    ("requests.request", "CWE-918", "requests.request on tainted URL"),
    ("urllib.request.urlopen", "CWE-918", "urlopen on tainted URL"),
    ("httpx.get", "CWE-918", "httpx.get on tainted URL"),
    ("httpx.post", "CWE-918", "httpx.post on tainted URL"),
    # XSS / template injection
    (".render_template_string", "CWE-79", "Flask render_template_string"),
    ("jinja2.Template", "CWE-1336", "Jinja2 Template() server-side template injection"),
    # XXE
    ("etree.parse", "CWE-611", "lxml etree.parse (XXE risk)"),
    ("etree.fromstring", "CWE-611", "lxml etree.fromstring (XXE risk)"),
    ("xml.etree.ElementTree.parse", "CWE-611", "ElementTree.parse"),
    # NoSQL injection
    ("mongo.db", "CWE-943", "MongoDB query with tainted input"),
]


# A *sanitizer* is a callable that, when wrapped around a tainted value,
# defangs it. If we observe one between source and sink, we suppress the
# finding (or downgrade its severity).
SANITIZERS: set[str] = {
    # SQL parameterization
    "bindparam",
    "text",  # only when bound via .params() -- approximated
    # Shell escaping
    "shlex.quote",
    "shlex.split",
    "pipes.quote",
    # Path normalization
    "secure_filename",
    "os.path.basename",
    "pathlib.PurePath",
    "werkzeug.utils.secure_filename",
    # HTML escaping
    "html.escape",
    "markupsafe.escape",
    "escape",
    "bleach.clean",
    # General sanitization signals
    "re.escape",
    "urllib.parse.quote",
    "urllib.parse.quote_plus",
    "json.dumps",  # at sink boundaries, often safe
    # Validation helpers
    "isinstance",
    "validate",
    "validators",
    # Crypto-grade re-encodings
    "base64.b64encode",
    "hashlib.sha256",
}


# ---------------------------------------------------------------------------
# Data classes
# ---------------------------------------------------------------------------


@dataclass
class TaintStep:
    """One step in the propagation chain."""

    line: int
    kind: str  # "source" | "propagation" | "sanitizer" | "sink"
    expr: str  # short string repr of the AST node
    detail: str = ""


@dataclass
class TaintPath:
    """A proven (or disproven) flow from a source to a sink."""

    path: Path
    function_name: str
    source: str
    source_line: int
    sink: str
    sink_line: int
    cwe: str
    sanitized: bool
    sanitizers_observed: list[str] = field(default_factory=list)
    steps: list[TaintStep] = field(default_factory=list)

    @property
    def is_proven(self) -> bool:
        """A path is "proven" if it's intraprocedural source -> sink and
        was NOT sanitized along the way.
        """
        return not self.sanitized

    def to_dict(self) -> dict:
        return {
            "path": str(self.path),
            "function": self.function_name,
            "source": self.source,
            "source_line": self.source_line,
            "sink": self.sink,
            "sink_line": self.sink_line,
            "cwe": self.cwe,
            "sanitized": self.sanitized,
            "sanitizers_observed": list(self.sanitizers_observed),
            "steps": [
                {"line": s.line, "kind": s.kind, "expr": s.expr, "detail": s.detail}
                for s in self.steps
            ],
            "is_proven": self.is_proven,
        }


# ---------------------------------------------------------------------------
# AST helpers
# ---------------------------------------------------------------------------


def _qualified_name(node: ast.AST) -> str:
    """Best-effort qualified-name extraction for Attribute / Name chains.

    Returns ``""`` if the node isn't a name/attribute chain (e.g. complex
    subscript or call).
    """
    parts: list[str] = []
    cur: ast.AST | None = node
    while cur is not None:
        if isinstance(cur, ast.Attribute):
            parts.append(cur.attr)
            cur = cur.value
        elif isinstance(cur, ast.Name):
            parts.append(cur.id)
            cur = None
        else:
            return ""
    return ".".join(reversed(parts))


def _is_source_expr(node: ast.AST) -> tuple[bool, str]:
    """Return (True, qualified_name) if ``node`` looks like a known source."""
    if isinstance(node, ast.Subscript):
        return _is_source_expr(node.value)
    if isinstance(node, ast.Call):
        called = _qualified_name(node.func)
        for src in SOURCE_PATTERNS:
            if called == src or called.endswith("." + src):
                return True, src
        # `input(...)` is a bare-Name call.
        if isinstance(node.func, ast.Name) and node.func.id in SOURCE_PATTERNS:
            return True, node.func.id
        return False, ""
    if isinstance(node, ast.Attribute):
        qn = _qualified_name(node)
        for src in SOURCE_PATTERNS:
            if qn == src or qn.endswith("." + src) or qn.startswith(src + "."):
                return True, src
    if isinstance(node, ast.Name) and node.id in SOURCE_PATTERNS:
        return True, node.id
    return False, ""


def _is_sink_call(node: ast.Call) -> tuple[bool, str, str, str]:
    """Return (matched, qualified_name, cwe, description) for sink calls."""
    qn = _qualified_name(node.func)
    if not qn:
        # bare-Name call (e.g. eval(), exec(), open(), compile())
        if isinstance(node.func, ast.Name):
            qn = node.func.id
    if not qn:
        return False, "", "", ""
    for suffix, cwe, desc in SINK_FUNCTIONS:
        if suffix.startswith("."):
            if qn.endswith(suffix) or ("." + qn).endswith(suffix):
                return True, qn, cwe, desc
        else:
            if qn == suffix or qn.endswith("." + suffix):
                return True, qn, cwe, desc
    return False, "", "", ""


def _short_expr(node: ast.AST) -> str:
    try:
        return ast.unparse(node)[:120]  # type: ignore[attr-defined]
    except Exception:  # noqa: BLE001 -- ast.unparse can raise on edge nodes
        return type(node).__name__


def _used_names(node: ast.AST) -> set[str]:
    """Return the set of bare Name ids referenced anywhere in ``node``."""
    out: set[str] = set()
    for child in ast.walk(node):
        if isinstance(child, ast.Name):
            out.add(child.id)
    return out


def _calls_in(node: ast.AST) -> list[ast.Call]:
    return [c for c in ast.walk(node) if isinstance(c, ast.Call)]


def _sanitizer_calls(node: ast.AST) -> list[str]:
    """Return sanitizer names invoked anywhere within ``node``."""
    out: list[str] = []
    for call in _calls_in(node):
        qn = _qualified_name(call.func)
        if not qn and isinstance(call.func, ast.Name):
            qn = call.func.id
        for san in SANITIZERS:
            if qn == san or qn.endswith("." + san):
                out.append(qn)
                break
    return out


# ---------------------------------------------------------------------------
# Tracer
# ---------------------------------------------------------------------------


class TaintTracer:
    """Intraprocedural taint tracer.

    Usage:

    >>> tracer = TaintTracer(Path("path/to/file.py"))
    >>> tracer.parse()
    >>> for taint in tracer.find_paths():
    ...     print(taint.source, "->", taint.sink, "proven:", taint.is_proven)
    """

    def __init__(self, file_path: Path) -> None:
        self.file_path = file_path
        self.tree: ast.Module | None = None

    def parse(self) -> bool:
        try:
            text = self.file_path.read_text(encoding="utf-8", errors="replace")
            self.tree = ast.parse(text, filename=str(self.file_path))
            return True
        except (OSError, SyntaxError) as exc:
            log.debug("taint: parse failed for %s: %s", self.file_path, exc)
            self.tree = None
            return False

    def find_paths(self) -> list[TaintPath]:
        """Return every (source, sink) pair we can prove inside this file."""
        if self.tree is None:
            return []
        out: list[TaintPath] = []
        for node in ast.walk(self.tree):
            if isinstance(node, ast.FunctionDef | ast.AsyncFunctionDef):
                out.extend(self._scan_function(node))
        return out

    # -- per-function ----------------------------------------------------

    def _scan_function(self, func: ast.FunctionDef | ast.AsyncFunctionDef) -> list[TaintPath]:
        # 1. Build the *tainted variable set* by scanning all statements
        #    top-to-bottom. We don't try to be path-sensitive; we just
        #    propagate taint through assignments and augmented assignments.
        tainted: dict[str, TaintStep] = {}  # name -> step that tainted it
        param_sources = self._param_sources(func)
        for pname, psource in param_sources.items():
            tainted[pname] = TaintStep(
                line=func.lineno,
                kind="source",
                expr=pname,
                detail=psource,
            )

        out: list[TaintPath] = []
        for stmt in ast.walk(func):
            # Skip the function header itself.
            if stmt is func:
                continue
            self._propagate(stmt, tainted)
            # Look for sink calls in this statement.
            for call in _calls_in(stmt):
                matched, qn, cwe, desc = _is_sink_call(call)
                if not matched:
                    continue
                taint_arg = self._tainted_arg(call, tainted)
                if taint_arg is None:
                    continue
                source_step = taint_arg
                sanitizers = _sanitizer_calls(call)
                # Walk back through the propagation chain and collect any
                # sanitizer hits we accumulated along the way.
                trace = self._build_trace(source_step, stmt, call, sanitizers)
                sanitized = bool(sanitizers) or any(s.kind == "sanitizer" for s in trace)
                out.append(
                    TaintPath(
                        path=self.file_path,
                        function_name=func.name,
                        source=source_step.detail or source_step.expr,
                        source_line=source_step.line,
                        sink=qn,
                        sink_line=call.lineno,
                        cwe=cwe,
                        sanitized=sanitized,
                        sanitizers_observed=sanitizers,
                        steps=trace,
                    )
                )
        return out

    def _param_sources(self, func: ast.FunctionDef | ast.AsyncFunctionDef) -> dict[str, str]:
        """If this function is an HTTP route handler (decorator hint), its
        parameters are conservatively treated as attacker-controlled.
        """
        if not _decorated_as_route(func):
            return {}
        result: dict[str, str] = {}
        args = func.args
        for arg in args.args:
            if arg.arg in {"self", "cls"}:
                continue
            result[arg.arg] = f"HTTP route parameter ``{arg.arg}``"
        return result

    def _propagate(self, stmt: ast.AST, tainted: dict[str, TaintStep]) -> None:
        """Update ``tainted`` with any new tainted bindings introduced by
        ``stmt``. We model assignments, augmented assignments, and for-loop
        targets.
        """
        if isinstance(stmt, ast.Assign):
            self._propagate_assign(stmt.targets, stmt.value, tainted)
        elif isinstance(stmt, ast.AugAssign):
            self._propagate_assign([stmt.target], stmt.value, tainted, augmented=True)
        elif isinstance(stmt, ast.AnnAssign) and stmt.value is not None:
            self._propagate_assign([stmt.target], stmt.value, tainted)
        elif isinstance(stmt, ast.For):
            # for x in tainted_iter: -- target becomes tainted iff iter is
            if self._expr_is_tainted(stmt.iter, tainted):
                if isinstance(stmt.target, ast.Name):
                    tainted[stmt.target.id] = TaintStep(
                        line=stmt.lineno,
                        kind="propagation",
                        expr=f"{stmt.target.id} = item of tainted iter",
                    )

    def _propagate_assign(
        self,
        targets: list[ast.AST],
        value: ast.AST,
        tainted: dict[str, TaintStep],
        *,
        augmented: bool = False,
    ) -> None:
        # First check if RHS is a known source.
        is_src, src_name = _is_source_expr(value)
        # OR if RHS references any tainted variable.
        rhs_tainted_via = self._referenced_tainted(value, tainted)
        # Sanitizers detected in RHS interrupt the taint.
        sanitizers = _sanitizer_calls(value)

        if is_src:
            step_kind = "source"
            step_detail = SOURCE_PATTERNS.get(src_name, src_name)
        elif rhs_tainted_via:
            step_kind = "propagation"
            step_detail = f"from tainted var(s) {sorted(rhs_tainted_via)}"
        else:
            step_kind = ""
            step_detail = ""

        # If we observed a sanitizer in the RHS, demote the new binding to
        # "sanitized" -- we still record the step but the path is clean.
        sanitized_here = bool(sanitizers) and (is_src or rhs_tainted_via)

        if step_kind == "":
            return

        step = TaintStep(
            line=getattr(value, "lineno", 0),
            kind="sanitizer" if sanitized_here else step_kind,
            expr=_short_expr(value),
            detail=step_detail,
        )

        for tgt in targets:
            if isinstance(tgt, ast.Name):
                if sanitized_here:
                    # Mark as no-longer-tainted by REMOVING from tainted map.
                    tainted.pop(tgt.id, None)
                else:
                    tainted[tgt.id] = step
            elif isinstance(tgt, ast.Tuple | ast.List):
                # Tuple unpacking -- conservative: taint every name target.
                for elt in tgt.elts:
                    if isinstance(elt, ast.Name) and not sanitized_here:
                        tainted[elt.id] = step

    def _expr_is_tainted(self, node: ast.AST, tainted: dict[str, TaintStep]) -> bool:
        names = _used_names(node)
        if names & set(tainted):
            return True
        return _is_source_expr(node)[0]

    def _referenced_tainted(self, node: ast.AST, tainted: dict[str, TaintStep]) -> set[str]:
        return _used_names(node) & set(tainted)

    def _tainted_arg(self, call: ast.Call, tainted: dict[str, TaintStep]) -> TaintStep | None:
        """Return the first tainted arg (or kwarg value) feeding into the call."""
        for arg in list(call.args) + [kw.value for kw in call.keywords]:
            # Source flowing in directly?
            is_src, src_name = _is_source_expr(arg)
            if is_src:
                return TaintStep(
                    line=getattr(arg, "lineno", call.lineno),
                    kind="source",
                    expr=_short_expr(arg),
                    detail=SOURCE_PATTERNS.get(src_name, src_name),
                )
            # A tainted variable flowing in?
            refs = self._referenced_tainted(arg, tainted)
            if refs:
                # Return the propagation step for the first referenced var.
                first = sorted(refs)[0]
                return tainted[first]
        return None

    def _build_trace(
        self,
        source_step: TaintStep,
        sink_stmt: ast.AST,
        sink_call: ast.Call,
        sanitizers: list[str],
    ) -> list[TaintStep]:
        steps = [source_step]
        if sanitizers:
            steps.append(
                TaintStep(
                    line=sink_call.lineno,
                    kind="sanitizer",
                    expr=", ".join(sanitizers),
                    detail="sanitizer observed at sink",
                )
            )
        steps.append(
            TaintStep(
                line=sink_call.lineno,
                kind="sink",
                expr=_short_expr(sink_call),
                detail="dangerous call reached",
            )
        )
        return steps


# ---------------------------------------------------------------------------
# Helpers (route detection)
# ---------------------------------------------------------------------------


def _decorated_as_route(func: ast.FunctionDef | ast.AsyncFunctionDef) -> bool:
    """Heuristic: does this function look like an HTTP route handler?"""
    for deco in func.decorator_list:
        attr = None
        if isinstance(deco, ast.Call):
            attr = getattr(deco.func, "attr", None) or getattr(deco.func, "id", None)
        elif isinstance(deco, ast.Attribute):
            attr = deco.attr
        elif isinstance(deco, ast.Name):
            attr = deco.id
        if attr and attr.lower() in {
            "get",
            "post",
            "put",
            "delete",
            "patch",
            "route",
            "endpoint",
            "view",
        }:
            return True
    return False


# ---------------------------------------------------------------------------
# Public convenience
# ---------------------------------------------------------------------------


def trace_file(path: Path) -> list[TaintPath]:
    """Convenience: parse + scan one file, return all proven (and sanitized) paths."""
    tracer = TaintTracer(path)
    if not tracer.parse():
        return []
    return tracer.find_paths()


def trace_files(paths: list[Path], *, only_python: bool = True) -> list[TaintPath]:
    """Run the tracer over a batch of files. Skips non-Python paths by default."""
    out: list[TaintPath] = []
    for p in paths:
        if only_python and p.suffix != ".py":
            continue
        out.extend(trace_file(p))
    return out
