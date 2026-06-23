"""AST taint-tracer tests.

The tracer is the precision-rigour bar -- these tests pin down the
behaviours we promise downstream stages can rely on:

1. Proven flow: source assigned to var, var used as sink arg => proven.
2. Sanitised flow: source passed through a known sanitiser => NOT proven.
3. No-flow: source and sink in different functions => not proven (we
   are intraprocedural by design).
4. Route-handler params get sourced automatically (web-framework hint).
5. Sink catalog: at least the SQL, command, eval, ssrf, pickle, xxe,
   ssti, jwt families are recognised.
6. File-level convenience: ``trace_file`` parses + returns paths.
"""

from __future__ import annotations

from pathlib import Path

from redeye.analysis.taint import (
    SANITIZERS,
    SINK_FUNCTIONS,
    SOURCE_PATTERNS,
    TaintTracer,
    trace_file,
)


def _make(tmp_path: Path, body: str) -> Path:
    p = tmp_path / "case.py"
    p.write_text(body, encoding="utf-8")
    return p


def test_proven_sql_flow_from_request(tmp_path: Path) -> None:
    p = _make(
        tmp_path,
        "from flask import request\n"
        "def lookup():\n"
        "    name = request.args['name']\n"
        "    q = f\"SELECT * FROM u WHERE n = '{name}'\"\n"
        "    cursor.execute(q)\n",
    )
    paths = trace_file(p)
    assert paths, "expected at least one taint path"
    proven = [p for p in paths if p.is_proven]
    assert proven, "expected a proven flow"
    p0 = proven[0]
    assert p0.cwe == "CWE-89"
    assert p0.sanitized is False
    assert "execute" in p0.sink


def test_sanitiser_blocks_flow(tmp_path: Path) -> None:
    p = _make(
        tmp_path,
        "from werkzeug.utils import secure_filename\n"
        "def upload(request):\n"
        "    name = request.files['f'].filename\n"
        "    safe = secure_filename(name)\n"
        "    open(safe, 'rb')\n",
    )
    paths = trace_file(p)
    proven = [p for p in paths if p.is_proven]
    # The sanitiser short-circuits the propagation, so the open() call
    # should not see a tainted value.
    assert not proven, f"sanitised flow should NOT be proven, got: {proven}"


def test_cross_function_flow_not_proven(tmp_path: Path) -> None:
    p = _make(
        tmp_path,
        "def get_input():\n"
        "    return request.args['x']\n"
        "\n"
        "def sink_caller():\n"
        "    v = get_input()\n"
        "    cursor.execute(v)\n",
    )
    paths = trace_file(p)
    # Intraprocedural-only -- we don't follow the call across functions.
    assert all(not pa.is_proven for pa in paths), (
        "cross-function flow must not be proven by an intraprocedural tracer"
    )


def test_route_handler_param_is_tainted(tmp_path: Path) -> None:
    p = _make(
        tmp_path,
        "@app.post('/lookup')\ndef lookup(name):\n    cursor.execute(name)\n",
    )
    paths = trace_file(p)
    assert paths, "route handler param should be auto-tainted"
    assert paths[0].is_proven


def test_sink_catalog_covers_key_families() -> None:
    cwes = {entry[1] for entry in SINK_FUNCTIONS}
    # We expect at least these families to be present.
    must_have = {
        "CWE-89",  # SQL
        "CWE-78",  # command
        "CWE-95",  # eval / exec / compile
        "CWE-502",  # deserialization
        "CWE-22",  # path traversal
        "CWE-918",  # SSRF
        "CWE-611",  # XXE
        "CWE-1336",  # SSTI
    }
    assert must_have.issubset(cwes), f"missing: {must_have - cwes}"


def test_source_catalog_covers_http_and_env() -> None:
    keys = set(SOURCE_PATTERNS)
    assert "request.args" in keys
    assert "request.json" in keys
    assert "os.environ" in keys


def test_sanitiser_set_has_known_helpers() -> None:
    assert "secure_filename" in SANITIZERS
    assert "shlex.quote" in SANITIZERS
    assert "html.escape" in SANITIZERS


def test_tracer_handles_unparseable_file(tmp_path: Path) -> None:
    p = _make(tmp_path, "def broken(:\n")
    tracer = TaintTracer(p)
    assert tracer.parse() is False
    assert tracer.find_paths() == []
