"""Cross-file SQL template linker tests."""

from __future__ import annotations

from pathlib import Path

from redeye.analysis.sql_templates import find_sql_template_injections


def _seed(tmp_path: Path) -> Path:
    sql_dir = tmp_path / "queries"
    sql_dir.mkdir()
    (sql_dir / "lookup.sql").write_text(
        "SELECT * FROM users WHERE name = '{}'\n",
        encoding="utf-8",
    )
    py = tmp_path / "views.py"
    py.write_text(
        "def lookup(request):\n"
        "    with open('queries/lookup.sql') as fh:\n"
        "        tmpl = fh.read()\n"
        "    q = tmpl.format(request.args['name'])\n"
        "    cursor.execute(q)\n",
        encoding="utf-8",
    )
    # A bystander that opens a different file -- should not match.
    (sql_dir / "other.sql").write_text("SELECT 1\n", encoding="utf-8")
    return tmp_path


def test_detects_template_injection(tmp_path: Path) -> None:
    repo = _seed(tmp_path)
    file_paths = [
        repo / "queries" / "lookup.sql",
        repo / "queries" / "other.sql",
        repo / "views.py",
    ]
    hits = find_sql_template_injections(repo, file_paths)
    assert len(hits) == 1
    h = hits[0]
    assert h.template_path.endswith("lookup.sql")
    assert h.consumer_path == "views.py"
    assert h.cwe == "CWE-89"
    assert h.sink_function.lower() == "execute"


def test_no_match_when_no_placeholder(tmp_path: Path) -> None:
    sql = tmp_path / "q.sql"
    sql.write_text("SELECT 1\n", encoding="utf-8")
    py = tmp_path / "v.py"
    py.write_text(
        "def f():\n    with open('q.sql') as fh:\n        cursor.execute(fh.read())\n",
        encoding="utf-8",
    )
    hits = find_sql_template_injections(tmp_path, [sql, py])
    assert hits == []


def test_no_match_when_consumer_does_not_format(tmp_path: Path) -> None:
    sql = tmp_path / "q.sql"
    sql.write_text("SELECT '{}'\n", encoding="utf-8")
    py = tmp_path / "v.py"
    py.write_text(
        "def f():\n    with open('q.sql') as fh:\n        s = fh.read()\n        cursor.execute(s, params)\n",
        encoding="utf-8",
    )
    hits = find_sql_template_injections(tmp_path, [sql, py])
    assert hits == []
