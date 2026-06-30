"""Lightweight cross-file taint (call graph) tests."""

from __future__ import annotations

from pathlib import Path

from redeye.callgraph import build_cross_file_flows


def _seed(tmp_path: Path) -> list[Path]:
    (tmp_path / "app").mkdir()
    # handler reads request and calls a helper defined in another file
    (tmp_path / "app" / "views.py").write_text(
        "from app.db import run_query\n"
        "def handler():\n"
        "    name = request.args.get('name')\n"
        "    return run_query(name)\n",
        encoding="utf-8",
    )
    (tmp_path / "app" / "db.py").write_text(
        "def run_query(name):\n"
        "    q = f\"SELECT * FROM users WHERE n = '{name}'\"\n"
        "    cursor.execute(q)\n"
        "    return cursor.fetchall()\n",
        encoding="utf-8",
    )
    return [tmp_path / "app" / "views.py", tmp_path / "app" / "db.py"]


def test_detects_cross_file_flow(tmp_path: Path) -> None:
    files = _seed(tmp_path)
    flows = build_cross_file_flows(target=tmp_path, file_paths=files)
    assert len(flows) == 1
    flow = flows[0]
    assert flow["source"]["path"] == "app/views.py"
    assert flow["source"]["func"] == "handler"
    assert flow["sink"]["path"] == "app/db.py"
    assert flow["sink"]["func"] == "run_query"
    assert flow["via_call"] == "run_query"
    assert flow["cwe"] == "CWE-89"


def test_same_file_flow_not_reported(tmp_path: Path) -> None:
    (tmp_path / "m.py").write_text(
        "def helper(name):\n"
        "    cursor.execute(f\"SELECT {name}\")\n"
        "def handler():\n"
        "    name = request.args.get('x')\n"
        "    helper(name)\n",
        encoding="utf-8",
    )
    flows = build_cross_file_flows(target=tmp_path, file_paths=[tmp_path / "m.py"])
    assert flows == []


def test_cap_limits_flows(tmp_path: Path) -> None:
    files = _seed(tmp_path)
    flows = build_cross_file_flows(target=tmp_path, file_paths=files, cap=0)
    assert flows == []
