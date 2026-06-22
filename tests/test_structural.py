"""Structural pre-index tests."""

from __future__ import annotations

from pathlib import Path

from redeye.structural import build_index


def _seed(tmp_path: Path) -> Path:
    (tmp_path / "src").mkdir()
    (tmp_path / "src" / "api.py").write_text(
        "from fastapi import APIRouter\n"
        "router = APIRouter()\n"
        "\n"
        "@router.post('/users/lookup')\n"
        "def lookup(username: str):\n"
        "    q = f\"SELECT * FROM users WHERE name = '{username}'\"\n"
        "    return cursor.execute(q)\n",
        encoding="utf-8",
    )
    (tmp_path / "src" / "shell.py").write_text(
        "import subprocess\ndef run(cmd):\n    subprocess.run(cmd, shell=True)\n",
        encoding="utf-8",
    )
    (tmp_path / "config.yaml").write_text(
        "api_key: 'sk-ant-abcdefghijklmnopqrstuvwxyz1234'\n",
        encoding="utf-8",
    )
    (tmp_path / "Dockerfile").write_text("FROM python:3.12\nUSER root\n", encoding="utf-8")
    return tmp_path


def test_index_finds_route_sink_secret(tmp_path: Path) -> None:
    repo = _seed(tmp_path)
    files = [
        repo / "src" / "api.py",
        repo / "src" / "shell.py",
        repo / "config.yaml",
        repo / "Dockerfile",
    ]
    idx = build_index(target=repo, file_paths=files)

    assert idx.files_indexed == 4
    # Routes
    assert any(
        "/users/lookup" in r.snippet or r.snippet == "POST /users/lookup" for r in idx.routes
    )
    # SQL sink: the test code does `q = f"..."` then `cursor.execute(q)`,
    # so the matching pattern is the variable form.
    sink_kinds = {h.kind for h in idx.sinks}
    assert "sql_execute_var" in sink_kinds
    assert "subprocess_shell_true" in sink_kinds
    # Secret
    assert any(h.kind == "anthropic_or_openai_key" for h in idx.secrets)
