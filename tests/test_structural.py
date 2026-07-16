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


def test_comment_only_lines_are_not_flagged(tmp_path: Path) -> None:
    """Patterns matching inside comment-only lines are false positives.

    Regression for the self-scan issue where the detector flagged security
    patterns appearing in comments (example code in docstrings, commented-out
    code, or -- when the harness scans itself -- a rule's own comment). Real
    executable code on the same file must still be detected.
    """
    src = (
        '# password = "supersecret"\n'  # 1: secret in comment -> skip
        "# cursor.execute(userq)\n"  # 2: SQL sink in comment -> skip
        "    # os.system(cmd)\n"  # 3: indented comment sink -> skip
        "// eval(userInput)\n"  # 4: C-family comment sink -> skip
        "x = 1\n"  # 5: benign
        'password = "realsecret123"\n'  # 6: real secret -> flag
        "os.system(realcmd)\n"  # 7: real sink -> flag
    )
    f = tmp_path / "mixed.py"
    f.write_text(src, encoding="utf-8")

    idx = build_index(target=tmp_path, file_paths=[f])

    commented_lines = {1, 2, 3, 4}
    flagged_lines = {h.line for h in idx.sinks} | {h.line for h in idx.secrets}
    assert not (flagged_lines & commented_lines), (
        f"comment-only lines were flagged: {sorted(flagged_lines & commented_lines)}"
    )
    # Real code on non-comment lines must still be detected.
    assert any(h.kind == "os_system" and h.line == 7 for h in idx.sinks)
    assert any(h.line == 6 for h in idx.secrets)
