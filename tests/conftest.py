"""Shared test fixtures."""

from __future__ import annotations

from pathlib import Path

import pytest


@pytest.fixture
def tiny_repo(tmp_path: Path) -> Path:
    """Create a minimal repo-shaped tree the pipeline can walk over.

    The layout deliberately includes the paths the mock backend cites
    (``src/api/users.py`` line 42, ``config/defaults.yaml`` line 12) and
    also the SQL/secret tokens the grounding pass looks for, so the mock
    findings survive the new S4b grounding stage.
    """
    (tmp_path / "src" / "api").mkdir(parents=True)
    (tmp_path / "src" / "main.py").write_text(
        "def add(a, b):\n    return a + b\n", encoding="utf-8"
    )

    users_lines = ["# users.py"] + [f"# pad {i}" for i in range(2, 38)]
    users_lines += [
        "def lookup(username):",
        "    # the next 6 lines are the cited bug",
        "    query = f\"SELECT * FROM users WHERE name = '{username}'\"",
        "    cursor = db.cursor()",
        "    cursor.execute(query)",
        "    rows = cursor.fetchall()",
        "    return rows",
        "    # end bug",
    ]
    (tmp_path / "src" / "api" / "users.py").write_text(
        "\n".join(users_lines) + "\n", encoding="utf-8"
    )

    defaults_lines = (
        [
            "# defaults.yaml",
            "log_level: INFO",
        ]
        + [f"# pad-{i}" for i in range(3, 12)]
        + [
            'api_key: "sk-ant-abcdefghijklmnopqrstuvwxyz1234"',
        ]
    )
    (tmp_path / "config").mkdir()
    (tmp_path / "config" / "defaults.yaml").write_text(
        "\n".join(defaults_lines) + "\n", encoding="utf-8"
    )

    (tmp_path / "Dockerfile").write_text("FROM python:3.11\nUSER root\n", encoding="utf-8")
    return tmp_path
