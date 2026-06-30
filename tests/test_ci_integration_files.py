"""Guard the turnkey CI integration files (GitHub Action + pre-commit hooks)."""

from __future__ import annotations

from pathlib import Path

import yaml

_ROOT = Path(__file__).resolve().parent.parent


def test_action_yml_is_valid_composite_action() -> None:
    data = yaml.safe_load((_ROOT / "action.yml").read_text(encoding="utf-8"))
    assert data["name"] == "RedEye SAST"
    assert data["runs"]["using"] == "composite"
    assert any(s.get("id") == "scan" for s in data["runs"]["steps"])
    assert "repo" in data["inputs"]
    assert "profile" in data["inputs"]


def test_pre_commit_hooks_define_redeye() -> None:
    hooks = yaml.safe_load((_ROOT / ".pre-commit-hooks.yaml").read_text(encoding="utf-8"))
    ids = {h["id"] for h in hooks}
    assert "redeye-diff-scan" in ids
    for h in hooks:
        assert h["entry"].startswith("redeye ")
        assert h["language"] == "python"
