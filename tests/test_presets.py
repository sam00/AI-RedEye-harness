"""Preset expansion tests.

The contract these tests pin down:

1. ``apply_preset`` produces the preset's default values for flags the user
   did NOT pass explicitly.
2. ``apply_preset`` leaves the user's explicit flags untouched.
3. Every preset name in the registry has the keys the scan callback expects.
4. The ``quick`` preset sets profile=mock (zero LLM cost).
5. The ``pr`` preset turns on diff_only + strict_grounding (mirrors GHA).
"""

from __future__ import annotations

import pytest

from redeye.commands.presets import PRESETS, apply_preset, list_presets


def _baseline_kwargs() -> dict:
    """The kwargs shape the scan callback uses, with Click-default values."""
    return {
        "profile": None,
        "diff_only": False,
        "pr_base": "main",
        "exclude_paths": [],
        "max_files": 0,
        "max_file_bytes": 0,
        "max_total_bytes": 0,
        "strict_grounding": False,
        "require_poc": False,
        "store_findings": False,
        "use_feedback": False,
    }


@pytest.mark.parametrize("name", list(PRESETS.keys()))
def test_every_preset_only_uses_known_keys(name: str) -> None:
    baseline = _baseline_kwargs()
    for key in PRESETS[name]:
        assert key in baseline, f"preset {name!r} sets unknown key {key!r}"


def test_pr_preset_turns_on_diff_only_and_strict() -> None:
    out = apply_preset("pr", explicit_flags=set(), current_kwargs=_baseline_kwargs())
    assert out["diff_only"] is True
    assert out["pr_base"] == "origin/main"
    assert out["strict_grounding"] is True
    assert out["max_files"] == 100
    assert "node_modules" in out["exclude_paths"]


def test_quick_preset_uses_mock_backend() -> None:
    out = apply_preset("quick", explicit_flags=set(), current_kwargs=_baseline_kwargs())
    assert out["profile"] == "mock"
    # Quick is for trying the tool; strict grounding off so demo findings survive.
    assert out["strict_grounding"] is False


def test_explicit_flag_wins_over_preset() -> None:
    base = _baseline_kwargs()
    # User explicitly passed --max-files 500
    base["max_files"] = 500
    out = apply_preset("pr", explicit_flags={"max_files"}, current_kwargs=base)
    # PR preset would have set 100, but the user's value wins.
    assert out["max_files"] == 500
    # Other PR-preset slots still take effect.
    assert out["diff_only"] is True
    assert out["strict_grounding"] is True


def test_explicit_profile_wins_over_quick_preset() -> None:
    base = _baseline_kwargs()
    base["profile"] = "full"
    out = apply_preset("quick", explicit_flags={"profile"}, current_kwargs=base)
    # Quick would have flipped profile to 'mock', but user said 'full'.
    assert out["profile"] == "full"


def test_unknown_preset_raises() -> None:
    with pytest.raises(ValueError):
        apply_preset("bogus", explicit_flags=set(), current_kwargs=_baseline_kwargs())


def test_list_presets_returns_four_items() -> None:
    names = [n for n, _ in list_presets()]
    assert set(names) == {"pr", "ci", "deep", "quick"}
