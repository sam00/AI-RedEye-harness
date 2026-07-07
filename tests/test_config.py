"""Smoke tests for profile loading and validation."""

from __future__ import annotations

import pytest

from redeye.config import load_profile
from redeye.errors import ConfigError


@pytest.mark.parametrize("profile_name", ["default", "cli", "full", "fable", "mock"])
def test_builtin_profiles_load(profile_name: str) -> None:
    cfg = load_profile(profile_name)
    assert cfg.name == profile_name
    assert cfg.roles, "every profile must declare at least one role"
    assert cfg.stages, "every profile must declare stages"
    expected_stages = {
        "s1_attack_surface",
        "s2_threat_model",
        "s3_strategize",
        "s4_research",
        "s5_policy_gate",
        "s6_adversarial",
        "s7_dedupe",
        "s8_chain",
        "s9_emit",
    }
    assert expected_stages.issubset(cfg.stages.keys())


def test_fable_profile_uses_fable_5_and_is_priced() -> None:
    from redeye.backends.sdk_anthropic import _PRICE_PER_MTOK_IN, _PRICE_PER_MTOK_OUT

    cfg = load_profile("fable")
    models = {role.model for role in cfg.roles.values()}
    assert "claude-fable-5" in models
    # Every SDK model the profile names must be in the price table so cost
    # accounting doesn't silently fall back to the generic default.
    for role in cfg.roles.values():
        if role.via == "sdk":
            assert role.model in _PRICE_PER_MTOK_IN
            assert role.model in _PRICE_PER_MTOK_OUT
    assert _PRICE_PER_MTOK_IN["claude-fable-5"] == 10.0
    assert _PRICE_PER_MTOK_OUT["claude-fable-5"] == 50.0


def test_unknown_profile_raises() -> None:
    with pytest.raises(ConfigError):
        load_profile("does-not-exist-xyz")


def test_config_hash_is_stable() -> None:
    a = load_profile("default")
    b = load_profile("default")
    assert a.config_hash() == b.config_hash()


def test_different_profiles_have_different_hashes() -> None:
    a = load_profile("default")
    b = load_profile("full")
    assert a.config_hash() != b.config_hash()
