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


# The only valid Anthropic model ids (mid-2026). Any sdk-routed role must name
# one of these; otherwise the SDK backend 400s and silently degrades to mock
# while the manifest still claims the real model ran.
_VALID_SDK_MODEL_IDS = {
    "claude-opus-4-8",
    "claude-sonnet-5",
    "claude-haiku-4-5-20251001",
    "claude-fable-5",
}

# Every profile the loader bundles.
_ALL_BUNDLED_PROFILES = ["default", "cli", "full", "fable", "mock", "ollama_local"]


def test_fable_profile_uses_fable_5_and_is_priced() -> None:
    from redeye.backends.sdk_anthropic import _PRICE_PER_MTOK_IN, _PRICE_PER_MTOK_OUT

    cfg = load_profile("fable")
    models = {role.model for role in cfg.roles.values()}
    assert "claude-fable-5" in models
    assert _PRICE_PER_MTOK_IN["claude-fable-5"] == 10.0
    assert _PRICE_PER_MTOK_OUT["claude-fable-5"] == 50.0


def test_every_sdk_role_model_is_valid_and_priced() -> None:
    """Across ALL bundled profiles, every sdk-routed model id must be a real
    Anthropic id AND be in the price table -- otherwise the SDK 400s and the
    stage fabricates mock output while the manifest claims the real model ran.
    """
    from redeye.backends.sdk_anthropic import _PRICE_PER_MTOK_IN, _PRICE_PER_MTOK_OUT

    seen_sdk_role = False
    for profile_name in _ALL_BUNDLED_PROFILES:
        cfg = load_profile(profile_name)
        for role_name, role in cfg.roles.items():
            if role.via != "sdk":
                continue
            seen_sdk_role = True
            assert role.model in _VALID_SDK_MODEL_IDS, (
                f"{profile_name}:{role_name} names invalid sdk model {role.model!r}"
            )
            assert role.model in _PRICE_PER_MTOK_IN, (
                f"{profile_name}:{role_name} model {role.model!r} not priced (in)"
            )
            assert role.model in _PRICE_PER_MTOK_OUT, (
                f"{profile_name}:{role_name} model {role.model!r} not priced (out)"
            )
    assert seen_sdk_role, "expected at least one sdk-routed role across bundled profiles"


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
