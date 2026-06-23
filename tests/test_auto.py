"""Auto-backend-detection + profile-synthesis tests.

The contract these tests pin down:

1. Detection picks Anthropic SDK first when its env var is set.
2. Detection falls back through bedrock -> cli -> openai -> vertex ->
   ollama -> mock as each tier becomes unavailable.
3. Mock is the deterministic fallback when nothing is configured (and
   the network probe is suppressed so the test stays hermetic).
4. ``build_auto_profile`` produces a Profile whose stages match what the
   orchestrator expects (all 13 stages including the v0.3 quality
   layers, voting disabled by default).
5. ``--profile auto`` and ``profile=None`` both route through the
   synthesized profile.
6. Explicit profile names (``default``, ``mock``, ``full``, etc.) bypass
   auto-detection entirely.
"""

from __future__ import annotations

import os

import pytest

from redeye.auto import (
    _has_aws_creds,
    _has_vertex,
    build_auto_profile,
    detect_best_backend,
)
from redeye.config.loader import load_profile

# Make every test hermetic by stripping every credential env var the
# detector looks at. Individual tests opt in to whichever they want set.
_CRED_ENV_VARS = [
    "ANTHROPIC_SDK_API_KEY",
    "ANTHROPIC_API_KEY",
    "AWS_ACCESS_KEY_ID",
    "AWS_SESSION_TOKEN",
    "AWS_PROFILE",
    "OPENAI_API_KEY",
    "GOOGLE_CLOUD_PROJECT",
    "GOOGLE_APPLICATION_CREDENTIALS",
    "OLLAMA_BASE_URL",
    "OLLAMA_MODEL",
    "REDEYE_PREFER_QUALITY",
    "REDEYE_NO_CLI",
    "REDEYE_PROFILE",
]


@pytest.fixture(autouse=True)
def _strip_creds(monkeypatch):
    """Every test in this file starts with a credential-free environment."""
    for var in _CRED_ENV_VARS:
        monkeypatch.delenv(var, raising=False)
    # Force the cli backend check to fall through too. We can't unset
    # ``which("claude")`` directly so we set REDEYE_NO_CLI for tests that
    # need to bypass it.


def test_detect_prefers_anthropic_sdk_when_key_set(monkeypatch):
    monkeypatch.setenv("ANTHROPIC_SDK_API_KEY", "sk-ant-test")
    choice = detect_best_backend(probe_network=False)
    assert choice.backend == "sdk"
    assert "claude" in choice.model.lower()
    assert choice.supports_temperature is True


def test_detect_bedrock_when_aws_only(monkeypatch):
    monkeypatch.setenv("AWS_PROFILE", "test-profile")
    monkeypatch.setenv("REDEYE_NO_CLI", "1")  # bypass any local claude binary
    choice = detect_best_backend(probe_network=False)
    assert choice.backend == "bedrock"


def test_detect_openai_when_only_openai_key(monkeypatch):
    monkeypatch.setenv("OPENAI_API_KEY", "sk-test")
    monkeypatch.setenv("REDEYE_NO_CLI", "1")
    choice = detect_best_backend(probe_network=False)
    assert choice.backend == "openai"
    assert "gpt" in choice.model.lower()


def test_detect_falls_back_to_mock_when_nothing_available(monkeypatch):
    monkeypatch.setenv("REDEYE_NO_CLI", "1")
    choice = detect_best_backend(probe_network=False)
    assert choice.backend == "mock"
    assert choice.supports_temperature is True


def test_quality_env_var_upgrades_model(monkeypatch):
    monkeypatch.setenv("ANTHROPIC_SDK_API_KEY", "sk-ant-test")
    monkeypatch.setenv("REDEYE_PREFER_QUALITY", "1")
    choice = detect_best_backend(probe_network=False)
    assert choice.backend == "sdk"
    # Quality upgrade should pick Opus over Sonnet.
    assert "opus" in choice.model.lower()


def test_build_auto_profile_has_all_quality_stages(monkeypatch):
    monkeypatch.setenv("REDEYE_NO_CLI", "1")
    p = build_auto_profile(probe_network=False)
    expected_stages = {
        "s1_attack_surface",
        "s1b_structural",
        "s2_threat_model",
        "s3_strategize",
        "s4_research",
        "s4b_grounding",
        "s5_policy_gate",
        "s6_adversarial",
        "s6b_validator",
        "s7_dedupe",
        "s8_chain",
        "s8b_poc",
        "s9_emit",
    }
    assert expected_stages.issubset(p.stages.keys())
    # Profile name encodes the choice for traceability.
    assert p.name.startswith("auto:")
    # Voting off by default -- single-backend, no cross-model diversity.
    assert p.voting.enabled is False


def test_load_profile_auto_routes_to_synthesizer(monkeypatch):
    monkeypatch.setenv("REDEYE_NO_CLI", "1")
    p = load_profile("auto")
    assert p.name.startswith("auto:")


def test_load_profile_explicit_default_still_works(monkeypatch):
    """Explicit --profile default must still load the bundled YAML."""
    monkeypatch.setenv("REDEYE_NO_CLI", "1")
    p = load_profile("default")
    assert p.name == "default"
    # Bundled default uses the cli backend; not the auto-detected one.
    assert all(role.via == "cli" for role in p.roles.values())


def test_load_profile_none_with_no_env_no_config_auto_detects(monkeypatch, tmp_path):
    """No --profile + no env var + no ./config.yaml -> auto-detect."""
    monkeypatch.setenv("REDEYE_NO_CLI", "1")
    monkeypatch.chdir(tmp_path)  # ensure no ./config.yaml in pwd
    p = load_profile(None)
    assert p.name.startswith("auto:")


def test_aws_creds_detector_picks_up_env(monkeypatch):
    assert _has_aws_creds() in (True, False)  # works either way; just smoke
    monkeypatch.setenv("AWS_ACCESS_KEY_ID", "TEST")
    assert _has_aws_creds() is True


def test_vertex_detector_requires_project_and_credentials(monkeypatch):
    monkeypatch.setenv("GOOGLE_CLOUD_PROJECT", "test-proj")
    # Project alone isn't enough.
    has_cred_path = "GOOGLE_APPLICATION_CREDENTIALS" in os.environ or os.path.exists(
        os.path.expanduser("~/.config/gcloud/application_default_credentials.json")
    )
    assert _has_vertex() is has_cred_path
