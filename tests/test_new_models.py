"""Guards for the models RedEye ships first-class pricing/recognition for.

These lock in the additions requested for the 2026 model refresh:

* OpenAI: ``gpt-5.5``, ``gpt-5.5-cyber``, ``gpt-5.6``, ``gpt-5.6-sol`` must be
  priced in both directions (the OpenAI-compatible backend forwards *any*
  model string, but an unpriced model silently bills at the gpt-4o rate, which
  understates cost for the premium tier).
* Anthropic: ``claude-opus-4-8`` ("claude 4.8") must stay in the SDK's known
  set *and* the price table, so it's selectable per-role without tripping the
  unknown-model warning or mis-costing the run.
"""

from __future__ import annotations

from redeye.backends import openai_compat, sdk_anthropic

_NEW_OPENAI_MODELS = ("gpt-5.5", "gpt-5.5-cyber", "gpt-5.6", "gpt-5.6-sol")


def test_new_openai_models_are_priced_in_both_directions() -> None:
    for model in _NEW_OPENAI_MODELS:
        assert model in openai_compat._PRICE_PER_MTOK_IN, f"{model} missing input price"
        assert model in openai_compat._PRICE_PER_MTOK_OUT, f"{model} missing output price"
        assert openai_compat._PRICE_PER_MTOK_IN[model] > 0
        assert openai_compat._PRICE_PER_MTOK_OUT[model] > 0


def test_claude_opus_4_8_is_known_and_priced() -> None:
    assert "claude-opus-4-8" in sdk_anthropic.KNOWN_MODEL_IDS
    assert "claude-opus-4-8" in sdk_anthropic._PRICE_PER_MTOK_IN
    assert "claude-opus-4-8" in sdk_anthropic._PRICE_PER_MTOK_OUT
