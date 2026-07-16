"""Guard: every Anthropic (``claude-*``) model id in a bundled profile is real.

Loaded straight from YAML with pyyaml so the check stays import-light (no
pydantic / backend imports) and can't be fooled by loader normalisation. The
``sdk`` backend forwards the id to the API verbatim; an unknown id 400s and the
backend silently degrades to mock while the manifest still claims the real
model ran -- so a stale id here is a correctness bug, not a cosmetic typo.

Non-Anthropic backends (``gpt-4o``, ``qwen2.5-coder:*``, ``mock-*``) are left
alone: only ids in the ``claude-`` namespace are checked against the valid set.
"""

from __future__ import annotations

from pathlib import Path

import yaml

_PROFILES_DIR = Path(__file__).resolve().parents[1] / "redeye" / "config" / "profiles"

# The only valid Anthropic model ids (mid-2026).
_VALID_ANTHROPIC_MODEL_IDS = {
    "claude-opus-4-8",
    "claude-sonnet-5",
    "claude-haiku-4-5-20251001",
    "claude-fable-5",
}


def _profile_files() -> list[Path]:
    files = sorted(_PROFILES_DIR.glob("*.yaml"))
    assert files, f"no bundled profiles found under {_PROFILES_DIR}"
    return files


def test_all_claude_model_ids_in_bundled_profiles_are_valid() -> None:
    offenders: list[str] = []
    for path in _profile_files():
        data = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
        for role_name, role in (data.get("roles") or {}).items():
            model = (role or {}).get("model", "")
            if model.startswith("claude-") and model not in _VALID_ANTHROPIC_MODEL_IDS:
                offenders.append(f"{path.name}:{role_name} -> {model}")
    assert not offenders, "invalid Anthropic model ids in profiles: " + ", ".join(offenders)
