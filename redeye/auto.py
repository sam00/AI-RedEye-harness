"""Auto-detect the best-available LLM backend and synthesize a runtime profile.

When the operator runs ``redeye scan`` without specifying ``--profile`` (and
without ``$REDEYE_PROFILE`` or a ``./config.yaml`` in cwd), the loader calls
:func:`build_auto_profile` instead of falling back to the bundled
``default.yaml``. The auto profile inspects what credentials and CLIs are
actually available on the machine and picks the strongest reasonable
backend, routes every stage through it, and enables the v0.3 quality
layers (S1b structural, S4b grounding, S6.5 validator, S8b PoC gate).

Detection priority (most preferred first):

1. **Anthropic SDK** -- if ``ANTHROPIC_SDK_API_KEY`` or
   ``ANTHROPIC_API_KEY`` is set. Sonnet-4.6 with temperature control.
2. **AWS Bedrock** -- if AWS credentials are reachable. Sonnet-3.5 via
   Bedrock; same model family, enterprise infra.
3. **Claude Code CLI** -- if ``claude`` is on PATH. Sonnet-4.6 via CLI;
   no API key needed, no temperature control.
4. **OpenAI** -- if ``OPENAI_API_KEY`` is set. GPT-4o with temperature.
5. **Vertex / Gemini** -- if GCP project + ADC are configured. Gemini
   2.5 Pro with temperature.
6. **Ollama** -- if a local Ollama server is reachable on
   ``OLLAMA_BASE_URL`` (default ``http://localhost:11434``). Whatever
   model the user has pulled (default ``qwen2.5-coder:14b``).
7. **Mock** -- deterministic fallback when nothing else is available.
   Zero LLM cost, perfect for first-time runs and CI smoke tests.

The detection is intentionally conservative -- it picks Sonnet-class
models rather than Opus-class even when both might be available, because
RedEye's deterministic grounding and PoC layers already do the heavy
precision lifting and Sonnet is the cost-quality sweet spot. Operators
who want the strongest available model can either select ``--profile
fable`` (Claude Fable 5 on the SDK backend) or ``--profile full`` for a
multi-backend layout, or pass ``REDEYE_PREFER_QUALITY=1`` -- which on the
SDK backend upgrades the auto profile to Claude Fable 5 (see below).
"""

from __future__ import annotations

import logging
import os
import shutil
from dataclasses import dataclass

import httpx

from redeye.config.loader import Profile, Role, Stage, Voting

log = logging.getLogger(__name__)


@dataclass(frozen=True)
class BackendChoice:
    """The result of one detection pass."""

    backend: str  # one of: sdk, bedrock, cli, openai, vertex, ollama, mock
    model: str
    why: str
    supports_temperature: bool


# Model strings used when REDEYE_PREFER_QUALITY=1 upgrades to "strongest"
# tier. On the Anthropic SDK this is Claude Fable 5 -- the strongest
# generally-available model; other backends keep their conservative top tier.
_QUALITY_UPGRADES: dict[str, str] = {
    "sdk": "claude-fable-5",
    "bedrock": "anthropic.claude-opus-4-5-20251101-v1:0",
    "cli": "claude-sonnet-4-6",  # CLI can't pin Opus reliably; keep Sonnet
    "openai": "gpt-4o",
    "vertex": "gemini-2.5-pro",
    "ollama": "qwen2.5-coder:32b",
}


def _has_aws_creds() -> bool:
    """Best-effort detection: env vars OR a populated ``~/.aws``."""
    if os.environ.get("AWS_ACCESS_KEY_ID") or os.environ.get("AWS_SESSION_TOKEN"):
        return True
    if os.environ.get("AWS_PROFILE"):
        return True
    creds = os.path.expanduser("~/.aws/credentials")
    config = os.path.expanduser("~/.aws/config")
    return os.path.exists(creds) or os.path.exists(config)


def _has_vertex() -> bool:
    """Need both a project ID and an authenticated identity (SA key or ADC)."""
    if not os.environ.get("GOOGLE_CLOUD_PROJECT"):
        return False
    if os.environ.get("GOOGLE_APPLICATION_CREDENTIALS"):
        return True
    adc = os.path.expanduser("~/.config/gcloud/application_default_credentials.json")
    return os.path.exists(adc)


def _ollama_reachable(timeout: float = 0.6) -> bool:
    """Quick probe -- 600ms cap so this never adds perceptible latency."""
    base = os.environ.get("OLLAMA_BASE_URL", "http://localhost:11434").rstrip("/")
    try:
        with httpx.Client(timeout=timeout) as client:
            resp = client.get(f"{base}/api/tags")
        return resp.status_code == 200
    except httpx.HTTPError:
        return False


def detect_best_backend(*, probe_network: bool = True) -> BackendChoice:
    """Walk the priority list and return the first backend that's available.

    ``probe_network=False`` skips the Ollama HTTP probe; useful for unit
    tests that don't want any network interaction.
    """
    quality = os.environ.get("REDEYE_PREFER_QUALITY") == "1"

    def _model(default: str, backend_name: str) -> str:
        return _QUALITY_UPGRADES[backend_name] if quality else default

    if os.environ.get("ANTHROPIC_SDK_API_KEY") or os.environ.get("ANTHROPIC_API_KEY"):
        return BackendChoice(
            backend="sdk",
            model=_model("claude-sonnet-4-6", "sdk"),
            why="Anthropic SDK key detected",
            supports_temperature=True,
        )

    if _has_aws_creds():
        return BackendChoice(
            backend="bedrock",
            model=_model("anthropic.claude-3-5-sonnet-20241022-v2:0", "bedrock"),
            why="AWS credentials detected",
            supports_temperature=True,
        )

    if shutil.which("claude") and not os.environ.get("REDEYE_NO_CLI"):
        return BackendChoice(
            backend="cli",
            model=_model("claude-sonnet-4-6", "cli"),
            why="claude CLI on PATH",
            supports_temperature=False,
        )

    if os.environ.get("OPENAI_API_KEY"):
        return BackendChoice(
            backend="openai",
            model=_model("gpt-4o", "openai"),
            why="OPENAI_API_KEY detected",
            supports_temperature=True,
        )

    if _has_vertex():
        return BackendChoice(
            backend="vertex",
            model=_model("gemini-2.5-pro", "vertex"),
            why="GCP project + credentials detected",
            supports_temperature=True,
        )

    if probe_network and _ollama_reachable():
        ollama_model = os.environ.get("OLLAMA_MODEL") or _model("qwen2.5-coder:14b", "ollama")
        return BackendChoice(
            backend="ollama",
            model=ollama_model,
            why=f"Ollama server reachable -- using {ollama_model}",
            supports_temperature=True,
        )

    return BackendChoice(
        backend="mock",
        model="mock-deep",
        why="no LLM credentials detected -- using deterministic mock",
        supports_temperature=True,
    )


def build_auto_profile(*, probe_network: bool = True) -> Profile:
    """Pick the best-available backend and return a Profile that uses it.

    Every stage gets routed through the same backend. The v0.3 quality
    layers (S1b structural, S4b grounding, S6.5 validator, S8b PoC gate)
    are enabled by default because they're deterministic / cheap and they
    materially improve precision. Multi-agent voting is enabled only when
    the backend supports temperature -- without temperature there's no
    sampling diversity to vote with.
    """
    choice = detect_best_backend(probe_network=probe_network)

    # One role used by the "heavy" stages, one cheaper for surveyor / reporter
    # / validator. Both currently use the same model -- the difference is
    # just max_tokens so we don't pay for long outputs where short ones do.
    deep_role = Role(
        via=choice.backend,
        model=choice.model,
        temperature=0.0 if choice.supports_temperature else None,
        max_tokens=8192,
    )
    cheap_role = Role(
        via=choice.backend,
        model=choice.model,
        temperature=0.0 if choice.supports_temperature else None,
        max_tokens=4096,
    )

    roles = {
        "surveyor": cheap_role,
        "researcher": deep_role,
        "adversary": deep_role,
        "reporter": cheap_role,
        "validator": cheap_role,
    }

    stages = {
        "s1_attack_surface": Stage(
            skill="attack_surface_mapper", role="surveyor", max_budget_usd=0.5
        ),
        "s1b_structural": Stage(skill="structural_index", role="surveyor", max_budget_usd=0.0),
        "s2_threat_model": Stage(skill="threat_modeler", role="surveyor", max_budget_usd=0.5),
        "s3_strategize": Stage(skill="research_strategist", role="researcher", max_budget_usd=0.5),
        "s4_research": Stage(
            skill="research_lenses",
            role="researcher",
            max_budget_usd=4.0,
            params={"lenses": ["language", "crypto", "logic", "access_control", "iac"]},
        ),
        "s4b_grounding": Stage(
            skill="grounding_pass", role="surveyor", max_budget_usd=0.0, params={"strict": False}
        ),
        "s5_policy_gate": Stage(skill="policy_gate", role="surveyor", max_budget_usd=0.2),
        "s6_adversarial": Stage(skill="adversarial_reviewer", role="adversary", max_budget_usd=2.0),
        "s6b_validator": Stage(skill="validator", role="validator", max_budget_usd=0.5),
        "s7_dedupe": Stage(skill="dedupe", role="reporter", max_budget_usd=0.1),
        "s8_chain": Stage(skill="exploit_strategist", role="reporter", max_budget_usd=1.0),
        "s8b_poc": Stage(
            skill="poc_gate", role="validator", max_budget_usd=0.5, params={"strict": False}
        ),
        "s8c_verify": Stage(
            skill="outcome_verifier",
            role="validator",
            max_budget_usd=0.0,
            params={"threshold": 3, "strict": False},
        ),
        "s9_emit": Stage(skill="emit", role="reporter", max_budget_usd=0.1),
    }

    voting = Voting(
        enabled=False,  # single-backend auto profile -- no cross-model diversity to vote with
        quorum=1,
        voters=[],
    )

    return Profile(
        name=f"auto:{choice.backend}:{choice.model}",
        source_path=f"<synthesized at runtime -- {choice.why}>",
        roles=roles,
        stages=stages,
        voting=voting,
    )
