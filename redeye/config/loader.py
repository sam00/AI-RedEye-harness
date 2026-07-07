"""Profile loader.

A *profile* is a YAML file with three top-level keys:

```yaml
roles:           # logical role -> {via: backend_name, model: id, temperature: 0.0}
  surveyor: ...
  researcher: ...
  adversary: ...
stages:          # stage_id -> {skill, role, max_budget_usd, params: {...}}
  s1_attack_surface: ...
  ...
voting:          # optional; multi-agent voting parameters
  enabled: true
  quorum: 2
  voters: [researcher, adversary]
```

The loader normalises the result into a :class:`Profile` (pydantic model)
that all downstream code can rely on without re-parsing YAML.
"""

from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
from typing import Any

import yaml
from pydantic import BaseModel, Field

from redeye.errors import ConfigError

_BUILTIN_PROFILES_DIR = Path(__file__).parent / "profiles"


class Role(BaseModel):
    """One logical role (e.g. `surveyor`, `researcher`, `adversary`)."""

    via: str = Field(..., description="Backend name: cli | sdk | openai | mock")
    model: str = Field(..., description="Model identifier, e.g. claude-sonnet-4-6")
    temperature: float | None = Field(default=None, ge=0.0, le=2.0)
    max_tokens: int = Field(default=4096, ge=128)
    extra: dict[str, Any] = Field(default_factory=dict)


class Stage(BaseModel):
    """One pipeline stage configuration."""

    skill: str
    role: str
    max_budget_usd: float = Field(default=1.0, ge=0.0)
    params: dict[str, Any] = Field(default_factory=dict)


class Voting(BaseModel):
    """Multi-agent voting config for FP suppression at S6."""

    enabled: bool = True
    quorum: int = Field(default=2, ge=1)
    voters: list[str] = Field(default_factory=list)


class Profile(BaseModel):
    """Validated, loaded profile. Hashable via :meth:`config_hash`."""

    name: str
    source_path: str
    roles: dict[str, Role]
    stages: dict[str, Stage]
    voting: Voting = Field(default_factory=Voting)

    def config_hash(self) -> str:
        """Stable SHA-256 of the profile content. Used in run_manifest.json."""
        payload = self.model_dump(exclude={"source_path"})
        canonical = json.dumps(payload, sort_keys=True, default=str)
        return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


def _candidate_paths(profile: str | None) -> tuple[list[Path], bool]:
    """Build the resolution order list.

    Returns (candidates, strict). ``strict`` is True when the user explicitly
    passed a ``--profile`` value -- in that mode we refuse to fall back to
    the default if the named profile is missing, because silently picking a
    different profile would surprise the operator.
    """
    candidates: list[Path] = []
    strict = bool(profile)
    if profile:
        p = Path(profile)
        if p.suffix in (".yaml", ".yml") and p.exists():
            candidates.append(p)
        else:
            candidates.append(_BUILTIN_PROFILES_DIR / f"{profile}.yaml")
        return candidates, strict

    env = os.environ.get("REDEYE_PROFILE")
    if env:
        candidates.append(_BUILTIN_PROFILES_DIR / f"{env}.yaml")
    cwd_config = Path.cwd() / "config.yaml"
    if cwd_config.exists():
        candidates.append(cwd_config)
    candidates.append(_BUILTIN_PROFILES_DIR / "default.yaml")
    return candidates, strict


def load_profile(profile: str | None = None) -> Profile:
    """Resolve and load a profile. Raises :class:`ConfigError` on failure.

    Special cases handled before the YAML resolution chain:

    - ``profile == "auto"`` -- synthesize a profile at runtime by detecting
      the best-available backend on the operator's machine. See
      :mod:`redeye.auto`.
    - ``profile is None`` AND no ``REDEYE_PROFILE`` env var AND no
      ``./config.yaml`` -- fall back to ``auto`` (rather than the bundled
      ``default.yaml``) so new users get a working scan without first
      learning what profiles exist. If the operator wants the literal
      bundled default, they can pass ``--profile default`` explicitly.
    """
    if profile == "auto":
        from redeye.auto import build_auto_profile

        return build_auto_profile()

    if (
        profile is None
        and not os.environ.get("REDEYE_PROFILE")
        and not (Path.cwd() / "config.yaml").exists()
    ):
        from redeye.auto import build_auto_profile

        return build_auto_profile()

    candidates, strict = _candidate_paths(profile)
    last_error: Exception | None = None
    for candidate in candidates:
        if not candidate.exists():
            continue
        try:
            with candidate.open() as fh:
                raw = yaml.safe_load(fh) or {}
        except yaml.YAMLError as exc:
            raise ConfigError(f"YAML error in {candidate}: {exc}") from exc

        if not isinstance(raw, dict):
            raise ConfigError(f"{candidate}: top-level must be a mapping, got {type(raw).__name__}")

        try:
            roles = {k: Role(**v) for k, v in (raw.get("roles") or {}).items()}
            stages = {k: Stage(**v) for k, v in (raw.get("stages") or {}).items()}
            voting_raw = raw.get("voting") or {}
            return Profile(
                name=raw.get("name") or candidate.stem,
                source_path=str(candidate),
                roles=roles,
                stages=stages,
                voting=Voting(**voting_raw),
            )
        except Exception as exc:  # noqa: BLE001
            last_error = exc
            continue

    if last_error is not None:
        raise ConfigError(f"Failed to load any profile: {last_error}")
    if strict:
        raise ConfigError(
            f"Profile {profile!r} not found. Use one of: default, cli, full, fable, mock; "
            f"or pass a path to a YAML file."
        )
    raise ConfigError("No profile found and no built-in default available.")
