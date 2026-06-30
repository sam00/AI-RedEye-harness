"""S2 skill -- STRIDE/OWASP threat modeling against the S1 attack surface.

Configurable via the ``s2_threat_model`` stage ``params`` in config.yaml:

- ``enabled`` (bool, default True)        -- handled by the stage; skips S2.
- ``max_threats`` (int, 0 = unlimited)    -- cap the emitted STRIDE list.
- ``baseline`` (path)                     -- YAML/JSON of accepted threat
  signatures (``category|asset``) to subtract from the output.
- ``max_document_chars`` (int)            -- cap the attack-surface document
  fed into the prompt (manifest/document cap).
- evidence caps -- how many structural items of each kind are injected:
  ``max_modules``, ``max_entry_points``, ``max_config_reps``,
  ``max_api_artifacts`` (each 0 = unlimited).
"""

from __future__ import annotations

import json
import logging
from pathlib import Path
from typing import Any

import yaml

from redeye.backends.base import BackendBase, CompletionResult
from redeye.skills._helpers import extract_json

log = logging.getLogger(__name__)

_SYSTEM = """\
You are doing STRIDE threat modeling for a service. Given the attack surface
JSON, return a JSON object with: actors (list), trust_boundaries (list),
stride (list of {category, asset, score, note}), top_risks (list of strings).
Be terse. The downstream consumer is automated tooling, not humans.
"""


def _cap(items: list, n: int) -> list:
    """Return at most ``n`` items (``n <= 0`` means unlimited)."""
    return items[:n] if n and n > 0 else items


def _build_evidence(
    attack_surface: dict[str, Any], structural_index: dict[str, Any], caps: dict[str, int]
) -> dict[str, Any]:
    """Assemble a capped evidence block from S1 + S1b for the prompt.

    Each category is bounded by its cap so the threat model stays focused and
    cheap: modules, entry points, config representatives, API artifacts.
    """
    routes = structural_index.get("routes", []) or []
    secrets = structural_index.get("secrets", []) or []
    all_hits = (
        routes
        + (structural_index.get("sources", []) or [])
        + (structural_index.get("sinks", []) or [])
        + secrets
    )
    # modules = distinct top-level path segments across all structural hits.
    modules: list[str] = []
    for h in all_hits:
        seg = str(h.get("path", "")).replace("\\", "/").split("/", 1)[0]
        if seg and seg not in modules:
            modules.append(seg)

    entry_points = [r.get("snippet") or r.get("path") for r in routes]
    api_artifacts = list(attack_surface.get("entrypoints", []) or [])
    config_reps = [f"{s.get('path')}:{s.get('line')}" for s in secrets]

    evidence = {
        "modules": _cap(modules, caps.get("modules", 0)),
        "entry_points": _cap(entry_points, caps.get("entry_points", 0)),
        "api_artifacts": _cap(api_artifacts, caps.get("api_artifacts", 0)),
        "config_reps": _cap(config_reps, caps.get("config_reps", 0)),
    }
    # Drop empty categories so the prompt stays terse.
    return {k: v for k, v in evidence.items() if v}


def _threat_sig(threat: Any) -> str:
    if not isinstance(threat, dict):
        return str(threat).strip().lower()
    return f"{threat.get('category', '')}|{threat.get('asset', '')}".strip().lower()


def _load_threat_baseline(path: str | None) -> set[str]:
    """Load accepted threat signatures (``category|asset``) from a file."""
    if not path:
        return set()
    p = Path(path)
    if not p.is_file():
        log.warning("threat baseline not found: %s", p)
        return set()
    try:
        text = p.read_text(encoding="utf-8")
        data = yaml.safe_load(text) if p.suffix in (".yaml", ".yml") else json.loads(text)
    except (yaml.YAMLError, json.JSONDecodeError, OSError) as exc:
        log.warning("failed to load threat baseline %s: %s", p, exc)
        return set()
    rows = data.get("accepted", data) if isinstance(data, dict) else data
    out: set[str] = set()
    for row in rows or []:
        out.add(_threat_sig(row))
    return out


def build_threat_model(
    *,
    target: Path,
    attack_surface: dict[str, Any],
    backend: BackendBase,
    model: str,
    temperature: float | None,
    max_tokens: int,
    max_budget_usd: float,
    structural_index: dict[str, Any] | None = None,
    params: dict[str, Any] | None = None,
) -> tuple[dict[str, Any], CompletionResult]:
    params = params or {}
    max_doc = int(params.get("max_document_chars", 6000) or 6000)
    caps = {
        "modules": int(params.get("max_modules", 0) or 0),
        "entry_points": int(params.get("max_entry_points", 0) or 0),
        "config_reps": int(params.get("max_config_reps", 0) or 0),
        "api_artifacts": int(params.get("max_api_artifacts", 0) or 0),
    }

    user = "Attack surface:\n\n" + json.dumps(attack_surface, indent=2)[:max_doc]
    evidence = _build_evidence(attack_surface, structural_index or {}, caps)
    if evidence:
        user += "\n\nStructural evidence (capped):\n" + json.dumps(evidence, indent=2)[:max_doc]

    completion = backend.complete(
        system=_SYSTEM,
        user=user,
        model=model,
        max_tokens=max_tokens,
        temperature=temperature,
    )
    parsed = extract_json(completion.text) or {}
    if not isinstance(parsed, dict):
        parsed = {"summary": str(parsed)[:500]}

    # Subtract accepted threats from the baseline, then cap the count.
    baseline = _load_threat_baseline(params.get("baseline"))
    if baseline and isinstance(parsed.get("stride"), list):
        parsed["stride"] = [t for t in parsed["stride"] if _threat_sig(t) not in baseline]
    max_threats = int(params.get("max_threats", 0) or 0)
    if max_threats > 0 and isinstance(parsed.get("stride"), list):
        parsed["stride"] = parsed["stride"][:max_threats]

    return parsed, completion
