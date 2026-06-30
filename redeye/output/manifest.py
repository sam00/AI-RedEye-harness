"""Run manifest writer.

The manifest is the single source of truth for "what did this run actually
do" and is intentionally easy to diff: pretty-printed JSON with sorted keys.
It lands at ``<output_dir>/run_manifest.json`` and is appended-only between
runs (each scan writes a timestamped manifest in addition to the canonical
filename).
"""

from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path

from redeye.schema import RunManifest


def write_manifest(output_dir: Path, manifest: RunManifest, *, redact: bool = True) -> Path:
    """Write the canonical + archived ``run_manifest.json``.

    When ``redact`` is True (default) obvious secret material (credential
    shapes, sensitive ``key: value`` pairs in embedded snippets / descriptions)
    is masked before the file is written. ``redact_secrets`` only replaces
    matched substrings with a quote-free token, so the JSON stays valid. The
    styled PDF is built from this manifest, so it inherits the redaction.
    """
    output_dir.mkdir(parents=True, exist_ok=True)

    canonical = output_dir / "run_manifest.json"
    timestamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    archived = output_dir / f"run_manifest_{timestamp}.json"

    payload = manifest.model_dump(mode="json")
    text = json.dumps(payload, indent=2, sort_keys=True)
    if redact:
        from redeye.redaction import redact_secrets

        text = redact_secrets(text)
    canonical.write_text(text, encoding="utf-8")
    archived.write_text(text, encoding="utf-8")

    # Drop the JSON Schema next to the manifest so downstream tooling can
    # validate it without importing RedEye.
    from redeye.output.manifest_schema import write_manifest_schema

    write_manifest_schema(output_dir)
    return canonical
