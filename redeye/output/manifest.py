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
from typing import Any

from redeye.schema import RunManifest


def write_manifest(output_dir: Path, manifest: RunManifest, *, redact: bool = True) -> Path:
    """Write the canonical + archived ``run_manifest.json``.

    When ``redact`` is True (default) obvious secret material (credential
    shapes, sensitive ``key: value`` pairs in embedded snippets / descriptions)
    is masked before the file is written. Redaction runs over the payload's
    string *values* (via ``redact_obj``) rather than the serialized JSON, so the
    serializer always re-escapes correctly and the manifest stays valid JSON --
    masking the serialized text could eat an escaped ``\\"`` and corrupt it. The
    styled PDF / HTML are built from this manifest, so they inherit the masking.
    """
    output_dir.mkdir(parents=True, exist_ok=True)

    canonical = output_dir / "run_manifest.json"
    timestamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    archived = output_dir / f"run_manifest_{timestamp}.json"

    payload: Any = manifest.model_dump(mode="json")
    if redact:
        from redeye.redaction import redact_obj

        payload = redact_obj(payload)
    text = json.dumps(payload, indent=2, sort_keys=True)
    canonical.write_text(text, encoding="utf-8")
    archived.write_text(text, encoding="utf-8")

    # Drop the JSON Schema next to the manifest so downstream tooling can
    # validate it without importing RedEye.
    from redeye.output.manifest_schema import write_manifest_schema

    write_manifest_schema(output_dir)
    return canonical
