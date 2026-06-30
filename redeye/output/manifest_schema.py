"""JSON Schema for ``run_manifest.json``.

The manifest is RedEye's audit record and the contract downstream tooling
(dashboards, policy engines, CI gates) reads. We derive a standard JSON
Schema (draft 2020-12) straight from the :class:`~redeye.schema.RunManifest`
Pydantic model so the schema can never drift from what we actually emit.

``write_manifest`` drops a ``run_manifest.schema.json`` next to every manifest
so consumers can validate without importing RedEye. :func:`validate_manifest_file`
validates a manifest: it uses the ``jsonschema`` package when available, and
otherwise falls back to Pydantic's own validation (no extra dependency).
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from redeye.schema import RunManifest

SCHEMA_FILENAME = "run_manifest.schema.json"


def manifest_json_schema() -> dict[str, Any]:
    """Return the JSON Schema (draft 2020-12) for a run manifest."""
    schema = RunManifest.model_json_schema()
    schema["$schema"] = "https://json-schema.org/draft/2020-12/schema"
    schema["title"] = "RedEye run_manifest.json"
    return schema


def write_manifest_schema(output_dir: Path) -> Path:
    """Write ``run_manifest.schema.json`` into ``output_dir`` and return it."""
    output_dir.mkdir(parents=True, exist_ok=True)
    path = output_dir / SCHEMA_FILENAME
    path.write_text(
        json.dumps(manifest_json_schema(), indent=2, sort_keys=True), encoding="utf-8"
    )
    return path


def validate_manifest_obj(obj: dict[str, Any]) -> list[str]:
    """Validate a manifest dict; return a list of human-readable errors.

    Empty list means valid. Prefers ``jsonschema`` (true schema validation)
    and falls back to Pydantic when it isn't installed.
    """
    try:
        import jsonschema  # type: ignore

        validator_cls = jsonschema.validators.validator_for(manifest_json_schema())
        validator = validator_cls(manifest_json_schema())
        return [
            f"{'/'.join(str(p) for p in e.path) or '<root>'}: {e.message}"
            for e in sorted(validator.iter_errors(obj), key=lambda e: list(e.path))
        ]
    except ImportError:
        from pydantic import ValidationError

        try:
            RunManifest.model_validate(obj)
        except ValidationError as exc:
            return [str(exc)]
        return []


def validate_manifest_file(path: Path) -> list[str]:
    """Validate a ``run_manifest.json`` file. Empty list means valid."""
    try:
        obj = json.loads(Path(path).read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        return [f"could not read/parse manifest: {exc}"]
    return validate_manifest_obj(obj)
