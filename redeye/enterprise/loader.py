"""File-first loaders for enterprise context (CMDB, CVE feed, controls).

Everything here is offline + deterministic: point it at JSON / YAML / CSV
files and get back validated models. Live connectors (GitHub Enterprise,
remote CVE feeds) build on these by producing the same record types.
"""

from __future__ import annotations

import csv
import json
from pathlib import Path
from typing import Any

import yaml
from pydantic import ValidationError

from redeye.enterprise.models import (
    CmdbRecord,
    ControlRecord,
    CveRecord,
    EnterpriseContext,
)
from redeye.errors import RedEyeError


class EnterpriseError(RedEyeError):
    """Raised when an enterprise context file is missing or malformed."""


def _read_structured(path: Path) -> Any:
    """Load a JSON / YAML / CSV file into plain Python objects."""
    if not path.exists():
        raise EnterpriseError(f"enterprise file not found: {path}")
    suffix = path.suffix.lower()
    try:
        text = path.read_text(encoding="utf-8")
        if suffix in (".yaml", ".yml"):
            return yaml.safe_load(text)
        if suffix == ".csv":
            return list(csv.DictReader(text.splitlines()))
        return json.loads(text)  # default: JSON
    except (yaml.YAMLError, json.JSONDecodeError, csv.Error, OSError) as exc:
        raise EnterpriseError(f"failed to parse {path}: {exc}") from exc


def _as_rows(data: Any, *, key: str | None = None) -> list[dict]:
    """Normalise a parsed file into a list of dict rows.

    Accepts a top-level list, or a mapping with an optional ``key``
    (e.g. ``{"cves": [...]}``) so feed files can be self-describing, or a
    single record mapping.
    """
    if data is None:
        return []
    if isinstance(data, list):
        return [r for r in data if isinstance(r, dict)]
    if isinstance(data, dict):
        if key and isinstance(data.get(key), list):
            return [r for r in data[key] if isinstance(r, dict)]
        return [data]
    raise EnterpriseError(f"expected a list or mapping, got {type(data).__name__}")


def load_cmdb(path: str | Path) -> dict[str, CmdbRecord]:
    """Load CMDB rows from a file, keyed by ``application_id``."""
    rows = _as_rows(_read_structured(Path(path)), key="assets")
    out: dict[str, CmdbRecord] = {}
    for row in rows:
        try:
            rec = CmdbRecord(**row)
        except ValidationError as exc:
            raise EnterpriseError(f"invalid CMDB record {row!r}: {exc}") from exc
        out[rec.application_id] = rec
    return out


def load_cve_feed(path: str | Path) -> list[CveRecord]:
    """Load a CVE feed file into :class:`CveRecord` objects."""
    rows = _as_rows(_read_structured(Path(path)), key="cves")
    try:
        return [CveRecord(**r) for r in rows]
    except ValidationError as exc:
        raise EnterpriseError(f"invalid CVE feed {path}: {exc}") from exc


def load_controls(path: str | Path) -> list[ControlRecord]:
    """Load a controls file into :class:`ControlRecord` objects."""
    rows = _as_rows(_read_structured(Path(path)), key="controls")
    try:
        return [ControlRecord(**r) for r in rows]
    except ValidationError as exc:
        raise EnterpriseError(f"invalid controls file {path}: {exc}") from exc


def build_enterprise_context(
    *,
    application_id: str | None = None,
    cmdb_path: str | Path | None = None,
    cve_path: str | Path | None = None,
    controls_path: str | Path | None = None,
) -> EnterpriseContext:
    """Assemble an :class:`EnterpriseContext` for one target from files.

    ``application_id`` selects the matching CMDB row (or the sole row if the
    file has exactly one). CVE / control feeds are loaded wholesale;
    filtering by component / CWE happens later, per finding.
    """
    cmdb_rec: CmdbRecord | None = None
    if cmdb_path:
        cmdb = load_cmdb(cmdb_path)
        if application_id:
            cmdb_rec = cmdb.get(application_id)
        elif len(cmdb) == 1:
            cmdb_rec = next(iter(cmdb.values()))

    return EnterpriseContext(
        cmdb=cmdb_rec,
        cves=load_cve_feed(cve_path) if cve_path else [],
        controls=load_controls(controls_path) if controls_path else [],
    )
