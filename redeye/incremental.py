"""Incremental scans: skip files unchanged since a prior run's manifest.

CI re-runs usually touch a handful of files, yet a naive scan re-reads the
whole tree. ``--incremental`` records a per-file content hash in the manifest
(``RunManifest.file_hashes``) and, on the next run, restricts the scope to
files whose hash is new or changed. It's content-based (robust to mtime churn
and rebases) and complements ``--diff-only`` (which is git-ref based).
"""

from __future__ import annotations

import hashlib
import json
import logging
from pathlib import Path

log = logging.getLogger(__name__)


def _rel(target: Path, path: Path) -> str:
    try:
        return str(path.relative_to(target))
    except ValueError:
        return str(path)


def hash_files(target: Path, files: list[Path]) -> dict[str, str]:
    """Return ``{relative_path: sha256}`` for ``files`` (unreadable files skipped)."""
    out: dict[str, str] = {}
    for p in files:
        try:
            out[_rel(target, p)] = hashlib.sha256(p.read_bytes()).hexdigest()
        except OSError as exc:
            log.debug("incremental: could not hash %s: %s", p, exc)
    return out


def load_prior_hashes(manifest_path: Path) -> dict[str, str]:
    """Read ``file_hashes`` from a prior ``run_manifest.json`` (empty if absent)."""
    try:
        data = json.loads(manifest_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return {}
    fh = data.get("file_hashes")
    return fh if isinstance(fh, dict) else {}


def changed_files(
    target: Path, files: list[Path], prior: dict[str, str]
) -> tuple[list[Path], dict[str, str]]:
    """Partition ``files`` into those changed-vs-prior; also return current hashes.

    A file is "changed" when its path is new or its hash differs from ``prior``.
    When ``prior`` is empty (first run) every file is considered changed.
    """
    current = hash_files(target, files)
    if not prior:
        return list(files), current
    changed: list[Path] = []
    for p in files:
        rel = _rel(target, p)
        if prior.get(rel) != current.get(rel):
            changed.append(p)
    return changed, current
