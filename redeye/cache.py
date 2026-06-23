"""Incremental cache for the deterministic structural pre-index.

Walking large repos with regex is fast (tens of milliseconds per
megabyte) but re-doing it every scan is wasted work when only a few
files changed. This cache keys each file's extracted hits by an
``(absolute_path, size, mtime_ns)`` triple, stored as a single JSON
file under ``~/.redeye/cache/structural/<sha256(target).json``.

On the next scan, files whose triple matches the cached entry are
served from cache; the rest are re-scanned. Cache hits never go stale
silently -- if a file's size or mtime changes by even one byte/ns we
rebuild.

This is the only state the harness keeps between runs (besides the
SQLite findings store, which is opt-in via ``--store-findings``). The
cache is purely a perf optimisation; deleting it is safe at any time.
"""

from __future__ import annotations

import hashlib
import json
import logging
import os
from dataclasses import dataclass
from pathlib import Path

log = logging.getLogger(__name__)

_CACHE_VERSION = 1


def _cache_root() -> Path:
    env = os.environ.get("REDEYE_CACHE_DIR")
    if env:
        return Path(env).expanduser()
    return Path.home() / ".redeye" / "cache" / "structural"


def _key_for_target(target: Path) -> str:
    return hashlib.sha256(str(target.resolve()).encode("utf-8")).hexdigest()[:24]


@dataclass
class _Entry:
    size: int
    mtime_ns: int
    hits: dict  # serialised StructuralHit-shaped dicts (routes/sources/sinks/secrets)


class StructuralCache:
    """File-keyed cache of structural hits for one target."""

    def __init__(self, target: Path) -> None:
        self.target = target.resolve()
        self.cache_root = _cache_root()
        self.cache_file = self.cache_root / f"{_key_for_target(self.target)}.json"
        self._entries: dict[str, _Entry] = {}
        self._loaded = False

    def load(self) -> None:
        if self._loaded:
            return
        self._loaded = True
        try:
            if not self.cache_file.is_file():
                return
            raw = json.loads(self.cache_file.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as exc:
            log.debug("cache: failed to load %s: %s", self.cache_file, exc)
            return
        if int(raw.get("version", 0)) != _CACHE_VERSION:
            return
        for path, entry in (raw.get("files") or {}).items():
            try:
                self._entries[path] = _Entry(
                    size=int(entry["size"]),
                    mtime_ns=int(entry["mtime_ns"]),
                    hits=entry.get("hits", {}),
                )
            except (KeyError, TypeError, ValueError):
                continue

    def lookup(self, path: Path) -> dict | None:
        """Return the cached hits for ``path`` if still valid, else None."""
        self.load()
        key = str(path)
        entry = self._entries.get(key)
        if entry is None:
            return None
        try:
            stat = path.stat()
        except OSError:
            return None
        if stat.st_size != entry.size or stat.st_mtime_ns != entry.mtime_ns:
            return None
        return entry.hits

    def store(self, path: Path, hits: dict) -> None:
        """Add or update an entry. Call :meth:`save` to persist."""
        self.load()
        try:
            stat = path.stat()
        except OSError:
            return
        self._entries[str(path)] = _Entry(size=stat.st_size, mtime_ns=stat.st_mtime_ns, hits=hits)

    def save(self) -> None:
        try:
            self.cache_root.mkdir(parents=True, exist_ok=True)
            payload = {
                "version": _CACHE_VERSION,
                "target": str(self.target),
                "files": {
                    p: {"size": e.size, "mtime_ns": e.mtime_ns, "hits": e.hits}
                    for p, e in self._entries.items()
                },
            }
            self.cache_file.write_text(json.dumps(payload, separators=(",", ":")), encoding="utf-8")
        except OSError as exc:
            log.debug("cache: failed to save %s: %s", self.cache_file, exc)

    def stats(self) -> dict:
        return {
            "cache_file": str(self.cache_file),
            "entries": len(self._entries),
        }
