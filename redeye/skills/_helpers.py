"""Shared helpers for skills: JSON extraction, light file enumeration, totals."""

from __future__ import annotations

import json
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Any

_FENCE_RE = re.compile(r"```(?:json)?\s*(\{.*?\}|\[.*?\])\s*```", re.DOTALL)
_LOOSE_OBJ_RE = re.compile(r"(\{.*\})", re.DOTALL)


@dataclass
class CompletionTotals:
    tokens_in: int = 0
    tokens_out: int = 0
    cost_usd: float = 0.0

    def add(self, *, tokens_in: int = 0, tokens_out: int = 0, cost_usd: float = 0.0) -> None:
        self.tokens_in += tokens_in
        self.tokens_out += tokens_out
        self.cost_usd += cost_usd


def extract_json(text: str) -> Any:
    """Pull the first JSON object/array from a (possibly noisy) LLM reply.

    Returns ``None`` if no parseable JSON was found. Tries fenced blocks
    first, then a greedy fallback.
    """
    if not text:
        return None
    m = _FENCE_RE.search(text)
    if m:
        try:
            return json.loads(m.group(1))
        except json.JSONDecodeError:
            pass
    m = _LOOSE_OBJ_RE.search(text)
    if m:
        try:
            return json.loads(m.group(1))
        except json.JSONDecodeError:
            pass
    return None


_INTERESTING_EXTS = {
    ".py",
    ".js",
    ".ts",
    ".tsx",
    ".jsx",
    ".java",
    ".kt",
    ".go",
    ".rb",
    ".php",
    ".rs",
    ".cpp",
    ".cc",
    ".c",
    ".h",
    ".cs",
    ".scala",
    ".swift",
    ".sol",
    ".tf",
    ".yml",
    ".yaml",
    ".json",
    ".sh",
    ".bash",
}

_IGNORE_DIRS = {
    ".git",
    "node_modules",
    "vendor",
    "dist",
    "build",
    "out",
    "target",
    "__pycache__",
    ".venv",
    "venv",
    ".tox",
}


def list_source_files(root: Path, max_files: int = 5000) -> list[Path]:
    """Return up to ``max_files`` source-like files under ``root``."""
    found: list[Path] = []
    for path in root.rglob("*"):
        parts = set(path.parts)
        if parts & _IGNORE_DIRS:
            continue
        if not path.is_file():
            continue
        if path.suffix.lower() in _INTERESTING_EXTS:
            found.append(path)
            if len(found) >= max_files:
                break
    return found


def short_repo_summary(root: Path, max_chars: int = 4000) -> str:
    """Return a concise textual snapshot of the repo for prompt context.

    We list directories, top files, and a few size/language hints. Real
    skills should walk into specific files; this is the orientation prompt.
    """
    lines = [f"Repo: {root}"]
    files = list_source_files(root, max_files=200)
    by_ext: dict[str, int] = {}
    for f in files:
        by_ext[f.suffix] = by_ext.get(f.suffix, 0) + 1
    lines.append(f"Files (sample): {len(files)}")
    for ext, cnt in sorted(by_ext.items(), key=lambda kv: -kv[1])[:10]:
        lines.append(f"  {ext}: {cnt}")
    top = sorted({p.relative_to(root).parts[0] for p in files if p.relative_to(root).parts})
    if top:
        lines.append("Top-level dirs/files: " + ", ".join(top[:30]))
    blob = "\n".join(lines)
    return blob[:max_chars]
