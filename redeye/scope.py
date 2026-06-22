"""Scope -- which files does the pipeline actually look at?

A scan is parameterised by:

- ``target``    -- repo root.
- ``diff_only`` -- if True, only files changed vs ``pr_base``.
- ``pr_base``   -- the merge-base / base-branch ref (e.g. ``origin/main``).
- ``exclude_paths`` -- substrings of paths to drop (e.g. ``test``, ``vendor``).
- DoS limits    -- max files, max bytes per file, max bytes total.

The :class:`Scope` object is built once per run and passed to every stage
and skill via the orchestrator's ``StageContext``. Skills that walk the
filesystem should use :meth:`Scope.iter_files` so the same exclusions and
limits apply consistently.
"""

from __future__ import annotations

import logging
import os
import subprocess
from collections.abc import Iterator
from dataclasses import dataclass, field
from pathlib import Path

log = logging.getLogger(__name__)

_DEFAULT_IGNORE_DIRS = {
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
    ".mypy_cache",
    ".pytest_cache",
    ".ruff_cache",
}

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
    ".hpp",
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
    ".dockerfile",
    "Dockerfile",
}


@dataclass
class Scope:
    """Decides which files the pipeline touches and reports skips."""

    target: Path
    diff_only: bool = False
    pr_base: str = "main"
    exclude_paths: list[str] = field(default_factory=list)
    max_files: int = 0  # 0 = unlimited
    max_file_bytes: int = 0
    max_total_bytes: int = 0

    # Populated by :meth:`build`.
    files: list[Path] = field(default_factory=list)
    skipped_oversize: list[Path] = field(default_factory=list)
    skipped_excluded: list[Path] = field(default_factory=list)
    skipped_truncated: int = 0
    total_bytes: int = 0
    diff_files: list[Path] | None = None

    @classmethod
    def build(
        cls,
        *,
        target: Path,
        diff_only: bool = False,
        pr_base: str = "main",
        exclude_paths: list[str] | None = None,
        max_files: int = 0,
        max_file_bytes: int = 0,
        max_total_bytes: int = 0,
    ) -> Scope:
        scope = cls(
            target=target.resolve(),
            diff_only=diff_only,
            pr_base=pr_base,
            exclude_paths=list(exclude_paths or []),
            max_files=max_files,
            max_file_bytes=max_file_bytes,
            max_total_bytes=max_total_bytes,
        )
        scope._populate()
        return scope

    # -- builders ----------------------------------------------------------

    def _populate(self) -> None:
        if self.diff_only:
            self.diff_files = self._git_diff_files()
            candidates = self.diff_files
        else:
            candidates = self._walk_files()

        running_total = 0
        for path in candidates:
            rel = self._relative(path)
            if self._is_excluded(rel):
                self.skipped_excluded.append(path)
                continue
            try:
                size = path.stat().st_size
            except OSError:
                continue
            if self.max_file_bytes and size > self.max_file_bytes:
                self.skipped_oversize.append(path)
                continue
            if self.max_total_bytes and running_total + size > self.max_total_bytes:
                self.skipped_truncated += 1
                continue
            if self.max_files and len(self.files) >= self.max_files:
                self.skipped_truncated += 1
                continue
            self.files.append(path)
            running_total += size
        self.total_bytes = running_total

    def _walk_files(self) -> list[Path]:
        out: list[Path] = []
        for root, dirs, fnames in os.walk(self.target):
            dirs[:] = [d for d in dirs if d not in _DEFAULT_IGNORE_DIRS]
            for fname in fnames:
                p = Path(root) / fname
                if p.suffix.lower() in _INTERESTING_EXTS or p.name in _INTERESTING_EXTS:
                    out.append(p)
        return out

    def _git_diff_files(self) -> list[Path]:
        """Return files changed in the working tree relative to ``pr_base``.

        Falls back to a full walk if the target isn't a git repo.
        """
        try:
            result = subprocess.run(
                ["git", "diff", "--name-only", "--diff-filter=ACMRT", f"{self.pr_base}...HEAD"],
                cwd=self.target,
                capture_output=True,
                text=True,
                timeout=15,
                check=False,
            )
        except (subprocess.SubprocessError, OSError) as exc:
            log.warning("git diff failed (%s); falling back to full walk.", exc)
            return self._walk_files()

        if result.returncode != 0:
            log.warning(
                "git diff exited %d (%s); falling back to full walk.",
                result.returncode,
                result.stderr.strip()[:200],
            )
            return self._walk_files()

        out: list[Path] = []
        for line in result.stdout.splitlines():
            line = line.strip()
            if not line:
                continue
            p = self.target / line
            if p.is_file() and (p.suffix.lower() in _INTERESTING_EXTS or p.name in _INTERESTING_EXTS):
                out.append(p)
        return out

    # -- helpers -----------------------------------------------------------

    def _relative(self, path: Path) -> str:
        try:
            return str(path.relative_to(self.target))
        except ValueError:
            return str(path)

    def _is_excluded(self, rel_path: str) -> bool:
        rel = rel_path.replace("\\", "/").lower()
        for needle in self.exclude_paths:
            if needle.lower() in rel:
                return True
        return False

    # -- public iteration --------------------------------------------------

    def iter_files(self) -> Iterator[Path]:
        return iter(self.files)

    def summary(self) -> dict[str, object]:
        return {
            "mode": "diff" if self.diff_only else "full",
            "pr_base": self.pr_base if self.diff_only else None,
            "files": len(self.files),
            "total_bytes": self.total_bytes,
            "skipped_excluded": len(self.skipped_excluded),
            "skipped_oversize": len(self.skipped_oversize),
            "skipped_truncated": self.skipped_truncated,
            "exclude_paths": list(self.exclude_paths),
            "max_files": self.max_files,
            "max_file_bytes": self.max_file_bytes,
            "max_total_bytes": self.max_total_bytes,
        }
