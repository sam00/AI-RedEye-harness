#!/usr/bin/env python3
"""Standalone helper that mirrors `redeye setup --install-agents`.

You don't normally need this -- `redeye setup --install-agents` does the
same thing -- but it's handy when bootstrapping in CI before the package is
on PATH.

Usage:
    python scripts/install_agents.py [target_dir]
"""

from __future__ import annotations

import shutil
import sys
from pathlib import Path

_FILES = {
    "AGENTS.md": "AGENTS.md",
    "CLAUDE.md": "CLAUDE.md",
    ".github/copilot-instructions.md": "AGENTS.md",
    "GEMINI.md": "AGENTS.md",
}


def install(target_dir: Path) -> int:
    repo_root = Path(__file__).resolve().parent.parent
    written = 0
    for dest_rel, src_rel in _FILES.items():
        dest = target_dir / dest_rel
        src = repo_root / src_rel
        if dest.exists():
            print(f"  skip  {dest_rel} (already exists)")
            continue
        if not src.exists():
            print(f"  miss  {dest_rel} (source {src_rel} not found)")
            continue
        dest.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(src, dest)
        print(f"  wrote {dest_rel}")
        written += 1
    print(f"\nInstalled {written} agent file(s).")
    return 0


def main() -> int:
    target = Path(sys.argv[1]) if len(sys.argv) > 1 else Path.cwd()
    if not target.is_dir():
        print(f"target_dir does not exist: {target}", file=sys.stderr)
        return 2
    return install(target)


if __name__ == "__main__":
    sys.exit(main())
