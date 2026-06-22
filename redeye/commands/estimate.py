"""`redeye estimate` — scope and rough USD budget for a scan.

We avoid every LLM call: file enumeration is purely local (`os.walk` plus
extension-based language detection) and the cost model is the per-stage
``max_budget_usd`` in the active profile. The number is intentionally a
loose upper bound — actual spend is almost always less.
"""

from __future__ import annotations

import os
from collections import Counter
from pathlib import Path

from rich.console import Console
from rich.table import Table

from redeye.config import load_profile

# Coarse extension ? language map. Extending this is fine; we only use it for
# the human-readable summary, so misclassification is annoying but not fatal.
_EXT_LANG: dict[str, str] = {
    ".py": "Python",
    ".js": "JavaScript",
    ".jsx": "JavaScript",
    ".ts": "TypeScript",
    ".tsx": "TypeScript",
    ".java": "Java",
    ".kt": "Kotlin",
    ".go": "Go",
    ".rb": "Ruby",
    ".php": "PHP",
    ".rs": "Rust",
    ".cpp": "C/C++",
    ".cc": "C/C++",
    ".c": "C/C++",
    ".h": "C/C++",
    ".hpp": "C/C++",
    ".cs": "C#",
    ".scala": "Scala",
    ".swift": "Swift",
    ".sol": "Solidity",
    ".tf": "Terraform",
    ".yml": "YAML",
    ".yaml": "YAML",
    ".json": "JSON",
    ".sh": "Shell",
    ".bash": "Shell",
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
    ".mypy_cache",
    ".pytest_cache",
    ".ruff_cache",
}


def _enumerate(repo: Path) -> tuple[int, int, Counter[str]]:
    """Return (file_count, total_bytes, language_counter)."""
    files = 0
    total = 0
    langs: Counter[str] = Counter()
    for root, dirs, fnames in os.walk(repo):
        dirs[:] = [d for d in dirs if d not in _IGNORE_DIRS]
        for fname in fnames:
            p = Path(root) / fname
            try:
                size = p.stat().st_size
            except OSError:
                continue
            files += 1
            total += size
            ext = p.suffix.lower()
            if ext in _EXT_LANG:
                langs[_EXT_LANG[ext]] += 1
    return files, total, langs


def run(*, console: Console, repo: Path, profile: str | None) -> None:
    cfg = load_profile(profile)
    console.rule(f"[bold]redeye estimate[/bold] — {repo}")

    files, total, langs = _enumerate(repo)
    console.print(
        f"Files scanned: [cyan]{files:,}[/cyan]   Total: [cyan]{total / 1e6:,.1f} MB[/cyan]"
    )

    if langs:
        lang_table = Table(title="Language mix")
        lang_table.add_column("Language")
        lang_table.add_column("Files", justify="right")
        for lang, count in langs.most_common():
            lang_table.add_row(lang, f"{count:,}")
        console.print(lang_table)
    else:
        console.print("[yellow]No source files matched our extension map.[/yellow]")

    cost_table = Table(title=f"Cost ceiling (profile: {cfg.name})")
    cost_table.add_column("Stage")
    cost_table.add_column("Skill")
    cost_table.add_column("Max USD", justify="right")
    grand_total = 0.0
    for stage_id, stage in sorted(cfg.stages.items()):
        cost_table.add_row(stage_id, stage.skill, f"${stage.max_budget_usd:.2f}")
        grand_total += stage.max_budget_usd
    console.print(cost_table)
    console.print(
        f"\n[bold]Worst-case total:[/bold] ${grand_total:.2f} (caps are per-stage, not global)"
    )
    console.print(
        "[dim]This is an upper bound. Actual spend is usually 30–60% lower because most "
        "stages exit early once findings stabilise.[/dim]"
    )
