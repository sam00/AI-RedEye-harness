"""`redeye threat-baseline {accept,list,remove}` -- manage accepted threats.

See :mod:`redeye.threat_baseline` for the storage format. Accepted STRIDE
threats are subtracted from future S2 threat models.
"""

from __future__ import annotations

import json
from pathlib import Path

from rich.console import Console
from rich.table import Table

from redeye.threat_baseline import ThreatBaseline, resolve_threat_baseline_root


def _stride_from_manifest(manifest_path: Path) -> list[dict]:
    """Pull the S2 threat model's STRIDE list out of a run_manifest.json."""
    try:
        data = json.loads(manifest_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return []
    for stage in data.get("stages", []):
        if stage.get("stage_id") == "s2_threat_model":
            tm = (stage.get("artifacts") or {}).get("threat_model") or {}
            return [t for t in (tm.get("stride") or []) if isinstance(t, dict)]
    return []


def accept(
    *,
    console: Console,
    category: str | None,
    asset: str | None,
    rationale: str,
    manifest: Path | None = None,
    accept_all: bool = False,
    file: Path | None = None,
    target_root: Path | None = None,
) -> int:
    root = (file or target_root or resolve_threat_baseline_root()).resolve()
    baseline = ThreatBaseline.load(root)

    if accept_all:
        if not manifest or not manifest.is_file():
            console.print("[red]--all requires --manifest pointing to a run_manifest.json.[/red]")
            return 2
        stride = _stride_from_manifest(manifest)
        if not stride:
            console.print(f"[yellow]No STRIDE threats found in {manifest}.[/yellow]")
            return 2
        n = 0
        for t in stride:
            cat, ast_ = t.get("category"), t.get("asset")
            if cat and ast_:
                baseline.accept(category=str(cat), asset=str(ast_), rationale=rationale)
                n += 1
        baseline.save()
        console.print(f"[green]Accepted {n} threat(s)[/green] -> {baseline.path}")
        return 0

    if not category or not asset:
        console.print("[red]Pass --category and --asset (or --manifest --all).[/red]")
        return 2

    entry = baseline.accept(category=category, asset=asset, rationale=rationale)
    baseline.save()
    console.print(
        f"[green]Accepted[/green] threat '{entry.signature}'\n  Written to {baseline.path}"
    )
    return 0


def list_entries(*, console: Console, file: Path | None = None, target_root: Path | None = None) -> int:
    root = (file or target_root or resolve_threat_baseline_root()).resolve()
    baseline = ThreatBaseline.load(root)
    if not baseline.entries:
        console.print(f"[dim](no threat-baseline entries at {baseline.path})[/dim]")
        return 0
    table = Table(title=f"Threat baseline -- {baseline.path}")
    table.add_column("Category")
    table.add_column("Asset")
    table.add_column("Accepted at")
    table.add_column("Rationale")
    for entry in baseline.entries.values():
        table.add_row(
            entry.category,
            entry.asset,
            entry.accepted_at.split("T")[0] if entry.accepted_at else "",
            entry.rationale[:60] + ("..." if len(entry.rationale) > 60 else ""),
        )
    console.print(table)
    return 0


def remove(
    *,
    console: Console,
    category: str,
    asset: str,
    file: Path | None = None,
    target_root: Path | None = None,
) -> int:
    root = (file or target_root or resolve_threat_baseline_root()).resolve()
    baseline = ThreatBaseline.load(root)
    if baseline.remove(category=category, asset=asset):
        baseline.save()
        console.print(f"[green]Removed[/green] threat '{category}|{asset}'")
        return 0
    console.print(f"[yellow]No entry for '{category}|{asset}'.[/yellow]")
    return 1
