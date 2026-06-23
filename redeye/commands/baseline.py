"""`redeye baseline {accept,list,remove}` -- manage the local baseline file.

The baseline lets an operator accept findings so they don't reappear in
future scans. See :mod:`redeye.baseline` for the storage format.
"""

from __future__ import annotations

import json
from pathlib import Path

from rich.console import Console
from rich.table import Table

from redeye.baseline import Baseline, _resolve_baseline_root, fingerprint


def _load_findings_from_manifest(manifest_path: Path) -> list[dict]:
    """Pull the s9_emit stage findings out of a run_manifest.json."""
    try:
        data = json.loads(manifest_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return []
    for stage in data.get("stages", []):
        if stage.get("stage_id") == "s9_emit":
            return stage.get("findings", []) or []
    return []


def accept(
    *,
    console: Console,
    finding_id: str | None,
    manifest: Path | None,
    rationale: str,
    target_root: Path | None = None,
) -> int:
    root = (target_root or _resolve_baseline_root()).resolve()
    baseline = Baseline.load(root)

    if not manifest:
        # Look in the default output dir
        guess = root / "out" / "run_manifest.json"
        if guess.is_file():
            manifest = guess
        else:
            console.print(
                "[yellow]No --manifest given and ./out/run_manifest.json not found.[/yellow]"
            )
            return 2

    findings = _load_findings_from_manifest(manifest)
    if not findings:
        console.print(f"[yellow]No findings in {manifest}.[/yellow]")
        return 2

    if finding_id is None:
        console.print("[red]Pass --finding-id (e.g. F-0001).[/red]")
        return 2

    matched = next((f for f in findings if f.get("id") == finding_id), None)
    if matched is None:
        console.print(f"[red]No finding with id {finding_id} in {manifest}.[/red]")
        return 2

    locs = matched.get("locations") or [{}]
    primary = locs[0]
    entry = baseline.accept(
        cwe=matched.get("cwe"),
        path=primary.get("path", "unknown"),
        start_line=int(primary.get("start_line", 0)),
        skill=matched.get("skill"),
        rationale=rationale,
    )
    baseline.save()
    console.print(
        f"[green]Accepted[/green] {finding_id} -> fingerprint {entry.fingerprint}\n"
        f"  Written to {baseline.path}"
    )
    return 0


def list_entries(*, console: Console, target_root: Path | None = None) -> int:
    root = (target_root or _resolve_baseline_root()).resolve()
    baseline = Baseline.load(root)
    if not baseline.entries:
        console.print(f"[dim](no baseline entries at {baseline.path})[/dim]")
        return 0

    table = Table(title=f"Baseline entries -- {baseline.path}")
    table.add_column("Fingerprint")
    table.add_column("CWE")
    table.add_column("Location")
    table.add_column("Skill")
    table.add_column("Accepted at")
    table.add_column("Rationale")
    for entry in baseline.entries.values():
        table.add_row(
            entry.fingerprint,
            entry.cwe,
            f"{entry.path}:{entry.start_line}",
            entry.skill,
            entry.accepted_at.split("T")[0] if entry.accepted_at else "",
            entry.rationale[:60] + ("..." if len(entry.rationale) > 60 else ""),
        )
    console.print(table)
    return 0


def remove(*, console: Console, fp: str, target_root: Path | None = None) -> int:
    root = (target_root or _resolve_baseline_root()).resolve()
    baseline = Baseline.load(root)
    if baseline.remove(fp):
        baseline.save()
        console.print(f"[green]Removed[/green] {fp} from baseline")
        return 0
    console.print(f"[yellow]No entry with fingerprint {fp}.[/yellow]")
    return 1


def show_fingerprint(*, console: Console, cwe: str, path: str, line: int, skill: str) -> int:
    """Utility: compute the fingerprint for a hypothetical finding."""
    fp = fingerprint(cwe=cwe, path=path, start_line=line, skill=skill)
    console.print(fp)
    return 0
