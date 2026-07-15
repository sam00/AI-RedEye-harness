"""``redeye report`` -- regenerate reports from an existing run manifest.

Reports are normally produced during ``scan``. Re-emitting them (say, to add
HTML/PDF after the fact, or to refresh formatting) previously meant re-running
the whole pipeline -- which spends real money on the LLM stages. This command
rebuilds any output format from a ``run_manifest.json`` alone: ``$0`` and
seconds, fully offline. ``--open`` launches the HTML in the default browser.
"""

from __future__ import annotations

import json
import logging
import webbrowser
from pathlib import Path

from rich.console import Console

log = logging.getLogger(__name__)

_ALL_FORMATS = ("html", "pdf", "md", "json", "csv")


def _resolve_manifest(manifest: Path | None) -> Path | None:
    """Find a run_manifest.json: explicit path, else common output locations."""
    if manifest is not None:
        return manifest if manifest.is_file() else None
    for candidate in (
        Path("run_manifest.json"),
        Path("security-scan") / "run_manifest.json",
        Path("out") / "run_manifest.json",
    ):
        if candidate.is_file():
            return candidate
    return None


def _reconstruct_markdown(data: dict, manifest_path: Path, out_dir: Path) -> Path:
    """Rebuild the Markdown report from serialized manifest findings."""
    from redeye.output.findings_export import _final_findings
    from redeye.output.markdown import write_markdown_report
    from redeye.schema import Finding

    findings = [Finding.model_validate(f) for f in _final_findings(data)]

    def _artifact(stage_id: str, key: str):
        for stage in data.get("stages", []) or []:
            if stage.get("stage_id") == stage_id:
                return (stage.get("artifacts") or {}).get(key)
        return None

    md_path = out_dir / "report.md"
    write_markdown_report(
        path=md_path,
        target=Path(data.get("target_repo", "target")),
        application_id=data.get("application_id"),
        findings=findings,
        attack_surface=_artifact("s1_attack_surface", "attack_surface") or {},
        threat_model=_artifact("s2_threat_model", "threat_model") or {},
        hallucination_metrics=data.get("hallucination_metrics") or {},
        structural_summary=_artifact("s1b_structural", "structural_summary"),
        external_summary=_artifact("s1b_structural", "external_summary"),
    )
    return md_path


def run(
    *,
    console: Console,
    manifest: Path | None,
    output_dir: Path | None,
    formats: list[str],
    open_report: bool = False,
) -> int:
    manifest_path = _resolve_manifest(manifest)
    if manifest_path is None:
        console.print(
            "[red]no run_manifest.json found[/red] -- pass --manifest PATH or run from a "
            "directory containing a scan output."
        )
        return 2

    try:
        data = json.loads(manifest_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        console.print(f"[red]could not read manifest:[/red] {exc}")
        return 2

    out_dir = output_dir or manifest_path.parent
    out_dir.mkdir(parents=True, exist_ok=True)
    target_name = Path(data.get("target_repo", "target")).name

    fmts = list(_ALL_FORMATS) if "all" in formats else formats
    produced: list[Path] = []
    html_path: Path | None = None

    console.rule(f"[bold]redeye report[/bold] -- {manifest_path} -> {out_dir}")

    if "html" in fmts:
        from redeye.output.html import render_manifest_html

        html_path = render_manifest_html(
            manifest_path, out_dir / "report.html", target_name=target_name
        )
        produced.append(html_path)

    if "pdf" in fmts:
        from redeye.output.pdf import PdfUnavailable, render_manifest_pdf

        try:
            produced.append(
                render_manifest_pdf(manifest_path, out_dir / "report.pdf", target_name=target_name)
            )
        except (PdfUnavailable, OSError) as exc:
            console.print(f"  [yellow]PDF skipped:[/yellow] {exc}")

    if "md" in fmts:
        try:
            produced.append(_reconstruct_markdown(data, manifest_path, out_dir))
        except Exception as exc:  # noqa: BLE001
            console.print(f"  [yellow]Markdown skipped:[/yellow] {exc}")

    if "json" in fmts or "csv" in fmts:
        from redeye.output.findings_export import export_findings

        json_path, csv_path = export_findings(manifest_path, out_dir)
        if "json" in fmts:
            produced.append(json_path)
        if "csv" in fmts:
            produced.append(csv_path)

    for p in produced:
        console.print(f"  [green]wrote[/green] {p}")

    if not produced:
        console.print("[yellow]nothing produced -- check --format[/yellow]")
        return 1

    if open_report:
        target = html_path or produced[0]
        try:
            webbrowser.open(target.resolve().as_uri())
            console.print(f"  [dim]opened {target}[/dim]")
        except Exception as exc:  # noqa: BLE001
            console.print(f"  [yellow]could not open browser:[/yellow] {exc}")

    return 0
