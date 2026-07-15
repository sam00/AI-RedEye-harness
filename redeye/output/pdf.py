"""Render a redeye run manifest into a styled PDF report.

This is the importable counterpart to ``scripts/build_report_pdf.py``: the
orchestrator can produce the PDF inline (``--pdf``) and the script delegates
here. ``reportlab`` is an *optional* dependency -- :data:`PDF_AVAILABLE` is
False and :func:`render_manifest_pdf` raises ``PdfUnavailable`` when it isn't
installed, so the core install stays dependency-light.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

try:  # reportlab is optional
    from reportlab.lib import colors
    from reportlab.lib.enums import TA_CENTER
    from reportlab.lib.pagesizes import LETTER
    from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
    from reportlab.lib.units import inch
    from reportlab.platypus import (
        PageBreak,
        Paragraph,
        SimpleDocTemplate,
        Spacer,
        Table,
        TableStyle,
    )

    PDF_AVAILABLE = True
except ImportError:  # pragma: no cover - exercised only without reportlab
    PDF_AVAILABLE = False


class PdfUnavailable(RuntimeError):
    """Raised when a PDF is requested but reportlab isn't installed."""


_PURPLE = "#7B189F"
_DARK = "#1A1A1A"
_PALE = "#F4F4F6"
_SEV_HEX = {
    "critical": "#7B0010",
    "high": "#C0291D",
    "medium": "#D88717",
    "low": "#3A6BC0",
    "informational": "#666666",
}


def _esc(text: Any) -> str:
    return str(text).replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")


def _styles():  # type: ignore[no-untyped-def]
    s = getSampleStyleSheet()
    purple = colors.HexColor(_PURPLE)
    dark = colors.HexColor(_DARK)
    out = {
        "h1": ParagraphStyle(
            "Ph1", parent=s["Heading1"], fontSize=22, textColor=purple, spaceAfter=12
        ),
        "h2": ParagraphStyle(
            "Ph2", parent=s["Heading2"], fontSize=15, textColor=purple, spaceBefore=14, spaceAfter=6
        ),
        "h3": ParagraphStyle(
            "Ph3", parent=s["Heading3"], fontSize=12, textColor=dark, spaceBefore=8, spaceAfter=4
        ),
        "body": ParagraphStyle(
            "Pbody", parent=s["BodyText"], fontSize=10, leading=13, textColor=dark, spaceAfter=6
        ),
        "small": ParagraphStyle(
            "Psmall",
            parent=s["BodyText"],
            fontSize=8.5,
            leading=11,
            textColor=colors.HexColor("#555"),
        ),
        "center": ParagraphStyle(
            "Pcenter", parent=s["BodyText"], fontSize=14, alignment=TA_CENTER, textColor=dark
        ),
    }
    return out


def _findings_from_manifest(data: dict) -> tuple[list[dict], list[dict]]:
    final: list[dict] = []
    for stage in data.get("stages", []):
        if stage.get("stage_id") == "s9_emit":
            final = stage.get("findings", []) or []
    seen = {f.get("id") for f in final}
    dropped: list[dict] = []
    seen_d: set[str] = set()
    for stage in data.get("stages", []):
        for f in stage.get("findings", []) or []:
            fid = f.get("id")
            if fid and fid not in seen and fid not in seen_d:
                if any(t.startswith(("dropped:", "hallucinated:")) for t in f.get("tags") or []):
                    dropped.append(f)
                    seen_d.add(fid)
    return final, dropped


def _by_sev(findings: list[dict]) -> dict[str, int]:
    out = {s: 0 for s in ("critical", "high", "medium", "low", "informational")}
    for f in findings:
        key = (f.get("severity") or "informational").lower()
        out[key] = out.get(key, 0) + 1
    return out


def render_manifest_pdf(
    manifest_path: Path,
    output: Path,
    *,
    title: str = "RedEye Security Scan Report",
    target_name: str | None = None,
) -> Path:
    """Render ``manifest_path`` (run_manifest.json) into ``output`` (PDF)."""
    if not PDF_AVAILABLE:
        raise PdfUnavailable("PDF output requires reportlab. Install with: pip install reportlab")

    data = json.loads(Path(manifest_path).read_text(encoding="utf-8"))
    stages = {s["stage_id"]: s for s in data.get("stages", []) or []}
    findings, dropped = _findings_from_manifest(data)
    by_sev = _by_sev(findings)
    st = _styles()
    target_name = target_name or Path(data.get("target_repo", "target")).name

    def kv(rows):  # type: ignore[no-untyped-def]
        body = [
            [Paragraph(f"<b>{_esc(k)}</b>", st["body"]), Paragraph(_esc(v), st["body"])]
            for k, v in rows
        ]
        t = Table(body, colWidths=[1.9 * inch, 4.6 * inch])
        t.setStyle(
            TableStyle(
                [
                    ("VALIGN", (0, 0), (-1, -1), "TOP"),
                    ("ROWBACKGROUNDS", (0, 0), (-1, -1), [colors.white, colors.HexColor(_PALE)]),
                ]
            )
        )
        return t

    doc = SimpleDocTemplate(
        str(output),
        pagesize=LETTER,
        rightMargin=0.75 * inch,
        leftMargin=0.75 * inch,
        topMargin=0.75 * inch,
        bottomMargin=0.75 * inch,
        title=title,
    )
    story: list = []

    # Cover
    story.append(Spacer(1, 1.0 * inch))
    story.append(Paragraph(_esc(title), st["h1"]))
    story.append(Paragraph(_esc(target_name), st["center"]))
    story.append(Spacer(1, 0.4 * inch))
    story.append(
        kv(
            [
                ("Application ID", data.get("application_id") or target_name),
                ("Repository", data.get("target_repo", "-")),
                ("Commit", (data.get("target_sha") or "-")[:12]),
                ("Tool / version", f"{data.get('tool', 'redeye')} {data.get('version', '')}"),
                ("Profile", data.get("profile", "-")),
                ("Estimated cost (USD)", f"${data.get('total_cost_usd', 0):.3f}"),
                ("Budget exceeded", "yes" if data.get("budget_exceeded") else "no"),
                ("Findings emitted", str(data.get("finding_count", len(findings)))),
                ("Findings dropped", str(data.get("dropped_count", len(dropped)))),
            ]
        )
    )
    story.append(Spacer(1, 0.2 * inch))
    story.append(
        Paragraph(
            "<i>LLM-generated triage candidates, not confirmed vulnerabilities. "
            "Treat severity, CWE and attack chains as starting points for review.</i>",
            st["small"],
        )
    )
    story.append(PageBreak())

    # Executive summary + severity table
    story.append(Paragraph("Executive summary", st["h2"]))
    crit = by_sev.get("critical", 0) + by_sev.get("high", 0)
    verified_n = sum(1 for f in findings if (f.get("verification") or {}).get("verified"))
    corroborated_n = sum(
        1
        for f in findings
        if f.get("externally_corroborated")
        or any(
            e.get("check") == "pass" and e.get("kind") == "external_corroboration"
            for e in (f.get("evidence") or [])
        )
    )
    story.append(
        Paragraph(
            f"The harness emitted <b>{len(findings)}</b> finding(s), of which "
            f"<b>{crit}</b> are Critical/High. "
            f"<b>{verified_n}</b> passed deterministic outcome verification (S8c) and "
            f"<b>{corroborated_n}</b> were corroborated by an independent scanner.",
            st["body"],
        )
    )
    rows = [[Paragraph("<b>Severity</b>", st["small"]), Paragraph("<b>Count</b>", st["small"])]]
    for sev in ("critical", "high", "medium", "low", "informational"):
        rows.append(
            [
                Paragraph(
                    f'<font color="{_SEV_HEX[sev]}"><b>{sev.upper()}</b></font>', st["small"]
                ),
                Paragraph(str(by_sev.get(sev, 0)), st["small"]),
            ]
        )
    sev_table = Table(rows, colWidths=[2.5 * inch, 1.0 * inch])
    sev_table.setStyle(
        TableStyle(
            [
                ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor(_PURPLE)),
                ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
                ("GRID", (0, 0), (-1, -1), 0.25, colors.lightgrey),
                ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, colors.HexColor(_PALE)]),
            ]
        )
    )
    story.append(sev_table)

    # Structural + external summary
    s1b = (stages.get("s1b_structural") or {}).get("artifacts") or {}
    summary = s1b.get("structural_summary") or {}
    if summary:
        story.append(Paragraph("Structural inventory (S1b)", st["h3"]))
        story.append(
            Paragraph(
                " &bull; ".join(f"{k.replace('_', ' ')}: <b>{v}</b>" for k, v in summary.items()),
                st["small"],
            )
        )
    ext = s1b.get("external_summary") or {}
    if ext.get("count"):
        story.append(Paragraph("External scanner ingestion", st["h3"]))
        story.append(
            Paragraph(
                f"Imported <b>{ext.get('count', 0)}</b> finding(s) "
                f"({ext.get('reachable', 0)} reachable, {ext.get('deduped', 0)} deduped).",
                st["small"],
            )
        )

    # Findings
    story.append(PageBreak())
    story.append(Paragraph("Findings", st["h2"]))
    if not findings:
        story.append(Paragraph("<i>No findings survived the quality pipeline.</i>", st["body"]))
    else:
        order = {"critical": 5, "high": 4, "medium": 3, "low": 2, "informational": 1}
        for f in sorted(findings, key=lambda f: -order.get((f.get("severity") or "").lower(), 0)):
            sev = (f.get("severity") or "").lower()
            locs = f.get("locations") or [{}]
            loc = locs[0]
            story.append(
                Paragraph(
                    f'<font color="{_SEV_HEX.get(sev, "#666")}"><b>[{sev.upper()}]</b></font> '
                    f'{_esc(f.get("title", ""))} <font color="#888">{f.get("id", "")}</font>',
                    st["h3"],
                )
            )
            ver = f.get("verification") or {}
            if ver:
                passed = sum(1 for ok in (ver.get("signals") or {}).values() if ok)
                considered = len(ver.get("signals") or {})
                verdict = (
                    f"{'VERIFIED' if ver.get('verified') else 'UNVERIFIED'} "
                    f"({passed}/{considered} signals, need {ver.get('threshold', 3)})"
                )
            else:
                verdict = "not run"
            story.append(
                kv(
                    [
                        ("CWE", f.get("cwe", "unknown")),
                        ("Location", f"{loc.get('path', '?')}:{loc.get('start_line', '?')}"),
                        ("Confidence", f"{f.get('confidence', 0):.2f}"),
                        ("Verification (S8c)", verdict),
                        ("Lens / stage", f"{f.get('skill', '-')} / {f.get('stage', '-')}"),
                    ]
                )
            )
            story.append(Paragraph(_esc(f.get("description", "") or "(none)"), st["body"]))
            story.append(
                Paragraph(
                    f"<b>Remediation:</b> {_esc(f.get('remediation', '') or '(none)')}",
                    st["small"],
                )
            )
            story.append(Spacer(1, 0.12 * inch))

    doc.build(story)
    return output
