#!/usr/bin/env python3
"""Render a redeye run into a styled PDF report.

Reads ``run_manifest.json`` (which carries every stage's artifacts and the
final list of findings) and produces a multi-section PDF:

- Cover page with target / profile / SHA / cost.
- Executive summary with severity counts and quality metrics.
- Structural inventory (S1b ground truth).
- Attack surface (S1) and threat model (S2) summaries.
- Per-finding sections with taint flow, evidence list, PoC, remediation.
- Appendix of dropped findings (hallucinations the harness pruned).

Pure Python: only depends on ``reportlab``.
"""

from __future__ import annotations

import argparse
import json
import sys
from datetime import datetime
from pathlib import Path
from typing import Any

from reportlab.lib import colors
from reportlab.lib.enums import TA_CENTER, TA_LEFT
from reportlab.lib.pagesizes import LETTER
from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
from reportlab.lib.units import inch
from reportlab.platypus import (
    KeepTogether,
    PageBreak,
    Paragraph,
    Preformatted,
    SimpleDocTemplate,
    Spacer,
    Table,
    TableStyle,
)


# ---------------------------------------------------------------------------
# Styling
# ---------------------------------------------------------------------------

PURPLE = colors.HexColor("#7B189F")
DARK = colors.HexColor("#1A1A1A")
MUTED = colors.HexColor("#555555")
PALE = colors.HexColor("#F4F4F6")
SEV_COLORS = {
    "critical": colors.HexColor("#7B0010"),
    "high": colors.HexColor("#C0291D"),
    "medium": colors.HexColor("#D88717"),
    "low": colors.HexColor("#3A6BC0"),
    "informational": colors.HexColor("#666666"),
}

_styles = getSampleStyleSheet()


def _style(name: str, parent: str = "BodyText", **kw) -> ParagraphStyle:
    if name in _styles.byName:
        return _styles[name]
    s = ParagraphStyle(name=name, parent=_styles[parent], **kw)
    _styles.add(s)
    return s


H1 = _style("H1", "Heading1", fontSize=22, leading=26, textColor=PURPLE, spaceAfter=12)
H2 = _style("H2", "Heading2", fontSize=15, leading=18, textColor=DARK, spaceBefore=14, spaceAfter=6)
H3 = _style("H3", "Heading3", fontSize=12, leading=15, textColor=DARK, spaceBefore=8, spaceAfter=4)
H4 = _style("H4", "Heading4", fontSize=11, leading=14, textColor=DARK, spaceBefore=6, spaceAfter=3)
BODY = _style("Body", "BodyText", fontSize=10, leading=13, textColor=DARK, spaceAfter=6)
SMALL = _style("Small", "BodyText", fontSize=8.5, leading=11, textColor=MUTED)
MONO = _style("Mono", "Code", fontSize=8.5, leading=11, textColor=DARK, leftIndent=10, spaceAfter=4)
CENTER = _style("Center", "BodyText", fontSize=14, alignment=TA_CENTER)


def esc(text: Any) -> str:
    return (
        str(text)
        .replace("&", "&amp;")
        .replace("<", "&lt;")
        .replace(">", "&gt;")
    )


def kv_table(rows, col_widths=(1.7 * inch, 4.8 * inch)) -> Table:
    data = [[Paragraph(f"<b>{esc(k)}</b>", BODY), Paragraph(esc(v), BODY)] for k, v in rows]
    t = Table(data, colWidths=list(col_widths))
    t.setStyle(
        TableStyle(
            [
                ("VALIGN", (0, 0), (-1, -1), "TOP"),
                ("BOTTOMPADDING", (0, 0), (-1, -1), 5),
                ("TOPPADDING", (0, 0), (-1, -1), 2),
                ("ROWBACKGROUNDS", (0, 0), (-1, -1), [colors.white, PALE]),
            ]
        )
    )
    return t


def _hex(c: colors.Color) -> str:
    """Return ``#rrggbb`` for a reportlab Color (its hexval is ``0xrrggbb``)."""
    return "#" + c.hexval()[2:]


def severity_summary_table(by_sev: dict[str, int]) -> Table:
    header = ["Severity", "Count"]
    rows = [[Paragraph(f"<b>{esc(h)}</b>", SMALL) for h in header]]
    for sev in ("critical", "high", "medium", "low", "informational"):
        count = by_sev.get(sev, 0)
        sev_color = SEV_COLORS.get(sev, MUTED)
        rows.append(
            [
                Paragraph(
                    f'<font color="{_hex(sev_color)}"><b>{sev.upper()}</b></font>',
                    SMALL,
                ),
                Paragraph(str(count), SMALL),
            ]
        )
    t = Table(rows, colWidths=[2.5 * inch, 1.0 * inch], repeatRows=1)
    t.setStyle(
        TableStyle(
            [
                ("BACKGROUND", (0, 0), (-1, 0), PURPLE),
                ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
                ("GRID", (0, 0), (-1, -1), 0.25, colors.lightgrey),
                ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, PALE]),
                ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
                ("TOPPADDING", (0, 0), (-1, -1), 3),
                ("BOTTOMPADDING", (0, 0), (-1, -1), 3),
            ]
        )
    )
    return t


def metrics_table(metrics: dict[str, int]) -> Table:
    labels = {
        "raw_lens": "Raw lens findings (before any filtering)",
        "ungrounded_dropped": "Dropped: cited path or line did not exist (S4b)",
        "ungrounded_downgraded": "Downgraded: weak grounding evidence (S4b)",
        "validator_rejected": "Rejected by single-pass validator (S6.5)",
        "voted_out": "Voted out by multi-agent vote (S6)",
        "missing_poc": "Demoted: no concrete PoC (S8b)",
    }
    header = ["Quality metric", "Count"]
    rows = [[Paragraph(f"<b>{esc(h)}</b>", SMALL) for h in header]]
    for key, label in labels.items():
        if key in metrics:
            rows.append(
                [
                    Paragraph(esc(label), SMALL),
                    Paragraph(f"<b>{metrics[key]}</b>", SMALL),
                ]
            )
    if len(rows) == 1:
        rows.append(
            [Paragraph("<i>(no metrics recorded)</i>", SMALL), Paragraph("-", SMALL)]
        )
    t = Table(rows, colWidths=[5.0 * inch, 1.0 * inch], repeatRows=1)
    t.setStyle(
        TableStyle(
            [
                ("BACKGROUND", (0, 0), (-1, 0), DARK),
                ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
                ("GRID", (0, 0), (-1, -1), 0.25, colors.lightgrey),
                ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, PALE]),
                ("VALIGN", (0, 0), (-1, -1), "TOP"),
                ("TOPPADDING", (0, 0), (-1, -1), 3),
                ("BOTTOMPADDING", (0, 0), (-1, -1), 3),
            ]
        )
    )
    return t


def structural_table(summary: dict[str, Any]) -> Table:
    rows = [[Paragraph("<b>Inventory bucket</b>", SMALL), Paragraph("<b>Count</b>", SMALL)]]
    for label, key in [
        ("Files indexed", "files_indexed"),
        ("Routes / RPC entrypoints", "routes"),
        ("Untrusted-input sources", "sources"),
        ("Dangerous sinks", "sinks"),
        ("Suspected secrets", "secrets"),
    ]:
        rows.append(
            [Paragraph(label, SMALL), Paragraph(f"<b>{summary.get(key, 0)}</b>", SMALL)]
        )
    t = Table(rows, colWidths=[4.0 * inch, 1.0 * inch], repeatRows=1)
    t.setStyle(
        TableStyle(
            [
                ("BACKGROUND", (0, 0), (-1, 0), PURPLE),
                ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
                ("GRID", (0, 0), (-1, -1), 0.25, colors.lightgrey),
                ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, PALE]),
                ("VALIGN", (0, 0), (-1, -1), "TOP"),
                ("TOPPADDING", (0, 0), (-1, -1), 3),
                ("BOTTOMPADDING", (0, 0), (-1, -1), 3),
            ]
        )
    )
    return t


def evidence_table(evidence: list[dict]) -> Table:
    rows = [
        [
            Paragraph("<b>Check</b>", SMALL),
            Paragraph("<b>Kind</b>", SMALL),
            Paragraph("<b>Detail</b>", SMALL),
        ]
    ]
    for e in evidence[:14]:
        check = e.get("check", "?").upper()
        c_color = {"PASS": "#0E7C3F", "FAIL": "#B22222", "UNKNOWN": _hex(MUTED)}.get(
            check, "#444444"
        )
        rows.append(
            [
                Paragraph(
                    f'<font color="{c_color}"><b>{esc(check)}</b></font>',
                    SMALL,
                ),
                Paragraph(esc(e.get("kind", "")), SMALL),
                Paragraph(esc(e.get("detail", ""))[:300], SMALL),
            ]
        )
    t = Table(rows, colWidths=[0.7 * inch, 1.4 * inch, 4.4 * inch], repeatRows=1)
    t.setStyle(
        TableStyle(
            [
                ("BACKGROUND", (0, 0), (-1, 0), DARK),
                ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
                ("GRID", (0, 0), (-1, -1), 0.25, colors.lightgrey),
                ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, PALE]),
                ("VALIGN", (0, 0), (-1, -1), "TOP"),
                ("TOPPADDING", (0, 0), (-1, -1), 3),
                ("BOTTOMPADDING", (0, 0), (-1, -1), 3),
            ]
        )
    )
    return t


# ---------------------------------------------------------------------------
# Page renderers
# ---------------------------------------------------------------------------


def render_finding(f: dict) -> list:
    out: list = []
    locs = f.get("locations") or []
    primary = locs[0] if locs else {}
    loc_str = (
        f"{primary.get('path', 'unknown')}:{primary.get('start_line', '?')}"
        + (f"-{primary['end_line']}" if primary.get("end_line") else "")
    )
    sev = (f.get("severity") or "").lower()
    sev_color = SEV_COLORS.get(sev, MUTED)
    grounded = "[grounded]" if f.get("grounded") else "[ungrounded]"
    title = (
        f'<font color="{_hex(sev_color)}"><b>[{sev.upper()}]</b></font> '
        f'{esc(f.get("title", ""))}  '
        f'<font color="#888888">{f.get("id","")} {grounded}</font>'
    )
    out.append(Paragraph(title, H3))

    out.append(
        kv_table(
            [
                ("CWE", f.get("cwe", "unknown")),
                ("Location", loc_str),
                ("Confidence", f"{f.get('confidence', 0):.2f}"),
                ("Lens / stage", f"{f.get('skill', '-')} / {f.get('stage', '-')}"),
                ("Validator", f.get("validator_verdict", "-")),
                (
                    "CVSS",
                    (
                        f"{f.get('cvss_vector','')}"
                        + (f"  (score {f['cvss_score']:.1f})" if f.get("cvss_score") is not None else "")
                    ).strip()
                    or "-",
                ),
                ("Tags", ", ".join(f.get("tags", []) or []) or "-"),
            ],
            col_widths=(1.4 * inch, 5.1 * inch),
        )
    )
    out.append(Spacer(1, 0.06 * inch))

    out.append(Paragraph("Description", H4))
    out.append(Paragraph(esc(f.get("description", "") or "(none)"), BODY))

    # Taint flow
    taint = f.get("taint") or {}
    if taint.get("source") or taint.get("sink"):
        out.append(Paragraph("Taint flow", H4))
        rows = []
        if taint.get("source"):
            src_loc = taint.get("source_location") or {}
            rows.append(
                (
                    "Source",
                    f"{taint['source']}"
                    + (f"  at  {src_loc.get('path','')}:{src_loc.get('start_line','')}" if src_loc else ""),
                )
            )
        if taint.get("sink"):
            snk_loc = taint.get("sink_location") or {}
            rows.append(
                (
                    "Sink",
                    f"{taint['sink']}"
                    + (f"  at  {snk_loc.get('path','')}:{snk_loc.get('start_line','')}" if snk_loc else ""),
                )
            )
        rows.append(("Sanitizer missing", str(taint.get("sanitizer_missing"))))
        observed = taint.get("sanitizers_observed") or []
        if observed:
            rows.append(("Sanitizers observed", ", ".join(observed)))
        steps = taint.get("taint_path") or []
        if steps:
            chain = " -> ".join(f"{s.get('path','')}:{s.get('start_line','')}" for s in steps)
            rows.append(("Path", chain))
        out.append(kv_table(rows, col_widths=(1.4 * inch, 5.1 * inch)))

    # Attack chain
    chain = f.get("attack_chain") or []
    if chain:
        out.append(Paragraph("Attack chain", H4))
        for i, step in enumerate(chain[:12], start=1):
            out.append(Paragraph(f"<b>{i}.</b> {esc(step)}", BODY))

    # PoC
    poc = f.get("poc")
    if poc:
        out.append(Paragraph("Proof of concept", H4))
        if poc.get("is_concrete"):
            if poc.get("payload"):
                out.append(Paragraph("<b>Payload</b>", SMALL))
                out.append(Preformatted(poc["payload"][:1500], MONO))
            if poc.get("invocation"):
                out.append(Paragraph("<b>Invocation</b>", SMALL))
                out.append(Preformatted(poc["invocation"][:1500], MONO))
            if poc.get("expected_effect"):
                out.append(Paragraph(f"<b>Expected effect:</b> {esc(poc['expected_effect'])}", SMALL))
        else:
            out.append(
                Paragraph(
                    f"<i>No concrete PoC.</i> {esc(poc.get('expected_effect', '(no rationale)'))}",
                    SMALL,
                )
            )

    # Evidence
    if f.get("evidence"):
        out.append(Paragraph("Evidence collected", H4))
        out.append(evidence_table(f["evidence"]))

    # Remediation
    out.append(Paragraph("Remediation", H4))
    out.append(Paragraph(esc(f.get("remediation", "") or "(none)"), BODY))

    out.append(Spacer(1, 0.18 * inch))
    return out


# ---------------------------------------------------------------------------
# Entrypoint
# ---------------------------------------------------------------------------


def _by_sev(findings: list[dict]) -> dict[str, int]:
    out = {s: 0 for s in ("critical", "high", "medium", "low", "informational")}
    for f in findings:
        out[(f.get("severity") or "informational").lower()] = (
            out.get((f.get("severity") or "informational").lower(), 0) + 1
        )
    return out


def _findings_from_manifest(manifest: dict) -> tuple[list[dict], list[dict]]:
    """Pull final findings + dropped findings out of the manifest.

    The harness emits the final survivors via the s9_emit stage's findings
    list. Dropped findings live in earlier stages' artifacts.
    """
    final: list[dict] = []
    dropped: list[dict] = []
    for stage in manifest.get("stages", []):
        sid = stage.get("stage_id")
        if sid == "s9_emit":
            final = stage.get("findings", []) or []
        elif sid in {"s4b_grounding", "s6b_validator"}:
            # these stages partition; the dropped IDs are listed in artifacts.
            pass
    # For dropped: walk every stage's findings and keep ones whose id isn't
    # in the final list. This is a heuristic but works.
    seen_final = {f.get("id") for f in final}
    seen_dropped: set[str] = set()
    for stage in manifest.get("stages", []):
        for f in stage.get("findings", []) or []:
            fid = f.get("id")
            if fid and fid not in seen_final and fid not in seen_dropped:
                if any(t.startswith("dropped:") or t.startswith("hallucinated:") for t in f.get("tags") or []):
                    dropped.append(f)
                    seen_dropped.add(fid)
    return final, dropped


def main() -> int:
    p = argparse.ArgumentParser()
    p.add_argument("manifest", type=Path, help="Path to run_manifest.json")
    p.add_argument("--output", "-o", type=Path, required=True, help="Output PDF path")
    p.add_argument("--title", default="redeye Security Scan Report")
    p.add_argument("--target-name", default=None, help="Display name for the target.")
    args = p.parse_args()

    if not args.manifest.is_file():
        print(f"manifest not found: {args.manifest}", file=sys.stderr)
        return 2

    data = json.loads(args.manifest.read_text(encoding="utf-8"))
    stages = {s["stage_id"]: s for s in data.get("stages", []) or []}

    findings, dropped = _findings_from_manifest(data)
    by_sev = _by_sev(findings)

    started = data.get("started_at")
    ended = data.get("ended_at")
    try:
        s_dt = datetime.fromisoformat((started or "").replace("Z", "+00:00"))
        e_dt = datetime.fromisoformat((ended or "").replace("Z", "+00:00"))
        duration_min = round((e_dt - s_dt).total_seconds() / 60, 2)
        when = f"{s_dt.strftime('%Y-%m-%d %H:%M UTC')} -> {e_dt.strftime('%H:%M UTC')} ({duration_min} min)"
    except Exception:
        when = f"{started or '-'} -> {ended or '-'}"

    target_name = args.target_name or Path(data.get("target_repo", "target")).name

    doc = SimpleDocTemplate(
        str(args.output),
        pagesize=LETTER,
        rightMargin=0.75 * inch,
        leftMargin=0.75 * inch,
        topMargin=0.75 * inch,
        bottomMargin=0.75 * inch,
        title=f"{target_name} -- {args.title}",
    )

    story: list = []

    # ---- Cover ----
    story.append(Spacer(1, 1.0 * inch))
    story.append(Paragraph(args.title, H1))
    story.append(Spacer(1, 0.18 * inch))
    story.append(Paragraph(target_name, CENTER))
    story.append(Spacer(1, 0.4 * inch))
    story.append(
        kv_table(
            [
                ("Application ID", data.get("application_id") or target_name),
                ("Repository", data.get("target_repo", "-")),
                ("Commit", (data.get("target_sha") or "-")[:12]),
                ("Tool / version", f"{data.get('tool', 'redeye')} {data.get('version', '')}"),
                ("Profile", data.get("profile", "-")),
                ("Config hash", (data.get("config_hash") or "-")[:16]),
                ("Scan window", when),
                ("Estimated cost (USD)", f"${data.get('total_cost_usd', 0):.3f}"),
                ("Findings emitted", str(data.get("finding_count", len(findings)))),
                ("Findings dropped", str(data.get("dropped_count", len(dropped)))),
            ]
        )
    )
    story.append(Spacer(1, 0.2 * inch))
    story.append(
        Paragraph(
            "<i>This report is generated by an LLM-driven agentic SAST harness. Findings are "
            "triage candidates, not confirmed vulnerabilities. Treat severity, CWE, and attack "
            "chains as starting points for human review.</i>",
            SMALL,
        )
    )
    story.append(PageBreak())

    # ---- Executive summary ----
    story.append(Paragraph("Executive summary", H2))
    crit = by_sev.get("critical", 0) + by_sev.get("high", 0)
    if findings:
        verdict = (
            f"The harness emitted <b>{len(findings)} finding(s)</b>, of which "
            f"<b>{crit}</b> are at Critical or High severity."
        )
    else:
        verdict = (
            "The harness completed without emitting any code-level findings that survived "
            "the deterministic grounding pass. The structural inventory and threat model below "
            "are the actionable output for manual follow-up."
        )
    story.append(Paragraph(verdict, BODY))
    story.append(Spacer(1, 0.1 * inch))
    story.append(Paragraph("Severity counts", H3))
    story.append(severity_summary_table(by_sev))
    story.append(Spacer(1, 0.18 * inch))

    metrics = data.get("hallucination_metrics") or {}
    story.append(Paragraph("Pipeline quality metrics", H3))
    story.append(
        Paragraph(
            "These counters reflect findings the pipeline pruned before reaching this report. "
            "High <b>ungrounded_dropped</b> or <b>voted_out</b> numbers mean the lenses were "
            "hallucinating on this target -- the harness caught them, you didn't have to.",
            SMALL,
        )
    )
    story.append(Spacer(1, 0.05 * inch))
    story.append(metrics_table(metrics))

    # ---- Structural inventory (S1b) ----
    s1b = (stages.get("s1b_structural") or {}).get("artifacts") or {}
    structural_summary = s1b.get("structural_summary") or {}
    if structural_summary:
        story.append(Spacer(1, 0.18 * inch))
        story.append(Paragraph("Structural inventory (S1b, deterministic)", H3))
        story.append(
            Paragraph(
                "Extracted by regex + AST without any LLM call. This is the ground truth the "
                "research lenses reasoned from -- no path here is invented.",
                SMALL,
            )
        )
        story.append(Spacer(1, 0.05 * inch))
        story.append(structural_table(structural_summary))

        idx = s1b.get("structural_index") or {}
        sinks = idx.get("sinks") or []
        if sinks:
            story.append(Spacer(1, 0.1 * inch))
            story.append(Paragraph("Top dangerous sinks observed", H4))
            for h in sinks[:10]:
                cwe = h.get("cwe", "")
                story.append(
                    Paragraph(
                        f"<b>{esc(h.get('kind', ''))}</b> "
                        f"<font color=\"888\">{esc(cwe)}</font> -- "
                        f"{esc(h.get('path', ''))}:{h.get('line', '')}",
                        SMALL,
                    )
                )
        secrets = idx.get("secrets") or []
        if secrets:
            story.append(Spacer(1, 0.05 * inch))
            story.append(Paragraph("Suspected secrets", H4))
            for h in secrets[:8]:
                story.append(
                    Paragraph(
                        f"<b>{esc(h.get('kind', ''))}</b> -- "
                        f"{esc(h.get('path', ''))}:{h.get('line', '')}",
                        SMALL,
                    )
                )

    story.append(PageBreak())

    # ---- Attack surface (S1) and threat model (S2) ----
    s1 = (stages.get("s1_attack_surface") or {}).get("artifacts", {}).get("attack_surface", {}) or {}
    if s1:
        story.append(Paragraph("Attack surface (S1)", H2))
        if s1.get("summary"):
            story.append(Paragraph(esc(s1["summary"]), BODY))
        for label, key in [
            ("Entrypoints", "entrypoints"),
            ("Auth boundaries", "auth_boundaries"),
            ("Sensitive sinks", "sensitive_sinks"),
        ]:
            items = s1.get(key) or []
            if not items:
                continue
            story.append(Paragraph(label, H3))
            for item in items[:15]:
                if isinstance(item, dict):
                    line = " -- ".join(
                        f"<b>{esc(k)}:</b> {esc(v)}"
                        for k, v in item.items()
                        if v and isinstance(v, (str, int, float))
                    )
                    story.append(Paragraph(line, SMALL))
                else:
                    story.append(Paragraph(f"- {esc(item)}", SMALL))

    s2 = (stages.get("s2_threat_model") or {}).get("artifacts", {}).get("threat_model", {}) or {}
    if s2:
        story.append(Spacer(1, 0.15 * inch))
        story.append(Paragraph("Threat model (S2)", H2))
        for label, key in [
            ("Actors", "actors"),
            ("Trust boundaries", "trust_boundaries"),
            ("Top risks", "top_risks"),
        ]:
            items = s2.get(key) or []
            if not items:
                continue
            story.append(Paragraph(label, H3))
            for item in items[:15]:
                story.append(Paragraph(f"- {esc(item)}", BODY))

        stride = s2.get("stride") or []
        if stride:
            story.append(Paragraph("STRIDE", H3))
            for row in stride[:15]:
                cat = row.get("category", "")
                asset = row.get("asset", "")
                score = row.get("score", "")
                note = row.get("note", "")
                story.append(
                    Paragraph(
                        f"<b>{esc(cat)}</b> -- {esc(asset)} (<b>{esc(score)}</b>): {esc(note)}",
                        SMALL,
                    )
                )

    story.append(PageBreak())

    # ---- Findings ----
    story.append(Paragraph("Findings", H2))
    if not findings:
        story.append(
            Paragraph(
                "<i>No code-level findings survived the v0.3 quality pipeline on this scan. "
                "See the quality metrics on page 2 for what was filtered, and the structural "
                "inventory above for follow-up targets.</i>",
                BODY,
            )
        )
    else:
        # Sort by severity descending then by id.
        sev_order = {"critical": 5, "high": 4, "medium": 3, "low": 2, "informational": 1}
        findings_sorted = sorted(
            findings,
            key=lambda f: (
                -sev_order.get((f.get("severity") or "").lower(), 0),
                f.get("id", ""),
            ),
        )
        for f in findings_sorted:
            story.extend(render_finding(f))

    # ---- Appendix ----
    if dropped:
        story.append(PageBreak())
        story.append(Paragraph("Appendix -- dropped findings", H2))
        story.append(
            Paragraph(
                "These candidate findings were emitted by S4 lenses but did not survive "
                "the deterministic grounding pass, the policy gate, or the validator. "
                "They are preserved here so reviewers can second-guess the harness.",
                SMALL,
            )
        )
        story.append(Spacer(1, 0.1 * inch))
        for f in dropped[:30]:
            story.extend(render_finding(f))

    # ---- Footer / next steps ----
    story.append(PageBreak())
    story.append(Paragraph("Next steps", H2))
    story.append(
        Paragraph(
            "1. Triage every Critical or High finding manually -- LLM verdicts are not "
            "ground truth.<br/>"
            "2. Inspect the structural inventory's top sinks / secrets even if the harness "
            "did not flag them.<br/>"
            "3. Re-run with a tuned profile against individual app workspaces for "
            "deeper S4 coverage.<br/>"
            "4. Tick TP / FP boxes on the companion PR comment so the next scan benefits "
            "from feedback context.",
            BODY,
        )
    )
    story.append(Spacer(1, 0.15 * inch))
    story.append(
        Paragraph(
            f"Generated by redeye {data.get('version', '')} "
            f"(profile <b>{data.get('profile', '')}</b>) "
            f"-- companion artifacts: SARIF + Markdown + run_manifest.json.",
            SMALL,
        )
    )

    doc.build(story)
    print(args.output)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
