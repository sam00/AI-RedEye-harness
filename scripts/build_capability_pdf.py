#!/usr/bin/env python3
"""Generate the full RedEye structure & capability document as a styled PDF.

This is a *product* document (not a per-scan report): it describes the
architecture, the 9-stage pipeline, the hallucination-reduction layer, the
skills catalog, multi-cloud backends, configuration knobs (including the
S1 intake controls, S2 threat-model knobs, and external-scanner ingestion),
CLI surface, profiles, outputs, and operational features.

Pure Python -- only depends on ``reportlab``. Run:

    python scripts/build_capability_pdf.py -o docs/RedEye-Structure-and-Capabilities.pdf
"""

from __future__ import annotations

import argparse
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

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

try:
    from redeye import __version__ as REDEYE_VERSION
except Exception:  # pragma: no cover - doc build should not depend on import
    REDEYE_VERSION = "0.3.0"

# ---------------------------------------------------------------------------
# Styling (matches scripts/build_report_pdf.py)
# ---------------------------------------------------------------------------

PURPLE = colors.HexColor("#7B189F")
DARK = colors.HexColor("#1A1A1A")
MUTED = colors.HexColor("#555555")
PALE = colors.HexColor("#F4F4F6")

_styles = getSampleStyleSheet()


def _style(name: str, parent: str = "BodyText", **kw) -> ParagraphStyle:
    if name in _styles.byName:
        return _styles[name]
    s = ParagraphStyle(name=name, parent=_styles[parent], **kw)
    _styles.add(s)
    return s


H1 = _style("CapH1", "Heading1", fontSize=24, leading=28, textColor=PURPLE, spaceAfter=12)
H2 = _style("CapH2", "Heading2", fontSize=16, leading=20, textColor=PURPLE, spaceBefore=16, spaceAfter=6)
H3 = _style("CapH3", "Heading3", fontSize=12.5, leading=16, textColor=DARK, spaceBefore=10, spaceAfter=4)
BODY = _style("CapBody", "BodyText", fontSize=10, leading=14, textColor=DARK, spaceAfter=6)
SMALL = _style("CapSmall", "BodyText", fontSize=8.5, leading=11, textColor=MUTED)
CENTER = _style("CapCenter", "BodyText", fontSize=14, alignment=TA_CENTER, textColor=DARK)
BULLET = _style("CapBullet", "BodyText", fontSize=10, leading=14, textColor=DARK, leftIndent=14, spaceAfter=2)


def esc(text: Any) -> str:
    return str(text).replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")


def kv_table(rows, col_widths=(1.9 * inch, 4.6 * inch)) -> Table:
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


def grid_table(header: list[str], rows: list[list[str]], col_widths: list[float]) -> Table:
    head = [Paragraph(f"<b>{esc(h)}</b>", SMALL) for h in header]
    data = [head]
    for r in rows:
        data.append([Paragraph(esc(c), SMALL) for c in r])
    t = Table(data, colWidths=col_widths, repeatRows=1)
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


def bullets(story: list, items: list[str]) -> None:
    for it in items:
        story.append(Paragraph(f"&bull;&nbsp;&nbsp;{it}", BULLET))


# ---------------------------------------------------------------------------
# Content
# ---------------------------------------------------------------------------

PIPELINE = [
    ("S1", "s1_attack_surface", "attack_surface_mapper", "LLM",
     "Walks the repo, identifies entrypoints, sensitive sinks, auth boundaries; emits the attack-surface map. Owns repo-intake knobs."),
    ("S1b", "s1b_structural", "structural_index", "Deterministic",
     "Regex + AST ground-truth inventory: routes, sources, sinks, secrets. Folds external scanner reports into the map. Zero LLM cost."),
    ("S2", "s2_threat_model", "threat_modeler", "LLM",
     "STRIDE/OWASP threat model over the surface + structural evidence. Configurable threat/evidence caps and a threat baseline."),
    ("S3", "s3_strategize", "research_strategist", "LLM",
     "Chooses which research lenses to spend budget on, guided by the threat model."),
    ("S4", "s4_research", "research_lenses", "LLM",
     "The core finding generator: language, crypto, logic, access-control and IaC lenses produce candidate findings with taint flow."),
    ("S4b", "s4b_grounding", "(grounding pass)", "Deterministic",
     "Verifies every cited file path, line number and snippet against real code. Drops or downgrades hallucinated findings."),
    ("S5", "s5_policy_gate", "(policy gate)", "Deterministic",
     "Applies policy: required taint slots, severity floors, allow/deny rules."),
    ("S6", "s6_adversarial", "adversarial_reviewer", "LLM",
     "Adversarial refinement, then N-of-M multi-agent voting to kill correlated false positives."),
    ("S6b", "s6b_validator", "validator", "LLM",
     "Single-pass precision-filter validator: cheap auto-reject of obvious garbage."),
    ("S7", "s7_dedupe", "(dedupe)", "Deterministic",
     "Fingerprint-based de-duplication and local baseline filtering of already-accepted findings."),
    ("S8", "s8_chain", "exploit_strategist", "LLM",
     "Links related findings into multi-step attack chains."),
    ("S8b", "s8b_poc", "poc_gate", "LLM",
     "Demands a concrete proof-of-concept; demotes (or drops) findings with only hand-wavy PoCs."),
    ("S8c", "s8c_verify", "(verification)", "Deterministic",
     "Outcome verification: collapses grounding/taint/PoC/reachability/votes into a single auditable verdict."),
    ("S9", "s9_emit", "(emitter)", "Deterministic",
     "Writes Markdown report, SARIF 2.1.0, and feeds the run manifest."),
]

DETERMINISTIC_CHECKS = [
    "<b>Structural pre-index (S1b)</b> -- real routes/sources/sinks so lenses reason from ground truth, not imagination.",
    "<b>Taint schema</b> -- every finding must declare source, sink and the path between them, or it isn't a finding.",
    "<b>Grounding pass (S4b)</b> -- cited paths/lines/snippets are verified against the actual file system.",
    "<b>Policy gate (S5)</b> -- required slots and severity floors enforced before spend on later stages.",
    "<b>Multi-agent voting (S6)</b> -- N-of-M voting kills correlated false positives across model families.",
    "<b>Validator auto-reject (S6b)</b> -- a cheap single-pass precision filter drops obvious garbage.",
    "<b>PoC gate (S8b) + outcome verification (S8c)</b> -- concrete exploit demanded; signals collapsed into a verdict.",
]

S1_KNOBS = [
    ("exclude_dirs", "Directory names to skip during intake (merged with defaults)."),
    ("exclude_exts", "File extensions to drop; leading dot optional (e.g. .min.js)."),
    ("exclude_globs", "fnmatch globs against the repo-relative path."),
    ("max_file_kb", "Skip files larger than N KB (combined with max_file_bytes; smaller wins)."),
    ("follow_symlinks", "If false (default), symlinked files are skipped."),
    ("dedupe_configs", "Drop byte-identical config files (.yaml/.json/.toml/.ini/.env/...)."),
]

S2_KNOBS = [
    ("enabled", "false -> skip threat modeling entirely (no LLM call)."),
    ("max_threats", "Cap the number of emitted STRIDE entries."),
    ("baseline", "Path to accepted-threat signatures (category|asset) to subtract."),
    ("max_document_chars", "Cap the attack-surface document fed into the prompt."),
    ("max_modules / max_entry_points", "Evidence caps: modules and entry points injected."),
    ("max_config_reps / max_api_artifacts", "Evidence caps: config reps and API artifacts injected."),
]

BACKENDS = [
    ("Anthropic CLI", "cli_claude", "Local Claude CLI; no API key plumbing, great for laptops."),
    ("Anthropic SDK", "sdk_anthropic", "Direct Anthropic API (Claude models)."),
    ("OpenAI-compatible", "openai_compat", "OpenAI and any OpenAI-compatible endpoint."),
    ("AWS Bedrock", "bedrock", "Managed frontier models in AWS."),
    ("Google Vertex", "vertex", "Gemini models via Vertex AI."),
    ("Ollama (local)", "ollama", "Fully local/offline models."),
    ("Mock", "mock", "Deterministic, zero-cost backend for demos and tests."),
]

CLI_COMMANDS = [
    ("redeye scan", "Run the full 9-stage pipeline against one or many repos."),
    ("redeye estimate", "Print scope and approximate USD cost. No LLM calls."),
    ("redeye doctor", "Verify credentials and backend reachability for a profile."),
    ("redeye setup / init", "Interactive setup; detect creds, pick a profile, write .env / config.yaml."),
    ("redeye baseline", "accept / list / remove findings so they don't reappear."),
    ("redeye collect-feedback", "Ingest TP/FP marks from a PR comment into the feedback store."),
]

SCAN_FLAGS = [
    ("--repo / --repo-file", "Single repo or CSV batch."),
    ("--profile / --preset", "Cost model + roles; preset = pr|ci|deep|quick one-flag combos."),
    ("--diff-only / --pr-base", "Scan only files changed vs a base ref (PR scans)."),
    ("--exclude-path / --exclude-dir / --exclude-ext / --exclude-glob", "Intake exclusions (merged with config.yaml)."),
    ("--max-files / --max-file-bytes / --max-file-kb / --max-total-bytes", "DoS / cost limits on intake."),
    ("--follow-symlinks / --dedupe-configs", "Symlink traversal; config-file de-duplication."),
    ("--external-scan PATH", "Fold a SARIF/Semgrep/generic-JSON scanner report into the map (repeatable)."),
    ("--strict-grounding / --require-poc", "Drop (vs downgrade) ungrounded / PoC-less findings."),
    ("--store-findings / --use-feedback", "Persist to and reuse the local feedback DB."),
    ("--pr-comment / --webhook-url", "Emit a PR-comment Markdown; post a summary to Slack/Teams/Discord."),
]

OUTPUTS = [
    ("Markdown report", "Human-readable findings, quality metrics, structural inventory, external-scanner summary."),
    ("SARIF 2.1.0", "Canonical machine output for code-scanning integrations."),
    ("run_manifest.json", "Full audit record: every stage, artifacts, cost, hallucination metrics."),
    ("PR comment", "GitHub-shaped Markdown for CI gating with TP/FP checkboxes."),
    ("PDF (this toolchain)", "Styled per-scan report (build_report_pdf.py) and this capability doc."),
]


def build(output: Path) -> None:
    doc = SimpleDocTemplate(
        str(output),
        pagesize=LETTER,
        rightMargin=0.75 * inch,
        leftMargin=0.75 * inch,
        topMargin=0.75 * inch,
        bottomMargin=0.75 * inch,
        title=f"RedEye {REDEYE_VERSION} -- Structure & Capabilities",
    )
    story: list = []
    now = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")

    # ---- Cover ----
    story.append(Spacer(1, 1.4 * inch))
    story.append(Paragraph("RedEye", H1))
    story.append(Paragraph("Structure &amp; Capability Document", CENTER))
    story.append(Spacer(1, 0.5 * inch))
    story.append(
        kv_table(
            [
                ("Tool", f"redeye {REDEYE_VERSION}"),
                ("Category", "Agentic SAST harness for autonomous vulnerability discovery"),
                ("Output", "SARIF 2.1.0 + Markdown + JSON manifest + PDF"),
                ("Backends", "Anthropic (CLI/SDK), OpenAI-compatible, AWS Bedrock, Google Vertex, Ollama"),
                ("Generated", now),
            ]
        )
    )
    story.append(Spacer(1, 0.3 * inch))
    story.append(
        Paragraph(
            "<i>Authorized use only. Findings are LLM-generated triage candidates that require "
            "human review.</i>",
            SMALL,
        )
    )
    story.append(PageBreak())

    # ---- Overview ----
    story.append(Paragraph("1. Overview", H2))
    story.append(
        Paragraph(
            "RedEye pairs the deep multi-stage pipeline of an offline research harness with the "
            "operational layer of a CI/CD scanner -- the same tool runs as a researcher's deep "
            "dive and as a PR gate. It is multi-cloud by design: no single LLM provider is a "
            "dependency.",
            BODY,
        )
    )
    story.append(Paragraph("Three design choices drive finding quality:", BODY))
    bullets(
        story,
        [
            "<b>Threat modeling before analysis</b> -- focuses the surface so lenses don't waste budget.",
            "<b>Multi-agent voting + single-pass validator</b> -- kills correlated false positives and obvious garbage.",
            "<b>Feedback loop</b> -- reviewer TP/FP marks persist locally and calibrate the next scan.",
        ],
    )

    # ---- Pipeline ----
    story.append(Paragraph("2. Pipeline architecture (9 core stages + sub-stages)", H2))
    story.append(
        Paragraph(
            "Each stage is a callable consuming a StageContext and returning a StageResult. The "
            "orchestrator owns flow; stages own content. Deterministic stages cost zero LLM tokens.",
            BODY,
        )
    )
    story.append(
        grid_table(
            ["#", "Stage", "Skill", "Type", "Responsibility"],
            [[a, b, c, d, e] for (a, b, c, d, e) in PIPELINE],
            [0.4 * inch, 1.25 * inch, 1.25 * inch, 0.95 * inch, 2.85 * inch],
        )
    )

    # ---- Hallucination layer ----
    story.append(Paragraph("3. Hallucination-reduction layer", H2))
    story.append(
        Paragraph(
            "Seven deterministic and adversarial checks sit in front of every finding, so what "
            "reaches a reviewer cites real code and survived every cheap check the harness can run:",
            BODY,
        )
    )
    bullets(story, DETERMINISTIC_CHECKS)

    story.append(PageBreak())

    # ---- Repo intake ----
    story.append(Paragraph("4. Repo intake & file inventory (S1)", H2))
    story.append(
        Paragraph(
            "The s1_attack_surface stage owns intake. Knobs live under its params in config.yaml "
            "and have matching CLI flags; scalar CLI flags win, list flags merge (union) with config.",
            BODY,
        )
    )
    story.append(
        grid_table(
            ["Knob", "Behaviour"],
            [[k, v] for (k, v) in S1_KNOBS],
            [2.2 * inch, 4.5 * inch],
        )
    )

    # ---- Threat model knobs ----
    story.append(Paragraph("5. Threat-model controls (S2)", H2))
    story.append(
        Paragraph(
            "The s2_threat_model stage is fully tunable: toggle it, cap output threats, subtract a "
            "threat baseline, and bound how much structural evidence is injected into the prompt.",
            BODY,
        )
    )
    story.append(
        grid_table(
            ["Knob", "Behaviour"],
            [[k, v] for (k, v) in S2_KNOBS],
            [2.2 * inch, 4.5 * inch],
        )
    )

    # ---- External ingestion ----
    story.append(Paragraph("6. External scanner ingestion (mapping enrichment)", H2))
    story.append(
        Paragraph(
            "RedEye consumes third-party scanner output -- <b>SARIF 2.1.0</b>, <b>Semgrep JSON</b>, "
            "and <b>generic JSON</b> -- and folds each finding's location into the structural map as "
            "a candidate sink hit. Provide reports via the s1b_structural.params.external_scanners "
            "list in config.yaml or the repeatable --external-scan CLI flag.",
            BODY,
        )
    )
    story.append(
        Paragraph(
            "<b>Mapping enrichment, not blind trust:</b> an imported location becomes a candidate "
            "only -- it still has to clear grounding (S4b), voting (S6) and outcome verification "
            "(S8c) before it can reach the report. An ingestion summary is written to the Markdown "
            "report, the PDF report, and the run manifest.",
            BODY,
        )
    )

    story.append(PageBreak())

    # ---- Backends ----
    story.append(Paragraph("7. Multi-cloud LLM backends", H2))
    story.append(
        grid_table(
            ["Backend", "Module", "Notes"],
            [[a, b, c] for (a, b, c) in BACKENDS],
            [1.6 * inch, 1.6 * inch, 3.5 * inch],
        )
    )
    story.append(
        Paragraph(
            "Profiles bundled: default, cli, full, mock, ollama_local. Each profile maps logical "
            "roles (surveyor, researcher, adversary, ...) to concrete models, temperatures, token "
            "and per-stage USD budgets.",
            SMALL,
        )
    )

    # ---- CLI ----
    story.append(Paragraph("8. CLI surface", H2))
    story.append(
        grid_table(
            ["Command", "Purpose"],
            [[a, b] for (a, b) in CLI_COMMANDS],
            [1.9 * inch, 4.8 * inch],
        )
    )
    story.append(Spacer(1, 0.1 * inch))
    story.append(Paragraph("Key <font face='Helvetica-Bold'>scan</font> flags", H3))
    story.append(
        grid_table(
            ["Flag(s)", "Effect"],
            [[a, b] for (a, b) in SCAN_FLAGS],
            [2.8 * inch, 3.9 * inch],
        )
    )

    story.append(PageBreak())

    # ---- Outputs ----
    story.append(Paragraph("9. Outputs & artifacts", H2))
    story.append(
        grid_table(
            ["Artifact", "Contents"],
            [[a, b] for (a, b) in OUTPUTS],
            [1.9 * inch, 4.8 * inch],
        )
    )

    # ---- Operational ----
    story.append(Paragraph("10. Operational features", H2))
    bullets(
        story,
        [
            "<b>Presets</b> -- pr / ci / deep / quick collapse common flag combos; explicit flags always win.",
            "<b>PR scans</b> -- --diff-only against a base ref for fast, scoped CI gating.",
            "<b>Baseline</b> -- accept findings so they're filtered from future scans (.redeye-baseline.yaml).",
            "<b>Feedback loop</b> -- TP/FP marks persist to ~/.redeye/scans.db and re-enter S4 lens prompts.",
            "<b>Notifications</b> -- Slack/Teams/Discord/generic webhooks; GitHub PR-comment Markdown.",
            "<b>Cost governance</b> -- per-stage max_budget_usd ceilings; estimate command (intake-aware) for dry costing.",
            "<b>DoS protection</b> -- file/byte/KB caps and exclusions bound worst-case intake.",
            "<b>Secret redaction</b> -- the Markdown report masks known credential shapes and sensitive key=value pairs before hitting disk.",
        ],
    )

    # ---- Config precedence ----
    story.append(Paragraph("11. Configuration precedence", H2))
    story.append(
        Paragraph(
            "1) Explicit CLI flags  &gt;  2) ./config.yaml  &gt;  3) selected profile  &gt;  "
            "4) bundled defaults. Environment variables already set win over .env files. List-type "
            "intake exclusions are merged (config baseline + CLI additions).",
            BODY,
        )
    )

    # ---- Limitations ----
    story.append(Paragraph("12. Limitations & responsible use", H2))
    bullets(
        story,
        [
            "Findings are LLM-generated triage candidates, not confirmed vulnerabilities.",
            "Run only against code you own or are explicitly authorized to test.",
            "Severity, CWE and attack chains are starting points for human review.",
            "Deterministic checks reduce -- but do not eliminate -- false positives and negatives.",
        ],
    )
    story.append(Spacer(1, 0.2 * inch))
    story.append(
        Paragraph(
            f"Generated from the redeye {REDEYE_VERSION} codebase. Companion docs: SETUP_GUIDE, "
            "USER_GUIDE, architecture.md, SKILLS.md, configuration.md.",
            SMALL,
        )
    )

    doc.build(story)


def main() -> int:
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument(
        "--output",
        "-o",
        type=Path,
        default=Path("docs/RedEye-Structure-and-Capabilities.pdf"),
        help="Output PDF path.",
    )
    args = p.parse_args()
    args.output.parent.mkdir(parents=True, exist_ok=True)
    build(args.output)
    print(args.output)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
