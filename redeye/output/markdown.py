"""Markdown report emitter."""

from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from redeye import __version__
from redeye.schema import Finding, Severity

_SEV_BADGE = {
    Severity.CRITICAL: "[CRITICAL]",
    Severity.HIGH: "[HIGH]",
    Severity.MEDIUM: "[MED]",
    Severity.LOW: "[LOW]",
    Severity.INFO: "[INFO]",
}


def _by_severity(findings: list[Finding]) -> dict[Severity, list[Finding]]:
    bucket: dict[Severity, list[Finding]] = {s: [] for s in Severity}
    for f in findings:
        bucket[f.severity].append(f)
    return bucket


def _render_taint(f: Finding) -> str:
    t = f.taint
    if not (t.source or t.sink):
        return "_(no taint flow recorded -- this finding may be hand-wavy)_"
    parts = [
        f"- **Source:** `{t.source or '?'}`"
        + (
            f" at `{t.source_location.path}:{t.source_location.start_line}`"
            if t.source_location
            else ""
        ),
        f"- **Sink:** `{t.sink or '?'}`"
        + (f" at `{t.sink_location.path}:{t.sink_location.start_line}`" if t.sink_location else ""),
        f"- **Sanitizer missing:** {t.sanitizer_missing}"
        + (f" (observed: {', '.join(t.sanitizers_observed)})" if t.sanitizers_observed else ""),
    ]
    if t.taint_path:
        steps = " -> ".join(f"`{s.path}:{s.start_line}`" for s in t.taint_path)
        parts.append(f"- **Path:** {steps}")
    return "\n".join(parts)


def _render_evidence(f: Finding) -> str:
    if not f.evidence:
        return "_(no evidence rows)_"
    rows = []
    for e in f.evidence[:12]:
        icon = {"pass": "[PASS]", "fail": "[FAIL]", "unknown": "[?]"}.get(e.check, "[?]")
        rows.append(f"- {icon} **{e.kind}** -- {e.detail[:240]}")
    return "\n".join(rows)


def _render_poc(f: Finding) -> str:
    if f.poc is None:
        return "_(no PoC stage ran)_"
    if not f.poc.is_concrete:
        return f"_no concrete PoC_ -- {f.poc.expected_effect or '(no rationale)'}"
    out = []
    if f.poc.payload:
        out.append("**Payload:**\n```\n" + f.poc.payload[:1500] + "\n```")
    if f.poc.invocation:
        out.append("**Invocation:**\n```\n" + f.poc.invocation[:1500] + "\n```")
    if f.poc.expected_effect:
        out.append(f"**Expected effect:** {f.poc.expected_effect[:600]}")
    return "\n\n".join(out)


def _render_finding(f: Finding) -> str:
    primary = f.locations[0] if f.locations else None
    loc_str = (
        f"{primary.path}:{primary.start_line}"
        + (f"-{primary.end_line}" if primary and primary.end_line else "")
        if primary
        else "unknown"
    )
    chain = "\n".join(f"  {i + 1}. {step}" for i, step in enumerate(f.attack_chain)) or "  (none)"
    votes = (
        "\n".join(
            f"  - **{v.role}** ({v.model}): `{v.verdict}` -- {v.rationale[:160]}" for v in f.votes
        )
        or "  (no votes recorded)"
    )

    grounding_badge = "[grounded]" if f.grounded else "[ungrounded]"
    cvss = ""
    if f.cvss_vector:
        cvss = f"\n- **CVSS:** `{f.cvss_vector}`" + (
            f" (score {f.cvss_score:.1f})" if f.cvss_score is not None else ""
        )

    parts = [
        f"### {_SEV_BADGE[f.severity]} {f.title}  `{f.id}` {grounding_badge}",
        "",
        f"- **CWE:** {f.cwe or 'unknown'}",
        f"- **Location:** `{loc_str}`",
        f"- **Confidence:** {f.confidence:.2f}",
        f"- **Lens / stage:** {f.skill or '-'} / {f.stage or '-'}",
        f"- **Tags:** {', '.join(f.tags) if f.tags else '-'}"
        + (f"\n- **Validator:** {f.validator_verdict}" if f.validator_verdict else "")
        + cvss,
        "",
        "**Description:**",
        "",
        f.description.strip() or "_no description_",
        "",
        "**Taint flow:**",
        "",
        _render_taint(f),
        "",
        "**Attack chain:**",
        "",
        chain,
        "",
        "**Proof of concept:**",
        "",
        _render_poc(f),
        "",
        "**Evidence collected:**",
        "",
        _render_evidence(f),
        "",
        "**Remediation:**",
        "",
        f.remediation.strip() or "_no remediation given_",
        "",
        "**Votes:**",
        "",
        votes,
        "",
        "---",
        "",
    ]
    return "\n".join(parts)


def write_markdown_report(
    *,
    path: Path,
    target: Path,
    application_id: str | None,
    findings: list[Finding],
    attack_surface: dict[str, Any] | None = None,
    threat_model: dict[str, Any] | None = None,
    dropped: list[Finding] | None = None,
    hallucination_metrics: dict[str, int] | None = None,
    structural_summary: dict[str, Any] | None = None,
) -> None:
    dropped = dropped or []
    by_sev = _by_severity(findings)
    now = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")

    lines: list[str] = [
        "# redeye scan report",
        "",
        f"- **Tool:** redeye {__version__}",
        f"- **Target:** `{target}`",
        f"- **Application ID:** {application_id or '-'}",
        f"- **Generated:** {now}",
        f"- **Findings:** {len(findings)} (dropped after voting: {len(dropped)})",
        "",
        "## Summary by severity",
        "",
        "| Severity | Count |",
        "|---|---|",
    ]
    for sev in (Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM, Severity.LOW, Severity.INFO):
        lines.append(f"| {sev.value} | {len(by_sev[sev])} |")
    lines.extend(["", "---", ""])

    if hallucination_metrics:
        # Surface what the pipeline filtered. Operators trust the report more
        # when they can see the harness pruning its own noise.
        lines.extend(
            [
                "## Quality metrics",
                "",
                "These counters reflect findings the pipeline pruned before reaching you. ",
                "High `ungrounded_dropped` or `voted_out` numbers mean the lenses are ",
                "hallucinating; consider tightening the model or the structural inventory.",
                "",
                "| Metric | Count |",
                "|---|---|",
            ]
        )
        labels = {
            "raw_lens": "Raw lens findings (before any filtering)",
            "ungrounded_dropped": "Dropped: cited path or line did not exist (S4b)",
            "ungrounded_downgraded": "Downgraded: weak grounding evidence (S4b)",
            "validator_rejected": "Rejected by single-pass validator (S6.5)",
            "voted_out": "Voted out by multi-agent vote (S6)",
            "missing_poc": "Demoted: no concrete PoC (S8b)",
        }
        for key, label in labels.items():
            if key in hallucination_metrics:
                lines.append(f"| {label} | {hallucination_metrics[key]} |")
        lines.extend(["", "---", ""])

    if structural_summary:
        lines.extend(
            [
                "## Structural inventory (S1b, deterministic)",
                "",
                f"- Files indexed: {structural_summary.get('files_indexed', 0)}",
                f"- Routes detected: {structural_summary.get('routes', 0)}",
                f"- Untrusted-input sources: {structural_summary.get('sources', 0)}",
                f"- Dangerous sinks: {structural_summary.get('sinks', 0)}",
                f"- Suspected secrets: {structural_summary.get('secrets', 0)}",
                "",
                "---",
                "",
            ]
        )

    if attack_surface:
        lines.extend(
            [
                "## Attack surface (S1)",
                "",
                "```json",
                json.dumps(attack_surface, indent=2)[:6000],
                "```",
                "",
            ]
        )
    if threat_model:
        lines.extend(
            [
                "## Threat model (S2)",
                "",
                "```json",
                json.dumps(threat_model, indent=2)[:6000],
                "```",
                "",
            ]
        )

    lines.extend(["## Findings", ""])
    if not findings:
        lines.append("_No findings were emitted by this run._")
    else:
        for sev in (Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM, Severity.LOW, Severity.INFO):
            sev_findings = by_sev[sev]
            if not sev_findings:
                continue
            lines.append(f"### {sev.value.upper()} ({len(sev_findings)})")
            lines.append("")
            for f in sev_findings:
                lines.append(_render_finding(f))

    if dropped:
        lines.extend(
            [
                "## Appendix -- dropped findings",
                "",
                "These findings were produced by S4 lenses but did not survive the",
                "S6 multi-agent voting threshold. They are kept here so reviewers",
                "can second-guess the voters.",
                "",
            ]
        )
        for f in dropped:
            lines.append(_render_finding(f))

    lines.extend(
        [
            "## How to read this report",
            "",
            "Findings are LLM-generated triage candidates. Treat severity, CWE,",
            "and attack-chain as starting points for human review. The companion",
            "SARIF file is canonical for tooling integrations.",
            "",
        ]
    )

    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text("\n".join(lines), encoding="utf-8")
