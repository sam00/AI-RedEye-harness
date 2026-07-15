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


_SIGNAL_LABELS = {
    "grounded": "grounded",
    "taint_complete": "taint",
    "concrete_poc": "PoC",
    "reachable": "reachable",
    "vote_confirmed": "voted",
    "externally_corroborated": "corroborated",
}


def _render_verification(f: Finding) -> str:
    v = f.verification
    if v is None:
        return "_(no outcome verification ran -- S8c disabled for this profile)_"
    passed = sum(1 for ok in v.signals.values() if ok)
    considered = len(v.signals)
    verdict = "[VERIFIED]" if v.verified else "[UNVERIFIED]"
    chips = "  ".join(
        f"{'[x]' if v.signals.get(k) else '[ ]'} {label}"
        for k, label in _SIGNAL_LABELS.items()
        if k in v.signals
    )
    lines = [
        f"- **Verdict:** {verdict} "
        f"(score {v.score:.2f}; {passed}/{considered} signals passed, need {v.threshold})",
        f"- **Signals:** {chips}" if chips else "- **Signals:** _(none recorded)_",
    ]
    if v.rationale:
        lines.append(f"- **Rationale:** {v.rationale}")
    if f.corroborating_tools:
        lines.append(f"- **Corroborated by:** {', '.join(f.corroborating_tools)}")
    if f.calibrated_confidence is not None:
        lines.append(f"- **Calibrated confidence:** {f.calibrated_confidence:.2f}")
    if f.abstained:
        lines.append("- **Abstained:** borderline -- routed to human review, not asserted.")
    return "\n".join(lines)


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
        "**Verification (S8c):**",
        "",
        _render_verification(f),
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
    external_summary: dict[str, Any] | None = None,
    redact: bool = True,
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

    # Verification summary (S8c): how many findings cleared the deterministic
    # K-of-N outcome verdict, and how many an independent scanner corroborated.
    # These are the numbers that make "validated & verified" auditable.
    verified = sum(1 for f in findings if f.verification and f.verification.verified)
    corroborated = sum(1 for f in findings if f.has_external_corroboration())
    abstained = sum(1 for f in findings if f.abstained)
    if findings:
        lines.extend(
            [
                "## Verification summary (S8c)",
                "",
                "Deterministic outcome verification cross-checks each finding against "
                "independent signals (grounding, taint, PoC, reachability, voter agreement, "
                "external-tool corroboration). Prioritise **verified** findings for triage.",
                "",
                "| Metric | Count |",
                "|---|---|",
                f"| Verified (passed K-of-N) | {verified} / {len(findings)} |",
                f"| Externally corroborated | {corroborated} / {len(findings)} |",
                f"| Abstained (routed to human) | {abstained} / {len(findings)} |",
                "",
                "---",
                "",
            ]
        )

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
            "outcome_unverified": "Flagged: failed K-of-N outcome verdict (S8c)",
            "outcome_unverified_dropped": "Dropped: unverified under --require-verified (S8c)",
            "baseline_filtered": "Suppressed: already accepted in baseline",
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

    if external_summary and external_summary.get("count"):
        by_tool = external_summary.get("by_tool", {}) or {}
        lines.extend(
            [
                "## External scanner ingestion (S1b)",
                "",
                "Third-party scanner findings folded into the structural map as candidate ",
                "hotspots. These are *mapping enrichment* -- each still had to clear grounding ",
                "(S4b), voting (S6) and verification (S8c) before reaching the Findings section.",
                "",
                f"- **Findings imported:** {external_summary.get('count', 0)}",
                f"- **Merged as structural hits:** {external_summary.get('hits_added', 0)}",
                "",
                "| Tool | Imported |",
                "|---|---|",
            ]
        )
        for tool, n in sorted(by_tool.items(), key=lambda kv: -kv[1]):
            lines.append(f"| {tool} | {n} |")
        sources = external_summary.get("sources", []) or []
        if sources:
            lines.append("")
            lines.append("Sources: " + ", ".join(f"`{s}`" for s in sources))
        errors = external_summary.get("errors", []) or []
        if errors:
            lines.append("")
            lines.append("**Ingestion errors:** " + "; ".join(str(e) for e in errors))
        lines.extend(["", "---", ""])

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

    report = "\n".join(lines)
    if redact:
        from redeye.redaction import redact_secrets

        report = redact_secrets(report)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(report, encoding="utf-8")
