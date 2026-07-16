"""GitHub PR comment writer.

Emits a Markdown file shaped like a typical PR security-scan comment:
- compact severity table at the top,
- one section per finding with TP / FP checkboxes,
- ``<!-- vuln-id: ... -->`` HTML comments so the feedback collector can
  reliably map a checked box back to a stored finding.

The actual comment-posting (``gh pr comment``) is delegated to the GitHub
Actions workflow -- this module just produces the Markdown.
"""

from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path

from redeye.schema import Finding, RunManifest, Severity

_SEV_ICON = {
    Severity.CRITICAL: ":rotating_light: Critical",
    Severity.HIGH: ":fire: High",
    Severity.MEDIUM: ":warning: Medium",
    Severity.LOW: ":information_source: Low",
    Severity.INFO: ":pushpin: Info",
}


def _summary_table(findings: list[Finding]) -> str:
    bucket: dict[Severity, int] = {s: 0 for s in Severity}
    for f in findings:
        bucket[f.severity] += 1
    rows = ["| Severity | Count |", "|---|---|"]
    for sev in (Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM, Severity.LOW, Severity.INFO):
        if bucket[sev] == 0:
            continue
        rows.append(f"| {_SEV_ICON[sev]} | {bucket[sev]} |")
    if len(rows) == 2:
        rows.append("| (no findings) | 0 |")
    return "\n".join(rows)


def _render_one(f: Finding, scan_id: str) -> list[str]:
    primary = f.locations[0] if f.locations else None
    loc = f"{primary.path}:{primary.start_line}" if primary else "unknown"
    cvss_line = (
        f"**CVSS Vector:** `{f.cvss_vector}`"
        if f.cvss_vector
        else "**CVSS Vector:** _not provided_"
    )
    score_line = f"**CVSS Score:** {f.cvss_score:.1f}" if f.cvss_score is not None else ""
    parts = [
        f"<!-- vuln-id: {f.id} scan-id: {scan_id} -->",
        "- [ ] :white_check_mark: True Positive",
        "- [ ] :x: False Positive",
        "",
        f"**ID**: `{f.id}`  ",
        f"**Severity**: {_SEV_ICON.get(f.severity, f.severity.value)}  ",
        f"**CWE**: {f.cwe or 'unknown'}  ",
        f"**Issue**: {f.title}  ",
        f"**Location**: `{loc}`  ",
        cvss_line + ("  " if cvss_line else ""),
    ]
    if score_line:
        parts.append(score_line + "  ")
    if f.validator_verdict:
        parts.append(
            f"**Validator**: `{f.validator_verdict}` -- {(f.validator_rationale or '')[:160]}  "
        )
    parts.extend(
        [
            "",
            "<details><summary>Click to see risk, attack chain, and remediation</summary>",
            "",
            "**Risk:**",
            "",
            f.description.strip() or "_no description_",
            "",
            "**Attack chain:**",
            "",
            "\n".join(f"  {i + 1}. {step}" for i, step in enumerate(f.attack_chain))
            or "_(none provided)_",
            "",
            "**Remediation:**",
            "",
            f.remediation.strip() or "_no remediation given_",
            "",
            "</details>",
            "",
            "---",
            "",
        ]
    )
    return parts


def write_pr_comment(
    *,
    path: Path,
    target: Path,
    application_id: str | None,
    findings: list[Finding],
    manifest: RunManifest,
) -> None:
    scan_id = f"{manifest.target_sha or 'no-sha'}--{manifest.started_at.isoformat()}"
    now = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")

    lines: list[str] = [
        "### :robot: RedEye security scan",
        "",
        f"**{len(findings)}** finding(s) reported on `{target}`"
        + (f" (AppId `{application_id}`)" if application_id else ""),
        "",
        f"_Generated {now} -- profile `{manifest.profile}` -- target SHA `{manifest.target_sha or 'unknown'}`_",
        "",
        "> :bulb: **Help us improve!** Tick one box below each finding (True Positive / False Positive). "
        "Saved feedback is fed into the next scan as context to reduce repeat false positives.",
        "",
        _summary_table(findings),
        "",
        "---",
        "",
    ]
    if not findings:
        lines.append("_No findings to review._")
    else:
        for f in findings:
            lines.extend(_render_one(f, scan_id))

    # The comment is posted verbatim to the PR thread -- mask secret material
    # (descriptions/remediations can quote credentials from the scanned code).
    from redeye.redaction import redact_secrets

    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(redact_secrets("\n".join(lines)), encoding="utf-8")
