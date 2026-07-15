"""SARIF 2.1.0 emitter.

We construct a minimum-viable SARIF document that any modern SARIF consumer
(GitHub Code Scanning, Azure DevOps, JFrog, Defect Dojo) can read. The only
non-obvious choice is mapping severities -- we use ``level`` for SARIF's
fixed vocabulary (none/note/warning/error) and emit a numeric
``security-severity`` property bag value so downstream filters work.
"""

from __future__ import annotations

import json
from pathlib import Path

from redeye import __version__
from redeye.schema import Finding, Severity

_SARIF_VERSION = "2.1.0"
_SCHEMA_URL = "https://json.schemastore.org/sarif-2.1.0.json"


def _level_for(severity: Severity) -> str:
    """SARIF only has 4 levels; map our 5-level scale onto them."""
    return {
        Severity.CRITICAL: "error",
        Severity.HIGH: "error",
        Severity.MEDIUM: "warning",
        Severity.LOW: "note",
        Severity.INFO: "none",
    }[severity]


def _security_severity(severity: Severity) -> str:
    """Numeric severity used by GitHub Code Scanning's UI."""
    return {
        Severity.CRITICAL: "9.5",
        Severity.HIGH: "8.0",
        Severity.MEDIUM: "5.5",
        Severity.LOW: "3.0",
        Severity.INFO: "0.5",
    }[severity]


def _rule_id_for(finding: Finding) -> str:
    if finding.cwe:
        return finding.cwe.replace(" ", "")
    if finding.skill:
        return f"redeye.{finding.skill}"
    return "redeye.unknown"


def build_sarif_log(*, target: Path, findings: list[Finding]) -> dict:
    rules: dict[str, dict] = {}
    results: list[dict] = []

    for f in findings:
        rule_id = _rule_id_for(f)
        rules.setdefault(
            rule_id,
            {
                "id": rule_id,
                "name": rule_id,
                "shortDescription": {"text": f.title},
                "fullDescription": {"text": f.description[:1000]},
                "helpUri": (
                    f"https://cwe.mitre.org/data/definitions/{f.cwe.replace('CWE-', '')}.html"
                    if f.cwe and f.cwe.startswith("CWE-")
                    else "https://github.com/sam00/AI-RedEye-harness"
                ),
                "properties": {
                    "tags": ["security", *f.tags],
                    "security-severity": _security_severity(f.severity),
                },
            },
        )

        result_locations = []
        for loc in f.locations:
            region: dict = {"startLine": loc.start_line}
            if loc.end_line:
                region["endLine"] = loc.end_line
            if loc.snippet:
                region["snippet"] = {"text": loc.snippet[:1500]}
            result_locations.append(
                {
                    "physicalLocation": {
                        "artifactLocation": {
                            "uri": loc.path,
                            "uriBaseId": "%SRCROOT%",
                        },
                        "region": region,
                    }
                }
            )

        properties: dict = {
            "confidence": f.confidence,
            "skill": f.skill,
            "stage": f.stage,
            "tags": f.tags,
            "remediation": f.remediation,
            "attack_chain": f.attack_chain,
            "grounded": f.grounded,
        }
        if f.cvss_vector:
            properties["cvss_v3.1_vector"] = f.cvss_vector
        if f.cvss_score is not None:
            # Override the rule-level severity with the per-finding CVSS so
            # GitHub Code Scanning / Defect Dojo display the right number.
            properties["security-severity"] = f"{f.cvss_score:.1f}"
        if f.validator_verdict:
            properties["validator_verdict"] = f.validator_verdict
        if f.validator_rationale:
            properties["validator_rationale"] = f.validator_rationale
        # Taint flow as nested properties (codeFlows would be richer, but
        # several SARIF consumers don't render them; properties travel everywhere).
        if f.taint and (f.taint.source or f.taint.sink):
            properties["taint"] = {
                "source": f.taint.source,
                "sink": f.taint.sink,
                "sanitizer_missing": f.taint.sanitizer_missing,
                "sanitizers_observed": f.taint.sanitizers_observed,
                "path": [
                    {"path": s.path, "start_line": s.start_line, "end_line": s.end_line}
                    for s in f.taint.taint_path
                ],
            }
        if f.evidence:
            properties["evidence"] = [
                {"kind": e.kind, "check": e.check, "detail": e.detail} for e in f.evidence
            ]
        if f.poc is not None:
            properties["poc"] = {
                "is_concrete": f.poc.is_concrete,
                "payload": f.poc.payload[:1500],
                "invocation": f.poc.invocation[:1500],
                "expected_effect": f.poc.expected_effect,
            }
        # Outcome verification (S8c) + corroboration/calibration, so SARIF
        # consumers can filter/sort on the deterministic verdict too.
        if f.verification is not None:
            properties["verification"] = {
                "verified": f.verification.verified,
                "score": f.verification.score,
                "signals": f.verification.signals,
                "threshold": f.verification.threshold,
                "method": f.verification.method,
            }
        if f.has_external_corroboration():
            properties["externally_corroborated"] = True
            if f.corroborating_tools:
                properties["corroborating_tools"] = f.corroborating_tools
        if f.calibrated_confidence is not None:
            properties["calibrated_confidence"] = f.calibrated_confidence
        if f.abstained:
            properties["abstained"] = True

        # Build a SARIF codeFlow if we have at least source -> sink locations.
        # codeFlows let GitHub render a taint-trace inline.
        code_flows = []
        if f.taint and f.taint.taint_path:
            thread_locations = []
            for step in f.taint.taint_path:
                thread_locations.append(
                    {
                        "location": {
                            "physicalLocation": {
                                "artifactLocation": {"uri": step.path, "uriBaseId": "%SRCROOT%"},
                                "region": {"startLine": step.start_line},
                            }
                        }
                    }
                )
            if thread_locations:
                code_flows = [{"threadFlows": [{"locations": thread_locations}]}]

        result = {
            "ruleId": rule_id,
            "level": _level_for(f.severity),
            "message": {"text": f.title},
            "locations": result_locations,
            "properties": properties,
            "fingerprints": {"redeye/v1": f.id},
        }
        if code_flows:
            result["codeFlows"] = code_flows
        results.append(result)

    return {
        "$schema": _SCHEMA_URL,
        "version": _SARIF_VERSION,
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "redeye",
                        "version": __version__,
                        "informationUri": "https://github.com/sam00/AI-RedEye-harness",
                        "rules": list(rules.values()),
                    }
                },
                "originalUriBaseIds": {"%SRCROOT%": {"uri": str(target.as_uri())}},
                "results": results,
            }
        ],
    }


def write_sarif(*, path: Path, target: Path, findings: list[Finding]) -> None:
    log = build_sarif_log(target=target, findings=findings)
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8") as fh:
        json.dump(log, fh, indent=2)
