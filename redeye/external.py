"""Ingest external scanner output and fold it into the structural map.

RedEye's own scanning is grounding-first: deterministic structural indexing
(S1b) plus LLM research lenses (S4). But teams usually already run other
scanners (Semgrep, CodeQL, Bandit, Trivy, generic SARIF emitters). Rather
than ignore that signal, this module normalises external findings into a
common shape and folds their *locations* into the structural inventory as
extra ``sink`` hits, so the lenses and threat model can reason about them as
real, already-flagged hotspots.

Crucially, this is **mapping enrichment, not blind trust**: an external
finding becomes a structural hit (a candidate location), and still has to
survive grounding (S4b), voting (S6) and outcome verification (S8c) like any
other candidate. We never promote an external finding straight to the report.

Supported input formats (auto-detected by content):

- **SARIF 2.1.0** -- ``{"version": "2.1.0", "runs": [...]}`` (CodeQL, many tools).
- **Semgrep JSON** -- ``{"results": [{"path", "start": {"line"}, "check_id", ...}]}``.
- **Generic JSON** -- a list of records, or ``{"findings": [...]}`` /
  ``{"results": [...]}``, each with path + line + (rule / message / severity / cwe).
"""

from __future__ import annotations

import json
import logging
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

log = logging.getLogger(__name__)

# Map common external severity vocabularies onto a coarse RedEye-ish scale.
_SEVERITY_ALIASES = {
    "error": "high",
    "warning": "medium",
    "warn": "medium",
    "note": "low",
    "info": "informational",
    "informational": "informational",
    "critical": "critical",
    "high": "high",
    "medium": "medium",
    "moderate": "medium",
    "low": "low",
}


@dataclass
class ExternalFinding:
    """One normalised finding imported from a third-party scanner."""

    tool: str
    rule_id: str
    message: str
    path: str
    start_line: int
    end_line: int | None = None
    severity: str = ""
    cwe: str | None = None

    def to_dict(self) -> dict[str, Any]:
        d: dict[str, Any] = {
            "tool": self.tool,
            "rule_id": self.rule_id,
            "message": self.message[:300],
            "path": self.path,
            "line": self.start_line,
            "severity": self.severity,
        }
        if self.cwe:
            d["cwe"] = self.cwe
        return d


@dataclass
class ExternalReport:
    """The aggregate of all external scanner files loaded for one scan."""

    findings: list[ExternalFinding] = field(default_factory=list)
    sources: list[str] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)

    @property
    def is_empty(self) -> bool:
        return not self.findings

    def summary(self) -> dict[str, Any]:
        by_tool: dict[str, int] = {}
        for f in self.findings:
            by_tool[f.tool] = by_tool.get(f.tool, 0) + 1
        return {
            "count": len(self.findings),
            "by_tool": by_tool,
            "sources": list(self.sources),
            "errors": list(self.errors),
        }


def _norm_severity(value: str | None) -> str:
    if not value:
        return ""
    return _SEVERITY_ALIASES.get(str(value).strip().lower(), str(value).strip().lower())


def _norm_path(raw: str) -> str:
    raw = (raw or "").strip()
    for prefix in ("file://", "./"):
        if raw.startswith(prefix):
            raw = raw[len(prefix) :]
    return raw.replace("\\", "/")


def _cwe_from_tags(tags: Any) -> str | None:
    """Pull a CWE id out of a SARIF/Semgrep tag or metadata blob."""
    if isinstance(tags, dict):
        tags = tags.get("cwe") or tags.get("cwe_id") or list(tags.values())
    if isinstance(tags, str):
        tags = [tags]
    if isinstance(tags, list):
        for t in tags:
            text = str(t).upper()
            if "CWE-" in text:
                # Normalise e.g. "external/cwe/cwe-089" -> "CWE-89".
                frag = text.split("CWE-", 1)[1]
                digits = "".join(ch for ch in frag if ch.isdigit())
                if digits:
                    return f"CWE-{int(digits)}"
    return None


def _sarif_physical(loc: dict) -> tuple[str | None, dict, str]:
    """Return (uri, region, snippet_text) from a SARIF location object."""
    phys = loc.get("physicalLocation") or {}
    art = phys.get("artifactLocation") or {}
    region = phys.get("region") or {}
    uri = art.get("uri")
    snippet = ""
    snip = region.get("snippet") or {}
    if isinstance(snip, dict):
        snippet = str(snip.get("text") or "")
    if not snippet:
        ctx = phys.get("contextRegion") or {}
        csnip = ctx.get("snippet") or {}
        if isinstance(csnip, dict):
            snippet = str(csnip.get("text") or "")
    return (uri, region, snippet)


def _result_is_suppressed(result: dict) -> bool:
    """Honour SARIF suppressions and baselineState=absent (don't import)."""
    suppressions = result.get("suppressions")
    if isinstance(suppressions, list) and len(suppressions) > 0:
        return True
    if result.get("baselineState") == "absent":
        return True
    return False


def _parse_sarif(data: dict, tool_default: str) -> list[ExternalFinding]:
    out: list[ExternalFinding] = []
    for run in data.get("runs", []) or []:
        tool_obj = run.get("tool") or {}
        driver = tool_obj.get("driver") or {}
        tool = driver.get("name") or tool_default
        # Rules can live on the driver and on extensions (CodeQL packs). Build
        # both an id->cwe map and an ordered list for ``ruleIndex`` lookups.
        rule_cwe: dict[str, str | None] = {}
        rules_ordered: list[dict] = []
        rule_components = [driver, *(tool_obj.get("extensions") or [])]
        for comp in rule_components:
            for rule in (comp or {}).get("rules", []) or []:
                rid = rule.get("id")
                rules_ordered.append(rule)
                if not rid:
                    continue
                props = rule.get("properties") or {}
                cwe = _cwe_from_tags(props.get("tags") or props.get("cwe"))
                if cwe is None:
                    cwe = _cwe_from_relationships(rule.get("relationships"))
                rule_cwe[rid] = cwe
        for result in run.get("results", []) or []:
            if _result_is_suppressed(result):
                continue
            rule_obj = result.get("rule") or {}
            rule_id = result.get("ruleId") or rule_obj.get("id")
            # Resolve via ruleIndex / rule.index when ruleId is absent.
            if not rule_id:
                idx = result.get("ruleIndex")
                if idx is None:
                    idx = rule_obj.get("index")
                if isinstance(idx, int) and 0 <= idx < len(rules_ordered):
                    rule_id = rules_ordered[idx].get("id")
            rule_id = rule_id or "unknown"
            message = ((result.get("message") or {}).get("text")) or ""
            level = result.get("level") or _level_from_rule(rules_ordered, rule_id)
            cwe = rule_cwe.get(str(rule_id)) or _cwe_from_tags(
                (result.get("properties") or {}).get("tags")
            )
            locations = result.get("locations") or []
            # Fall back to relatedLocations when there's no primary location.
            if not locations:
                locations = result.get("relatedLocations") or []
            for loc in locations:
                uri, region, snippet = _sarif_physical(loc)
                if not uri:
                    continue
                out.append(
                    ExternalFinding(
                        tool=tool,
                        rule_id=str(rule_id),
                        message=str(message or snippet),
                        path=_norm_path(uri),
                        start_line=int(region.get("startLine", 1) or 1),
                        end_line=int(region["endLine"]) if region.get("endLine") else None,
                        severity=_norm_severity(level),
                        cwe=cwe,
                    )
                )
    return out


def _level_from_rule(rules_ordered: list[dict], rule_id: str) -> str:
    """Derive a level from a rule's defaultConfiguration when the result omits one."""
    for rule in rules_ordered:
        if rule.get("id") == rule_id:
            cfg = rule.get("defaultConfiguration") or {}
            return str(cfg.get("level") or "")
    return ""


def _cwe_from_relationships(relationships: Any) -> str | None:
    """CodeQL encodes CWE links in result/rule ``relationships`` -> taxa ids."""
    if not isinstance(relationships, list):
        return None
    for rel in relationships:
        target = (rel or {}).get("target") or {}
        ident = target.get("id") or ""
        cwe = _cwe_from_tags(str(ident))
        if cwe:
            return cwe
    return None


def _parse_semgrep(data: dict) -> list[ExternalFinding]:
    out: list[ExternalFinding] = []
    for r in data.get("results", []) or []:
        if not isinstance(r, dict) or "check_id" not in r:
            return []  # not actually semgrep; let the generic parser try
        extra = r.get("extra") or {}
        meta = extra.get("metadata") or {}
        out.append(
            ExternalFinding(
                tool="semgrep",
                rule_id=str(r.get("check_id", "unknown")),
                message=str(extra.get("message", "")),
                path=_norm_path(str(r.get("path", ""))),
                start_line=int((r.get("start") or {}).get("line", 1) or 1),
                end_line=int((r.get("end") or {}).get("line")) if (r.get("end") or {}).get("line") else None,
                severity=_norm_severity(extra.get("severity")),
                cwe=_cwe_from_tags(meta.get("cwe")),
            )
        )
    return out


def _parse_generic(rows: list, tool_default: str) -> list[ExternalFinding]:
    out: list[ExternalFinding] = []
    for r in rows:
        if not isinstance(r, dict):
            continue
        path = (
            r.get("path")
            or r.get("file")
            or r.get("filename")
            or r.get("File")
            or r.get("location")
        )
        if not path:
            continue
        line = (
            r.get("line")
            or r.get("start_line")
            or r.get("lineno")
            or r.get("line_number")
            or r.get("StartLine")
            or 1
        )
        out.append(
            ExternalFinding(
                tool=str(r.get("tool") or tool_default),
                rule_id=str(
                    r.get("rule_id") or r.get("rule") or r.get("check_id") or r.get("id") or "unknown"
                ),
                message=str(r.get("message") or r.get("description") or r.get("title") or ""),
                path=_norm_path(str(path)),
                start_line=int(line or 1),
                end_line=int(r["end_line"]) if r.get("end_line") else None,
                severity=_norm_severity(r.get("severity")),
                cwe=_cwe_from_tags(r.get("cwe") or r.get("cwe_id")),
            )
        )
    return out


def _parse_bandit(data: dict) -> list[ExternalFinding]:
    """Bandit JSON: ``{"results": [{"filename","line_number","test_id",...}]}``."""
    out: list[ExternalFinding] = []
    for r in data.get("results", []) or []:
        if not isinstance(r, dict) or "filename" not in r:
            return []
        cwe_obj = r.get("issue_cwe") or {}
        cwe = None
        if isinstance(cwe_obj, dict) and cwe_obj.get("id"):
            cwe = f"CWE-{int(str(cwe_obj['id']).split('-')[-1])}"
        out.append(
            ExternalFinding(
                tool="bandit",
                rule_id=str(r.get("test_id") or r.get("test_name") or "unknown"),
                message=str(r.get("issue_text", "")),
                path=_norm_path(str(r.get("filename", ""))),
                start_line=int(r.get("line_number", 1) or 1),
                severity=_norm_severity(r.get("issue_severity")),
                cwe=cwe,
            )
        )
    return out


def _parse_gitleaks(rows: list) -> list[ExternalFinding]:
    """Gitleaks JSON: a list of ``{"RuleID","File","StartLine","Description",...}``."""
    out: list[ExternalFinding] = []
    for r in rows:
        if not isinstance(r, dict) or not (r.get("RuleID") or r.get("File")):
            return []
        out.append(
            ExternalFinding(
                tool="gitleaks",
                rule_id=str(r.get("RuleID") or "secret"),
                message=str(r.get("Description") or "hardcoded secret"),
                path=_norm_path(str(r.get("File", ""))),
                start_line=int(r.get("StartLine", 1) or 1),
                end_line=int(r["EndLine"]) if r.get("EndLine") else None,
                severity="high",
                cwe="CWE-798",
            )
        )
    return out


def _parse_trivy(data: dict) -> list[ExternalFinding]:
    """Trivy JSON: ``{"Results": [{"Target", "Vulnerabilities"|"Misconfigurations"|"Secrets"}]}``."""
    out: list[ExternalFinding] = []
    for res in data.get("Results", []) or []:
        target = _norm_path(str(res.get("Target", "")))
        for v in res.get("Vulnerabilities", []) or []:
            out.append(
                ExternalFinding(
                    tool="trivy",
                    rule_id=str(v.get("VulnerabilityID", "unknown")),
                    message=str(v.get("Title") or v.get("Description") or "")[:300],
                    path=target or str(v.get("PkgName", "")),
                    start_line=1,
                    severity=_norm_severity(v.get("Severity")),
                    cwe=_cwe_from_tags(v.get("CweIDs")),
                )
            )
        for m in res.get("Misconfigurations", []) or []:
            cause = m.get("CauseMetadata") or {}
            out.append(
                ExternalFinding(
                    tool="trivy",
                    rule_id=str(m.get("ID", "unknown")),
                    message=str(m.get("Title") or m.get("Message") or "")[:300],
                    path=target,
                    start_line=int(cause.get("StartLine", 1) or 1),
                    severity=_norm_severity(m.get("Severity")),
                )
            )
        for s in res.get("Secrets", []) or []:
            out.append(
                ExternalFinding(
                    tool="trivy",
                    rule_id=str(s.get("RuleID", "secret")),
                    message=str(s.get("Title", "hardcoded secret"))[:300],
                    path=target,
                    start_line=int(s.get("StartLine", 1) or 1),
                    severity=_norm_severity(s.get("Severity")),
                    cwe="CWE-798",
                )
            )
    return out


def _parse_grype(data: dict) -> list[ExternalFinding]:
    """Grype JSON: ``{"matches": [{"vulnerability","artifact":{"locations":[{"path"}]}}]}``."""
    out: list[ExternalFinding] = []
    for m in data.get("matches", []) or []:
        vuln = m.get("vulnerability") or {}
        artifact = m.get("artifact") or {}
        locations = artifact.get("locations") or []
        path = ""
        if locations and isinstance(locations[0], dict):
            path = _norm_path(str(locations[0].get("path", "")))
        out.append(
            ExternalFinding(
                tool="grype",
                rule_id=str(vuln.get("id", "unknown")),
                message=str(vuln.get("description") or artifact.get("name") or "")[:300],
                path=path or str(artifact.get("name", "")),
                start_line=1,
                severity=_norm_severity(vuln.get("severity")),
            )
        )
    return out


def load_external_file(path: Path) -> list[ExternalFinding]:
    """Parse a single external scanner file into normalised findings.

    Format is auto-detected by content. Supported: SARIF 2.1.0, Semgrep JSON,
    Trivy, Bandit, Gitleaks, Grype, and a permissive generic JSON shape.
    """
    text = path.read_text(encoding="utf-8", errors="replace")
    data = json.loads(text)
    tool_default = path.stem

    if isinstance(data, dict):
        if data.get("version") and data.get("runs") is not None:
            return _parse_sarif(data, tool_default)
        # Trivy: capital "Results" and/or SchemaVersion.
        if isinstance(data.get("Results"), list) or "SchemaVersion" in data:
            trivy = _parse_trivy(data)
            if trivy:
                return trivy
        # Grype: top-level "matches".
        if isinstance(data.get("matches"), list):
            return _parse_grype(data)
        if isinstance(data.get("results"), list):
            # results[] is shared by Semgrep and Bandit; try each, then generic.
            for parser in (_parse_semgrep, _parse_bandit):
                parsed = parser(data)
                if parsed:
                    return parsed
            return _parse_generic(data["results"], tool_default)
        if isinstance(data.get("findings"), list):
            return _parse_generic(data["findings"], tool_default)
    if isinstance(data, list):
        # Gitleaks emits a bare list of capitalised records; try it first.
        gitleaks = _parse_gitleaks(data)
        if gitleaks:
            return gitleaks
        return _parse_generic(data, tool_default)
    return []


def load_external_reports(paths: list[str | Path]) -> ExternalReport:
    """Load and normalise every external scanner file. Errors are recorded,
    never raised, so a malformed feed can't abort a scan."""
    report = ExternalReport()
    for raw in paths:
        p = Path(raw)
        if not p.is_file():
            report.errors.append(f"not found: {p}")
            continue
        try:
            findings = load_external_file(p)
        except (json.JSONDecodeError, OSError, ValueError, TypeError) as exc:
            report.errors.append(f"{p}: {exc}")
            log.warning("external: failed to parse %s: %s", p, exc)
            continue
        report.findings.extend(findings)
        report.sources.append(str(p))
        log.info("external: loaded %d finding(s) from %s", len(findings), p)
    return report
