"""Tests for external-scanner corroboration (improvement #2)."""

from __future__ import annotations

from dataclasses import dataclass

from redeye.corroboration import annotate_findings, match_one
from redeye.schema import Finding, Location, Severity


@dataclass
class _Ext:
    path: str
    start_line: int
    cwe: str | None
    tool: str = "semgrep"
    rule_id: str = "sql-injection"


def _finding(path="app/users.py", line=42, cwe="CWE-89") -> Finding:
    return Finding(
        id="F-1",
        title="t",
        severity=Severity.HIGH,
        description="d",
        cwe=cwe,
        locations=[Location(path=path, start_line=line)],
    )


def test_match_basename_and_proximity():
    exts = [_Ext("src/app/users.py", 44, "CWE-89")]
    hit = match_one(path="app/users.py", line=42, cwe="CWE-89", externals=exts)
    assert hit is not None and hit.tool == "semgrep" and hit.line_delta == 2


def test_cwe_mismatch_not_corroboration():
    exts = [_Ext("app/users.py", 42, "CWE-89")]
    assert match_one(path="app/users.py", line=42, cwe="CWE-78", externals=exts) is None


def test_far_line_not_corroboration():
    exts = [_Ext("app/users.py", 99, "CWE-89")]
    assert match_one(path="app/users.py", line=42, cwe="CWE-89", externals=exts) is None


def test_annotate_findings_sets_signal():
    findings = [_finding()]
    exts = [_Ext("app/users.py", 43, "CWE-89", tool="codeql")]
    n = annotate_findings(findings, exts)
    assert n == 1
    f = findings[0]
    assert f.externally_corroborated is True
    assert "codeql" in f.corroborating_tools
    assert f.has_external_corroboration() is True
    assert any(e.kind == "external_corroboration" and e.check == "pass" for e in f.evidence)


def test_annotate_no_externals_is_noop():
    findings = [_finding()]
    assert annotate_findings(findings, []) == 0
    assert findings[0].externally_corroborated is False
