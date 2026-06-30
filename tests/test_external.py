"""External scanner ingestion tests (SARIF / Semgrep / generic JSON)."""

from __future__ import annotations

import json
from pathlib import Path

from redeye.external import load_external_reports
from redeye.structural import StructuralIndex, merge_external_findings


def _write(p: Path, obj: dict | list) -> Path:
    p.write_text(json.dumps(obj), encoding="utf-8")
    return p


def test_sarif_ingestion(tmp_path: Path) -> None:
    sarif = {
        "version": "2.1.0",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "CodeQL",
                        "rules": [
                            {
                                "id": "py/sql-injection",
                                "properties": {"tags": ["external/cwe/cwe-089"]},
                            }
                        ],
                    }
                },
                "results": [
                    {
                        "ruleId": "py/sql-injection",
                        "level": "error",
                        "message": {"text": "SQL injection"},
                        "locations": [
                            {
                                "physicalLocation": {
                                    "artifactLocation": {"uri": "app/users.py"},
                                    "region": {"startLine": 42},
                                }
                            }
                        ],
                    }
                ],
            }
        ],
    }
    f = _write(tmp_path / "codeql.sarif", sarif)
    report = load_external_reports([f])
    assert len(report.findings) == 1
    finding = report.findings[0]
    assert finding.tool == "CodeQL"
    assert finding.path == "app/users.py"
    assert finding.start_line == 42
    assert finding.cwe == "CWE-89"
    assert finding.severity == "high"


def test_semgrep_ingestion(tmp_path: Path) -> None:
    semgrep = {
        "results": [
            {
                "check_id": "python.lang.security.audit.dangerous-exec",
                "path": "svc/run.py",
                "start": {"line": 10},
                "end": {"line": 10},
                "extra": {
                    "message": "exec is dangerous",
                    "severity": "ERROR",
                    "metadata": {"cwe": ["CWE-95: Eval Injection"]},
                },
            }
        ]
    }
    f = _write(tmp_path / "semgrep.json", semgrep)
    report = load_external_reports([f])
    assert len(report.findings) == 1
    assert report.findings[0].tool == "semgrep"
    assert report.findings[0].path == "svc/run.py"
    assert report.findings[0].cwe == "CWE-95"


def test_generic_json_list(tmp_path: Path) -> None:
    rows = [
        {"path": "a/b.py", "line": 3, "rule": "hardcoded-secret", "severity": "high"},
        {"file": "c/d.js", "start_line": 8, "message": "xss"},
    ]
    f = _write(tmp_path / "generic.json", rows)
    report = load_external_reports([f])
    assert len(report.findings) == 2
    assert report.findings[0].path == "a/b.py"
    assert report.findings[1].path == "c/d.js"
    assert report.findings[1].start_line == 8


def test_malformed_file_is_recorded_not_raised(tmp_path: Path) -> None:
    bad = tmp_path / "bad.json"
    bad.write_text("{not json", encoding="utf-8")
    report = load_external_reports([bad, tmp_path / "missing.sarif"])
    assert report.is_empty
    assert len(report.errors) == 2


def test_sarif_codeql_ruleindex_relationships_snippet(tmp_path: Path) -> None:
    """CodeQL-shaped SARIF: ruleIndex resolution, CWE via relationships,
    region.snippet fallback, and suppression handling."""
    sarif = {
        "version": "2.1.0",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "CodeQL",
                        "rules": [
                            {
                                "id": "py/path-injection",
                                "relationships": [{"target": {"id": "CWE-022"}}],
                            },
                        ],
                    }
                },
                "results": [
                    {
                        "ruleIndex": 0,
                        "message": {"text": ""},
                        "locations": [
                            {
                                "physicalLocation": {
                                    "artifactLocation": {"uri": "app/files.py"},
                                    "region": {
                                        "startLine": 7,
                                        "snippet": {"text": "open(user_path)"},
                                    },
                                }
                            }
                        ],
                    },
                    {
                        "ruleId": "py/path-injection",
                        "message": {"text": "suppressed one"},
                        "suppressions": [{"kind": "external"}],
                        "locations": [
                            {
                                "physicalLocation": {
                                    "artifactLocation": {"uri": "app/other.py"},
                                    "region": {"startLine": 1},
                                }
                            }
                        ],
                    },
                ],
            }
        ],
    }
    f = _write(tmp_path / "codeql.sarif", sarif)
    report = load_external_reports([f])
    # Suppressed result dropped; one finding remains.
    assert len(report.findings) == 1
    hit = report.findings[0]
    assert hit.cwe == "CWE-22"
    assert hit.path == "app/files.py"
    assert hit.start_line == 7
    assert "open(user_path)" in hit.message  # snippet used as message fallback


def test_bandit_ingestion(tmp_path: Path) -> None:
    bandit = {
        "results": [
            {
                "filename": "svc/run.py",
                "line_number": 12,
                "test_id": "B602",
                "issue_text": "subprocess with shell=True",
                "issue_severity": "HIGH",
                "issue_cwe": {"id": 78},
            }
        ]
    }
    f = _write(tmp_path / "bandit.json", bandit)
    report = load_external_reports([f])
    assert len(report.findings) == 1
    assert report.findings[0].tool == "bandit"
    assert report.findings[0].cwe == "CWE-78"
    assert report.findings[0].start_line == 12


def test_gitleaks_ingestion(tmp_path: Path) -> None:
    gitleaks = [
        {"RuleID": "aws-key", "File": "conf/app.py", "StartLine": 4, "Description": "AWS key"}
    ]
    f = _write(tmp_path / "gitleaks.json", gitleaks)
    report = load_external_reports([f])
    assert len(report.findings) == 1
    assert report.findings[0].tool == "gitleaks"
    assert report.findings[0].cwe == "CWE-798"
    assert report.findings[0].path == "conf/app.py"


def test_trivy_ingestion(tmp_path: Path) -> None:
    trivy = {
        "SchemaVersion": 2,
        "Results": [
            {
                "Target": "Dockerfile",
                "Misconfigurations": [
                    {
                        "ID": "DS002",
                        "Title": "root user",
                        "Severity": "HIGH",
                        "CauseMetadata": {"StartLine": 3},
                    }
                ],
            }
        ],
    }
    f = _write(tmp_path / "trivy.json", trivy)
    report = load_external_reports([f])
    assert len(report.findings) == 1
    assert report.findings[0].tool == "trivy"
    assert report.findings[0].path == "Dockerfile"
    assert report.findings[0].start_line == 3


def test_grype_ingestion(tmp_path: Path) -> None:
    grype = {
        "matches": [
            {
                "vulnerability": {
                    "id": "CVE-2021-1234",
                    "severity": "Critical",
                    "description": "rce",
                },
                "artifact": {"name": "libfoo", "locations": [{"path": "requirements.txt"}]},
            }
        ]
    }
    f = _write(tmp_path / "grype.json", grype)
    report = load_external_reports([f])
    assert len(report.findings) == 1
    assert report.findings[0].tool == "grype"
    assert report.findings[0].path == "requirements.txt"
    assert report.findings[0].severity == "critical"


def test_merge_into_structural_index(tmp_path: Path) -> None:
    rows = [{"path": "app/x.py", "line": 5, "rule": "r1", "tool": "tool1", "cwe": "CWE-89"}]
    f = _write(tmp_path / "g.json", rows)
    report = load_external_reports([f])
    index = StructuralIndex()
    stats = merge_external_findings(index, report.findings)
    assert stats["added"] == 1
    assert len(index.sinks) == 1
    hit = index.sinks[0]
    assert hit.path == "app/x.py"
    assert hit.line == 5
    assert hit.pattern_id == "external_scanner"
    assert hit.cwe_hint == "CWE-89"


def test_merge_dedupes_against_native_sink(tmp_path: Path) -> None:
    from redeye.structural import StructuralHit

    index = StructuralIndex()
    index.sinks.append(
        StructuralHit("app/x.py", 5, "sql_execute_var", "sql_execute_var", "cursor.execute(q)")
    )
    rows = [{"path": "app/x.py", "line": 5, "rule": "py/sqli", "tool": "CodeQL", "cwe": "CWE-89"}]
    f = _write(tmp_path / "g.json", rows)
    report = load_external_reports([f])
    stats = merge_external_findings(index, report.findings)
    # No duplicate sink added; the native hit is corroborated instead.
    assert stats["added"] == 0
    assert stats["deduped"] == 1
    assert len(index.sinks) == 1
    assert "CodeQL:py/sqli" in index.sinks[0].corroborated_by


def test_merge_flags_reachable_when_source_colocated(tmp_path: Path) -> None:
    from redeye.structural import StructuralHit

    index = StructuralIndex()
    index.sources.append(StructuralHit("app/x.py", 2, "http_input", "source", "request.args"))
    rows = [{"path": "app/x.py", "line": 9, "rule": "r1", "tool": "t1", "cwe": "CWE-89"}]
    f = _write(tmp_path / "g.json", rows)
    report = load_external_reports([f])
    stats = merge_external_findings(index, report.findings)
    assert stats["added"] == 1
    assert stats["reachable"] == 1
    assert index.sinks[-1].reachable_from_source is True
