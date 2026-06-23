"""Baseline-file tests."""

from __future__ import annotations

from pathlib import Path

from redeye.baseline import Baseline, filter_findings, fingerprint
from redeye.schema import Finding, Location, Severity


def _f(idx: int, cwe: str = "CWE-89", path: str = "src/a.py", line: int = 1) -> Finding:
    return Finding(
        id=f"F-{idx:04d}",
        title=f"test {idx}",
        severity=Severity.HIGH,
        cwe=cwe,
        description="x",
        locations=[Location(path=path, start_line=line)],
        remediation="bind",
        skill="language",
    )


def test_fingerprint_is_stable_across_calls() -> None:
    fp1 = fingerprint(cwe="CWE-89", path="src/a.py", start_line=42, skill="language")
    fp2 = fingerprint(cwe="CWE-89", path="src/a.py", start_line=42, skill="language")
    assert fp1 == fp2
    assert len(fp1) == 16


def test_fingerprint_changes_with_inputs() -> None:
    fp_a = fingerprint(cwe="CWE-89", path="src/a.py", start_line=42, skill="language")
    fp_b = fingerprint(cwe="CWE-78", path="src/a.py", start_line=42, skill="language")
    assert fp_a != fp_b


def test_load_returns_empty_when_no_file(tmp_path: Path) -> None:
    b = Baseline.load(tmp_path)
    assert b.entries == {}


def test_accept_and_persist_roundtrip(tmp_path: Path) -> None:
    b = Baseline.load(tmp_path)
    entry = b.accept(
        cwe="CWE-89", path="src/a.py", start_line=10, skill="language", rationale="reviewed"
    )
    b.save()

    # New instance should re-load from disk.
    b2 = Baseline.load(tmp_path)
    assert entry.fingerprint in b2.entries
    assert b2.entries[entry.fingerprint].rationale == "reviewed"


def test_filter_findings_drops_accepted(tmp_path: Path) -> None:
    b = Baseline.load(tmp_path)
    b.accept(cwe="CWE-89", path="src/a.py", start_line=1, skill="language")
    findings = [_f(1), _f(2, path="src/b.py")]
    kept, filtered = filter_findings(findings, b)
    assert len(kept) == 1
    assert len(filtered) == 1
    assert filtered[0].id == "F-0001"
    assert "baseline:accepted" in filtered[0].tags


def test_remove_clears_entry(tmp_path: Path) -> None:
    b = Baseline.load(tmp_path)
    e = b.accept(cwe="CWE-89", path="src/a.py", start_line=1, skill="language")
    assert b.remove(e.fingerprint) is True
    assert e.fingerprint not in b.entries
    assert b.remove("notarealfingerprint") is False
