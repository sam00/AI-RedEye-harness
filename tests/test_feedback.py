"""Feedback store + collect-feedback tests."""

from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path

from redeye.commands.collect_feedback import _parse
from redeye.feedback.store import FindingsStore
from redeye.schema import Finding, Location, RunManifest, Severity


def test_collect_feedback_parses_marks() -> None:
    body = """
### RedEye

Some preamble.

<!-- vuln-id: F-0001 scan-id: abc--2026-01-01T00:00:00 -->
- [x] :white_check_mark: True Positive
- [ ] :x: False Positive

**ID**: `F-0001`
... details ...

<!-- vuln-id: F-0002 scan-id: abc--2026-01-01T00:00:00 -->
- [ ] :white_check_mark: True Positive
- [x] :x: False Positive

**ID**: `F-0002`
"""
    marks = _parse(body)
    assert ("abc--2026-01-01T00:00:00", "F-0001", "TP") in marks
    assert ("abc--2026-01-01T00:00:00", "F-0002", "FP") in marks


def test_findings_store_roundtrip(tmp_path: Path) -> None:
    db = FindingsStore(tmp_path / "scans.db")

    finding = Finding(
        id="F-0001",
        title="SQLi in user lookup",
        severity=Severity.HIGH,
        cwe="CWE-89",
        cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N",
        cvss_score=8.6,
        description="x",
        locations=[Location(path="src/api/users.py", start_line=42)],
        attack_chain=["a", "b"],
        remediation="parameterise",
        confidence=0.7,
        skill="language",
    )
    manifest = RunManifest(
        version="0.2.0",
        started_at=datetime(2026, 1, 1, tzinfo=timezone.utc),
        ended_at=datetime(2026, 1, 1, 0, 1, 0, tzinfo=timezone.utc),
        profile="mock",
        config_hash="deadbeef",
        target_repo="/tmp/repo",
        target_sha="abc123",
        application_id="APP-1",
        finding_count=1,
        dropped_count=0,
        total_cost_usd=0.0,
    )

    scan_id = db.record_scan(repo="/tmp/repo", manifest=manifest, findings=[finding])
    assert scan_id

    db.record_reviewer_verdict(scan_id=scan_id, finding_id="F-0001", verdict="TP")
    feedback = db.load_feedback(repo="/tmp/repo")
    assert len(feedback) == 1
    assert feedback[0]["verdict"] == "TP"
    assert feedback[0]["cwe"] == "CWE-89"
