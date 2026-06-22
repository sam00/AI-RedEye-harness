"""PR comment writer test."""

from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path

from redeye.output.pr_comment import write_pr_comment
from redeye.schema import Finding, Location, RunManifest, Severity


def test_pr_comment_renders(tmp_path: Path) -> None:
    finding = Finding(
        id="F-0001",
        title="SQL injection in user lookup",
        severity=Severity.HIGH,
        cwe="CWE-89",
        cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N",
        cvss_score=8.6,
        description="The lookup concatenates the request-supplied username into a raw SQL string.",
        locations=[Location(path="src/api/users.py", start_line=42, end_line=48)],
        attack_chain=["POST /api/lookup", "raw SQL", "DB executes"],
        remediation="Use SQLAlchemy text() with bindparams.",
        confidence=0.85,
    )
    manifest = RunManifest(
        version="0.2.0",
        started_at=datetime(2026, 1, 1, tzinfo=timezone.utc),
        ended_at=datetime(2026, 1, 1, 0, 1, tzinfo=timezone.utc),
        profile="mock",
        config_hash="0",
        target_repo="/tmp/repo",
        target_sha="abc123",
        finding_count=1,
        dropped_count=0,
    )

    out = tmp_path / "comment.md"
    write_pr_comment(
        path=out,
        target=Path("/tmp/repo"),
        application_id="APP-1",
        findings=[finding],
        manifest=manifest,
    )

    content = out.read_text(encoding="utf-8")
    assert "RedEye" in content
    assert "<!-- vuln-id: F-0001" in content
    assert "True Positive" in content
    assert "False Positive" in content
    assert "CWE-89" in content
    assert "CVSS:3.1/AV:N" in content
