"""SQLite-backed findings store + feedback loop.

A small local-first store for scan findings and reviewer TP/FP marks.

Two tables:

- ``scans`` -- one row per scan, with profile, target SHA, totals.
- ``findings`` -- one row per finding, joined to ``scans`` via ``scan_id``.

Reviewer feedback (true positive / false positive marks) lands in the
``findings.reviewer_verdict`` column. The PR-comment writer parses
GitHub PR comments to extract these marks; here we just expose load/store.

A roadmap entry covers the Databricks variant.
"""

from __future__ import annotations

import json
import os
import sqlite3
from contextlib import closing
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

_SCHEMA = """
CREATE TABLE IF NOT EXISTS scans (
    scan_id TEXT PRIMARY KEY,
    repo TEXT NOT NULL,
    application_id TEXT,
    profile TEXT,
    config_hash TEXT,
    target_sha TEXT,
    started_at TEXT,
    ended_at TEXT,
    finding_count INTEGER,
    dropped_count INTEGER,
    total_cost_usd REAL,
    manifest_json TEXT
);

CREATE TABLE IF NOT EXISTS findings (
    finding_id TEXT NOT NULL,
    scan_id TEXT NOT NULL,
    repo TEXT NOT NULL,
    title TEXT,
    severity TEXT,
    cwe TEXT,
    cvss_vector TEXT,
    cvss_score REAL,
    path TEXT,
    start_line INTEGER,
    skill TEXT,
    confidence REAL,
    validator_verdict TEXT,
    reviewer_verdict TEXT,        -- TP/FP/UNK from PR comment
    reviewer_at TEXT,
    finding_json TEXT,
    PRIMARY KEY (scan_id, finding_id)
);

CREATE INDEX IF NOT EXISTS idx_findings_repo ON findings(repo);
CREATE INDEX IF NOT EXISTS idx_findings_reviewer ON findings(reviewer_verdict);
"""


class FindingsStore:
    """Tiny SQLite wrapper. No threading, no migrations -- this is a feedback
    cache, not a database.
    """

    def __init__(self, db_path: Path) -> None:
        self.db_path = db_path
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        self._init_schema()

    @classmethod
    def default(cls) -> FindingsStore:
        env = os.environ.get("REDEYE_DB_PATH")
        if env:
            return cls(Path(os.path.expanduser(env)))
        return cls(Path.home() / ".redeye" / "scans.db")

    def _connect(self) -> sqlite3.Connection:
        conn = sqlite3.connect(str(self.db_path))
        conn.row_factory = sqlite3.Row
        return conn

    def _init_schema(self) -> None:
        with closing(self._connect()) as conn, conn:
            conn.executescript(_SCHEMA)

    # -- write side --------------------------------------------------------

    def record_scan(self, *, repo: str, manifest, findings: list) -> str:  # type: ignore[no-untyped-def]
        scan_id = f"{manifest.target_sha or 'no-sha'}--{manifest.started_at.isoformat()}"
        with closing(self._connect()) as conn, conn:
            conn.execute(
                """
                INSERT OR REPLACE INTO scans (
                    scan_id, repo, application_id, profile, config_hash, target_sha,
                    started_at, ended_at, finding_count, dropped_count, total_cost_usd, manifest_json
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    scan_id,
                    repo,
                    manifest.application_id,
                    manifest.profile,
                    manifest.config_hash,
                    manifest.target_sha,
                    manifest.started_at.isoformat(),
                    manifest.ended_at.isoformat() if manifest.ended_at else None,
                    manifest.finding_count,
                    manifest.dropped_count,
                    manifest.total_cost_usd,
                    json.dumps(manifest.model_dump(mode="json"), default=str),
                ),
            )
            for f in findings:
                primary = f.locations[0] if f.locations else None
                conn.execute(
                    """
                    INSERT OR REPLACE INTO findings (
                        finding_id, scan_id, repo, title, severity, cwe,
                        cvss_vector, cvss_score, path, start_line, skill,
                        confidence, validator_verdict,
                        reviewer_verdict, reviewer_at, finding_json
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        f.id,
                        scan_id,
                        repo,
                        f.title,
                        f.severity.value,
                        f.cwe,
                        f.cvss_vector,
                        f.cvss_score,
                        primary.path if primary else None,
                        primary.start_line if primary else None,
                        f.skill,
                        f.confidence,
                        f.validator_verdict,
                        None,  # reviewer_verdict filled in by collect_feedback
                        None,
                        json.dumps(f.model_dump(mode="json"), default=str),
                    ),
                )
        return scan_id

    def record_reviewer_verdict(self, *, scan_id: str, finding_id: str, verdict: str) -> None:
        verdict = verdict.upper()
        if verdict not in {"TP", "FP", "UNK"}:
            raise ValueError(f"verdict must be TP|FP|UNK, got {verdict!r}")
        with closing(self._connect()) as conn, conn:
            conn.execute(
                "UPDATE findings SET reviewer_verdict = ?, reviewer_at = ? "
                "WHERE scan_id = ? AND finding_id = ?",
                (verdict, datetime.now(timezone.utc).isoformat(), scan_id, finding_id),
            )

    # -- read side --------------------------------------------------------

    def load_feedback(self, *, repo: str, limit: int = 50) -> list[dict[str, Any]]:
        """Return a compact list of prior reviewer marks for a repo.

        Used by S4 lenses to calibrate confidence on subsequent runs.
        """
        with closing(self._connect()) as conn:
            rows = conn.execute(
                """
                SELECT finding_id, title, severity, cwe, path, reviewer_verdict
                FROM findings
                WHERE repo = ? AND reviewer_verdict IS NOT NULL
                ORDER BY reviewer_at DESC
                LIMIT ?
                """,
                (repo, limit),
            ).fetchall()
        out: list[dict[str, Any]] = []
        for r in rows:
            out.append(
                {
                    "id": r["finding_id"],
                    "title": r["title"],
                    "severity": r["severity"],
                    "cwe": r["cwe"],
                    "path": r["path"],
                    "verdict": r["reviewer_verdict"],
                }
            )
        return out
