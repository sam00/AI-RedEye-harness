"""Baseline file: accept findings so they don't reappear on future scans.

The baseline file is ``.redeye-baseline.yaml`` in the target repo root.
It holds fingerprints of findings the operator has reviewed and
explicitly accepted (either as not-a-bug, or as accepted-risk). On a
subsequent scan, any finding whose fingerprint matches an entry in the
baseline is filtered out before the report is emitted.

Fingerprint shape (intentionally stable across runs):

    sha256(cwe + path + start_line + skill)[:16]

This is robust to wording changes in the finding title or description
(the LLM may reword on every run) but pins to the structural identity
(same CWE at same file:line, by the same skill).

Operator workflow:

    redeye baseline accept F-0001      # accept by run-local id
    redeye baseline accept --all-low   # accept all current LOW findings
    redeye baseline list               # show accepted entries
    redeye baseline remove <fingerprint>
"""

from __future__ import annotations

import hashlib
import os
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path

import yaml

BASELINE_FILENAME = ".redeye-baseline.yaml"


def fingerprint(*, cwe: str | None, path: str, start_line: int, skill: str | None) -> str:
    """Stable per-finding fingerprint (16 hex chars)."""
    raw = f"{(cwe or 'UNK').upper()}|{path}|{start_line}|{(skill or 'unknown')}"
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()[:16]


@dataclass
class BaselineEntry:
    fingerprint: str
    cwe: str
    path: str
    start_line: int
    skill: str
    accepted_by: str = "operator"
    accepted_at: str = ""
    rationale: str = ""

    def to_dict(self) -> dict:
        return {
            "fingerprint": self.fingerprint,
            "cwe": self.cwe,
            "path": self.path,
            "start_line": self.start_line,
            "skill": self.skill,
            "accepted_by": self.accepted_by,
            "accepted_at": self.accepted_at,
            "rationale": self.rationale,
        }

    @classmethod
    def from_dict(cls, d: dict) -> BaselineEntry:
        return cls(
            fingerprint=str(d.get("fingerprint", "")),
            cwe=str(d.get("cwe", "")),
            path=str(d.get("path", "")),
            start_line=int(d.get("start_line", 0)),
            skill=str(d.get("skill", "")),
            accepted_by=str(d.get("accepted_by", "operator")),
            accepted_at=str(d.get("accepted_at", "")),
            rationale=str(d.get("rationale", "")),
        )


@dataclass
class Baseline:
    """In-memory baseline; backed by ``.redeye-baseline.yaml`` in the target."""

    path: Path
    entries: dict[str, BaselineEntry] = field(default_factory=dict)

    @classmethod
    def load(cls, target: Path) -> Baseline:
        bl_path = target / BASELINE_FILENAME
        b = cls(path=bl_path)
        if bl_path.is_file():
            try:
                raw = yaml.safe_load(bl_path.read_text(encoding="utf-8")) or {}
            except yaml.YAMLError:
                return b
            for entry in raw.get("accepted", []) or []:
                if isinstance(entry, dict):
                    be = BaselineEntry.from_dict(entry)
                    if be.fingerprint:
                        b.entries[be.fingerprint] = be
        return b

    def save(self) -> None:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        payload = {
            "# This file lists findings the operator has reviewed and": None,
            "# accepted. Findings matching these fingerprints will be filtered": None,
            "# out of future scan reports. Commit this file to source control": None,
            "# so the team's acceptance decisions persist.": None,
            "version": 1,
            "accepted": [e.to_dict() for e in self.entries.values()],
        }
        # Strip the comment-key entries (yaml.dump doesn't natively support
        # inline comments). We write them as actual YAML comments instead.
        clean = {k: v for k, v in payload.items() if v is not None}
        header = (
            "# .redeye-baseline.yaml\n"
            "# Findings the operator has reviewed and accepted.\n"
            "# Future scans filter out any finding whose fingerprint matches.\n"
            "# Commit this file to source control to share decisions across the team.\n"
        )
        body = yaml.safe_dump(clean, sort_keys=False)
        self.path.write_text(header + body, encoding="utf-8")

    def contains(self, *, cwe: str | None, path: str, start_line: int, skill: str | None) -> bool:
        return fingerprint(cwe=cwe, path=path, start_line=start_line, skill=skill) in self.entries

    def accept(
        self,
        *,
        cwe: str | None,
        path: str,
        start_line: int,
        skill: str | None,
        rationale: str = "",
        accepted_by: str = "operator",
    ) -> BaselineEntry:
        fp = fingerprint(cwe=cwe, path=path, start_line=start_line, skill=skill)
        entry = BaselineEntry(
            fingerprint=fp,
            cwe=(cwe or "UNK").upper(),
            path=path,
            start_line=start_line,
            skill=skill or "unknown",
            accepted_by=accepted_by,
            accepted_at=datetime.now(timezone.utc).isoformat(),
            rationale=rationale[:500],
        )
        self.entries[fp] = entry
        return entry

    def remove(self, fp: str) -> bool:
        if fp in self.entries:
            del self.entries[fp]
            return True
        return False


def filter_findings(findings: list, baseline: Baseline) -> tuple[list, list]:  # type: ignore[no-untyped-def]
    """Return (kept, filtered_by_baseline). Inputs are :class:`Finding`."""
    kept = []
    filtered = []
    for f in findings:
        if not f.locations:
            kept.append(f)
            continue
        primary = f.locations[0]
        if baseline.contains(
            cwe=f.cwe, path=primary.path, start_line=primary.start_line, skill=f.skill
        ):
            f.tags.append("baseline:accepted")
            filtered.append(f)
        else:
            kept.append(f)
    return kept, filtered


def _resolve_baseline_root() -> Path:
    """Return the directory the baseline file should live in.

    Default: cwd. Override with ``REDEYE_BASELINE_PATH=/abs/path``.
    """
    override = os.environ.get("REDEYE_BASELINE_PATH")
    if override:
        return Path(override).expanduser()
    return Path.cwd()
