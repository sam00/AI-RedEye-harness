"""Threat baseline: accept STRIDE threats so S2 stops re-emitting them.

Mirrors :mod:`redeye.baseline` (which handles *findings*) but for the S2
threat model. The accepted file is ``.redeye-threat-baseline.yaml`` and stores
threat signatures (``category|asset``). Point a profile's
``s2_threat_model.params.baseline`` at this file and accepted threats are
subtracted from future threat models (see
:func:`redeye.skills.threat_modeler._load_threat_baseline`).

Operator workflow::

    redeye threat-baseline accept --category Spoofing --asset login
    redeye threat-baseline list
    redeye threat-baseline remove --category Spoofing --asset login
    redeye threat-baseline accept --manifest out/run_manifest.json --all
"""

from __future__ import annotations

import os
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path

import yaml

THREAT_BASELINE_FILENAME = ".redeye-threat-baseline.yaml"


def threat_sig(category: str, asset: str) -> str:
    """Stable ``category|asset`` signature, matching the threat modeler."""
    return f"{category}|{asset}".strip().lower()


@dataclass
class ThreatEntry:
    category: str
    asset: str
    accepted_by: str = "operator"
    accepted_at: str = ""
    rationale: str = ""

    @property
    def signature(self) -> str:
        return threat_sig(self.category, self.asset)

    def to_dict(self) -> dict:
        return {
            "category": self.category,
            "asset": self.asset,
            "accepted_by": self.accepted_by,
            "accepted_at": self.accepted_at,
            "rationale": self.rationale,
        }

    @classmethod
    def from_dict(cls, d: dict) -> ThreatEntry:
        return cls(
            category=str(d.get("category", "")),
            asset=str(d.get("asset", "")),
            accepted_by=str(d.get("accepted_by", "operator")),
            accepted_at=str(d.get("accepted_at", "")),
            rationale=str(d.get("rationale", "")),
        )


@dataclass
class ThreatBaseline:
    path: Path
    entries: dict[str, ThreatEntry] = field(default_factory=dict)

    @classmethod
    def load(cls, root: Path) -> ThreatBaseline:
        bl_path = root / THREAT_BASELINE_FILENAME if root.is_dir() else root
        b = cls(path=bl_path)
        if bl_path.is_file():
            try:
                raw = yaml.safe_load(bl_path.read_text(encoding="utf-8")) or {}
            except yaml.YAMLError:
                return b
            rows = raw.get("accepted", []) if isinstance(raw, dict) else raw
            for entry in rows or []:
                if isinstance(entry, dict) and entry.get("category"):
                    e = ThreatEntry.from_dict(entry)
                    b.entries[e.signature] = e
        return b

    def save(self) -> None:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        header = (
            "# .redeye-threat-baseline.yaml\n"
            "# STRIDE threats the operator has reviewed and accepted.\n"
            "# Point s2_threat_model.params.baseline at this file to subtract them.\n"
            "# Commit to source control to share decisions across the team.\n"
        )
        body = yaml.safe_dump(
            {"version": 1, "accepted": [e.to_dict() for e in self.entries.values()]},
            sort_keys=False,
        )
        self.path.write_text(header + body, encoding="utf-8")

    def accept(
        self,
        *,
        category: str,
        asset: str,
        rationale: str = "",
        accepted_by: str = "operator",
    ) -> ThreatEntry:
        entry = ThreatEntry(
            category=category,
            asset=asset,
            accepted_by=accepted_by,
            accepted_at=datetime.now(timezone.utc).isoformat(),
            rationale=rationale[:500],
        )
        self.entries[entry.signature] = entry
        return entry

    def remove(self, *, category: str, asset: str) -> bool:
        sig = threat_sig(category, asset)
        if sig in self.entries:
            del self.entries[sig]
            return True
        return False


def resolve_threat_baseline_root() -> Path:
    """Directory the threat baseline lives in (cwd, or REDEYE_THREAT_BASELINE_PATH)."""
    override = os.environ.get("REDEYE_THREAT_BASELINE_PATH")
    if override:
        return Path(override).expanduser()
    return Path.cwd()
