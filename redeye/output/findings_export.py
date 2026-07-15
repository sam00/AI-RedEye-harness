"""Flat findings export: ``findings.json`` and ``findings.csv``.

SARIF is canonical for tooling and the run manifest is the full audit record,
but both are verbose and awkward for quick dashboards, spreadsheet triage,
ticket creation, or run-to-run diffing. This emitter produces a *flat*,
one-row-per-finding view with the fields operators actually sort and filter on
-- severity, CWE, CVSS, confidence, and the deterministic verification /
corroboration verdicts (S8c / improvement #2).

Both the ``scan`` command and the standalone ``report`` command build these
from the same ``run_manifest.json``, so the two paths never drift.
"""

from __future__ import annotations

import csv
import json
from pathlib import Path

# Column order for the CSV and the per-row JSON objects. Kept explicit so the
# schema is stable for downstream consumers (spreadsheets, dashboards, diffs).
FIELDS: tuple[str, ...] = (
    "id",
    "title",
    "severity",
    "cwe",
    "cvss_score",
    "cvss_vector",
    "confidence",
    "calibrated_confidence",
    "verified",
    "verification_score",
    "verification_signals",
    "externally_corroborated",
    "corroborating_tools",
    "grounded",
    "reachability",
    "has_concrete_poc",
    "poc_demonstrated",
    "abstained",
    "path",
    "start_line",
    "end_line",
    "skill",
    "stage",
    "tags",
    "remediation",
)


def _final_findings(data: dict) -> list[dict]:
    """Return the findings emitted by the last stage (s9_emit) of a manifest."""
    final: list[dict] = []
    for stage in data.get("stages", []) or []:
        if stage.get("stage_id") == "s9_emit":
            final = stage.get("findings", []) or []
    if not final:
        # Fallback: last stage that produced any findings.
        for stage in data.get("stages", []) or []:
            if stage.get("findings"):
                final = stage.get("findings") or []
    return final


def _is_corroborated(f: dict) -> bool:
    if f.get("externally_corroborated"):
        return True
    return any(
        e.get("check") == "pass" and e.get("kind") == "external_corroboration"
        for e in (f.get("evidence") or [])
    )


def _flatten(f: dict) -> dict:
    """Collapse a serialized Finding dict into one flat row."""
    locs = f.get("locations") or [{}]
    loc = locs[0] if locs else {}
    ver = f.get("verification") or {}
    signals = ver.get("signals") or {}
    passing = sorted(k for k, ok in signals.items() if ok)
    return {
        "id": f.get("id", ""),
        "title": f.get("title", ""),
        "severity": (f.get("severity") or "").lower(),
        "cwe": f.get("cwe") or "",
        "cvss_score": f.get("cvss_score"),
        "cvss_vector": f.get("cvss_vector") or "",
        "confidence": f.get("confidence"),
        "calibrated_confidence": f.get("calibrated_confidence"),
        "verified": bool(ver.get("verified")),
        "verification_score": ver.get("score"),
        "verification_signals": ";".join(passing),
        "externally_corroborated": _is_corroborated(f),
        "corroborating_tools": ";".join(f.get("corroborating_tools") or []),
        "grounded": bool(f.get("grounded")),
        "reachability": f.get("reachability"),
        "has_concrete_poc": bool((f.get("poc") or {}).get("is_concrete")),
        "poc_demonstrated": bool(f.get("poc_demonstrated")),
        "abstained": bool(f.get("abstained")),
        "path": loc.get("path", ""),
        "start_line": loc.get("start_line", ""),
        "end_line": loc.get("end_line", ""),
        "skill": f.get("skill") or "",
        "stage": f.get("stage") or "",
        "tags": ";".join(f.get("tags") or []),
        "remediation": (f.get("remediation") or "").replace("\n", " ").strip(),
    }


def flatten_findings(findings: list[dict]) -> list[dict]:
    """Public helper: flatten a list of serialized Finding dicts."""
    return [_flatten(f) for f in findings]


def export_findings(manifest_path: Path, out_dir: Path) -> tuple[Path, Path]:
    """Write ``findings.json`` + ``findings.csv`` from a run manifest.

    Returns the (json_path, csv_path) pair. Redaction already ran when the
    manifest was written, so no secrets reach these files.
    """
    data = json.loads(Path(manifest_path).read_text(encoding="utf-8"))
    rows = flatten_findings(_final_findings(data))

    out_dir.mkdir(parents=True, exist_ok=True)
    json_path = out_dir / "findings.json"
    csv_path = out_dir / "findings.csv"

    json_path.write_text(json.dumps(rows, indent=2, sort_keys=False), encoding="utf-8")

    with csv_path.open("w", encoding="utf-8", newline="") as fh:
        writer = csv.DictWriter(fh, fieldnames=list(FIELDS), extrasaction="ignore")
        writer.writeheader()
        for row in rows:
            writer.writerow(row)

    return json_path, csv_path
