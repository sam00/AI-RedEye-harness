"""HTML / PDF report + manifest JSON Schema tests."""

from __future__ import annotations

import json
from pathlib import Path

from click.testing import CliRunner

from redeye.cli import main
from redeye.output.html import render_manifest_html
from redeye.output.manifest_schema import (
    manifest_json_schema,
    validate_manifest_file,
    write_manifest_schema,
)
from redeye.output.pdf import PDF_AVAILABLE, render_manifest_pdf

_MANIFEST = {
    "tool": "redeye",
    "version": "0.3.0",
    "started_at": "2026-01-01T00:00:00+00:00",
    "ended_at": "2026-01-01T00:01:00+00:00",
    "profile": "mock",
    "config_hash": "abc",
    "target_repo": "/tmp/demo",
    "total_cost_usd": 0.0,
    "finding_count": 1,
    "dropped_count": 0,
    "stages": [
        {
            "stage_id": "s1b_structural",
            "skill": "structural_index",
            "artifacts": {
                "structural_summary": {"files_indexed": 3, "sinks": 1},
                "external_summary": {"count": 2, "reachable": 1, "deduped": 1},
            },
        },
        {
            "stage_id": "s9_emit",
            "skill": "emit",
            "findings": [
                {
                    "id": "F-0001",
                    "title": "SQL injection",
                    "severity": "high",
                    "cwe": "CWE-89",
                    "description": "bad",
                    "confidence": 0.8,
                    "grounded": True,
                    "skill": "language",
                    "stage": "s4_research",
                    "tags": ["deterministic"],
                    "locations": [{"path": "app/x.py", "start_line": 5}],
                    "remediation": "use params",
                }
            ],
        },
    ],
}


def _write_manifest(tmp_path: Path) -> Path:
    p = tmp_path / "run_manifest.json"
    p.write_text(json.dumps(_MANIFEST), encoding="utf-8")
    return p


def test_html_report_is_self_contained(tmp_path: Path) -> None:
    manifest = _write_manifest(tmp_path)
    out = tmp_path / "report.html"
    render_manifest_html(manifest, out, target_name="demo")
    text = out.read_text(encoding="utf-8")
    assert "<!DOCTYPE html>" in text
    assert "SQL injection" in text
    assert "data-severity=\"high\"" in text
    # No external asset references.
    assert "http://" not in text and "https://" not in text
    assert "<script>" in text  # interactive filtering inlined


def test_pdf_report_renders(tmp_path: Path) -> None:
    if not PDF_AVAILABLE:
        return  # reportlab not installed; inline PDF gracefully unavailable
    manifest = _write_manifest(tmp_path)
    out = tmp_path / "report.pdf"
    render_manifest_pdf(manifest, out, target_name="demo")
    assert out.is_file()
    assert out.read_bytes()[:5] == b"%PDF-"


def test_manifest_schema_valid_and_validates(tmp_path: Path) -> None:
    schema = manifest_json_schema()
    assert schema.get("title")
    assert "properties" in schema
    manifest = _write_manifest(tmp_path)
    errors = validate_manifest_file(manifest)
    assert errors == [], errors


def test_write_manifest_schema(tmp_path: Path) -> None:
    p = write_manifest_schema(tmp_path)
    assert p.is_file()
    schema = json.loads(p.read_text(encoding="utf-8"))
    assert schema["title"].startswith("RedEye")


def test_scan_emits_html_and_schema(tiny_repo: Path) -> None:
    out = tiny_repo / "out"
    runner = CliRunner()
    rc = runner.invoke(
        main,
        ["scan", "--repo", str(tiny_repo), "--profile", "mock", "--html",
         "--output-dir", str(out)],
    )
    assert rc.exit_code == 0, rc.output
    assert (out / "report.html").is_file()
    # Schema is dropped next to the manifest automatically.
    assert (out / "run_manifest.schema.json").is_file()
    assert validate_manifest_file(out / "run_manifest.json") == []
