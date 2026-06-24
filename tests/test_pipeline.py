"""End-to-end smoke tests against the mock backend."""

from __future__ import annotations

import json
from pathlib import Path

from rich.console import Console

from redeye.config import load_profile
from redeye.pipeline.orchestrator import Orchestrator


def test_full_pipeline_runs_against_mock(tiny_repo: Path) -> None:
    cfg = load_profile("mock")
    out_dir = tiny_repo / "security-scan"
    orch = Orchestrator(
        config=cfg,
        console=Console(record=True),
        target=tiny_repo,
        output_dir=out_dir,
        application_id="APP-TEST",
    )
    manifest = orch.run()

    assert manifest.profile == "mock"
    assert manifest.application_id == "APP-TEST"
    assert manifest.ended_at is not None
    assert manifest.finding_count >= 0
    # Mock profile enables all 14 stages: the original 9 plus
    # s1b_structural, s4b_grounding, s6b_validator, s8b_poc, and s8c_verify.
    assert len(manifest.stages) == 14

    md_files = list(out_dir.glob("*_report.md"))
    sarif_files = list(out_dir.glob("*_report.sarif"))
    assert md_files, "Markdown report should have been written"
    assert sarif_files, "SARIF report should have been written"
    assert (out_dir / "run_manifest.json").is_file()


def test_mock_pipeline_produces_findings(tiny_repo: Path) -> None:
    cfg = load_profile("mock")
    out_dir = tiny_repo / "security-scan"
    orch = Orchestrator(
        config=cfg,
        console=Console(record=True),
        target=tiny_repo,
        output_dir=out_dir,
        application_id=None,
    )
    manifest = orch.run()

    # The mock S4 always emits two findings; voting may keep some/all.
    assert manifest.finding_count >= 1


def test_sarif_is_well_formed(tiny_repo: Path) -> None:
    cfg = load_profile("mock")
    out_dir = tiny_repo / "security-scan"
    orch = Orchestrator(
        config=cfg,
        console=Console(record=True),
        target=tiny_repo,
        output_dir=out_dir,
        application_id=None,
    )
    orch.run()

    sarif_path = next(out_dir.glob("*_report.sarif"))
    with sarif_path.open() as fh:
        sarif = json.load(fh)
    assert sarif["version"] == "2.1.0"
    assert sarif["runs"][0]["tool"]["driver"]["name"] == "redeye"
