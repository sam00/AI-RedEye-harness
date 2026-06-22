"""CLI surface tests via Click's runner."""

from __future__ import annotations

from pathlib import Path

from click.testing import CliRunner

from redeye import __version__
from redeye.cli import main


def test_version_flag() -> None:
    runner = CliRunner()
    result = runner.invoke(main, ["--version"])
    assert result.exit_code == 0
    assert __version__ in result.output


def test_help_works() -> None:
    runner = CliRunner()
    result = runner.invoke(main, ["--help"])
    assert result.exit_code == 0
    assert "scan" in result.output


def test_doctor_runs(monkeypatch) -> None:
    # Doctor should succeed with the mock profile because mock is always operable.
    monkeypatch.setenv("REDEYE_PROFILE", "mock")
    runner = CliRunner()
    result = runner.invoke(main, ["doctor", "--no-network"])
    assert result.exit_code == 0


def test_estimate_runs(tiny_repo: Path) -> None:
    runner = CliRunner()
    result = runner.invoke(main, ["estimate", "--repo", str(tiny_repo), "--profile", "mock"])
    assert result.exit_code == 0
    assert "Files scanned" in result.output


def test_scan_runs(tiny_repo: Path) -> None:
    runner = CliRunner()
    result = runner.invoke(
        main,
        [
            "scan",
            "--repo",
            str(tiny_repo),
            "--profile",
            "mock",
            "--output-dir",
            str(tiny_repo / "security-scan"),
        ],
    )
    assert result.exit_code == 0, result.output
