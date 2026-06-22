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


def test_scan_with_preset_quick_runs_against_mock(tiny_repo: Path, monkeypatch) -> None:
    """`redeye scan --preset quick` should produce a working scan with
    profile=mock baked in. No --profile flag needed.
    """
    # Point the SQLite store inside tmp so the test stays hermetic.
    monkeypatch.setenv("REDEYE_DB_PATH", str(tiny_repo / "scans.db"))
    runner = CliRunner()
    result = runner.invoke(
        main,
        [
            "scan",
            "--repo",
            str(tiny_repo),
            "--preset",
            "quick",
            "--output-dir",
            str(tiny_repo / "out"),
        ],
    )
    assert result.exit_code == 0, result.output
    # The preset banner should print so operators see what was applied.
    assert "applied preset" in result.output
    assert "quick" in result.output


def test_scan_explicit_flag_overrides_preset(tiny_repo: Path, monkeypatch) -> None:
    """User-supplied --max-files must beat the preset's value."""
    monkeypatch.setenv("REDEYE_DB_PATH", str(tiny_repo / "scans.db"))
    runner = CliRunner()
    result = runner.invoke(
        main,
        [
            "scan",
            "--repo",
            str(tiny_repo),
            "--preset",
            "quick",
            "--max-files",
            "7",
            "--output-dir",
            str(tiny_repo / "out"),
        ],
    )
    assert result.exit_code == 0, result.output
    # Banner shows that max_files was preserved as explicit.
    assert "max_files" in result.output
