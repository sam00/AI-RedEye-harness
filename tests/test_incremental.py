"""Incremental scan tests."""

from __future__ import annotations

import json
from pathlib import Path

from click.testing import CliRunner

from redeye.cli import main
from redeye.incremental import changed_files, hash_files, load_prior_hashes


def test_changed_files_first_run_returns_all(tmp_path: Path) -> None:
    (tmp_path / "a.py").write_text("x = 1\n", encoding="utf-8")
    (tmp_path / "b.py").write_text("y = 2\n", encoding="utf-8")
    files = [tmp_path / "a.py", tmp_path / "b.py"]
    changed, current = changed_files(tmp_path, files, prior={})
    assert set(changed) == set(files)
    assert set(current) == {"a.py", "b.py"}


def test_changed_files_detects_modifications(tmp_path: Path) -> None:
    a = tmp_path / "a.py"
    b = tmp_path / "b.py"
    a.write_text("x = 1\n", encoding="utf-8")
    b.write_text("y = 2\n", encoding="utf-8")
    prior = hash_files(tmp_path, [a, b])
    # Modify only b.
    b.write_text("y = 3\n", encoding="utf-8")
    changed, _ = changed_files(tmp_path, [a, b], prior)
    assert changed == [b]


def test_load_prior_hashes_from_manifest(tmp_path: Path) -> None:
    manifest = tmp_path / "run_manifest.json"
    manifest.write_text(json.dumps({"file_hashes": {"a.py": "deadbeef"}}), encoding="utf-8")
    assert load_prior_hashes(manifest) == {"a.py": "deadbeef"}
    assert load_prior_hashes(tmp_path / "missing.json") == {}


def test_incremental_scan_records_hashes_and_skips(tiny_repo: Path) -> None:
    out = tiny_repo / "out"
    runner = CliRunner()
    # First incremental run: no prior -> full scan, records file_hashes.
    rc1 = runner.invoke(
        main,
        [
            "scan",
            "--repo",
            str(tiny_repo),
            "--profile",
            "mock",
            "--incremental",
            "--output-dir",
            str(out),
        ],
    )
    assert rc1.exit_code == 0, rc1.output
    manifest = json.loads((out / "run_manifest.json").read_text(encoding="utf-8"))
    assert manifest["file_hashes"], "first run should record file hashes"

    # Second incremental run: nothing changed -> 0 files changed reported.
    rc2 = runner.invoke(
        main,
        [
            "scan",
            "--repo",
            str(tiny_repo),
            "--profile",
            "mock",
            "--incremental",
            "--output-dir",
            str(out),
        ],
    )
    assert rc2.exit_code == 0, rc2.output
    assert "0/" in rc2.output or "changed" in rc2.output
