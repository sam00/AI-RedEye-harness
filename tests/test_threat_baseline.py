"""Threat-baseline storage + CLI tests."""

from __future__ import annotations

from pathlib import Path

from click.testing import CliRunner

from redeye.cli import main
from redeye.skills.threat_modeler import _load_threat_baseline
from redeye.threat_baseline import ThreatBaseline, threat_sig


def test_accept_and_load_roundtrip(tmp_path: Path) -> None:
    f = tmp_path / ".redeye-threat-baseline.yaml"
    bl = ThreatBaseline.load(f)
    bl.accept(category="Spoofing", asset="login", rationale="accepted risk")
    bl.save()
    # Reload and confirm persisted.
    bl2 = ThreatBaseline.load(f)
    assert threat_sig("Spoofing", "login") in bl2.entries
    # The threat modeler's loader reads the same file shape.
    sigs = _load_threat_baseline(str(f))
    assert "spoofing|login" in sigs


def test_remove(tmp_path: Path) -> None:
    f = tmp_path / ".redeye-threat-baseline.yaml"
    bl = ThreatBaseline.load(f)
    bl.accept(category="Tampering", asset="db")
    bl.save()
    bl = ThreatBaseline.load(f)
    assert bl.remove(category="Tampering", asset="db") is True
    assert bl.entries == {}


def test_cli_accept_list(tmp_path: Path) -> None:
    f = tmp_path / "tb.yaml"
    runner = CliRunner()
    rc = runner.invoke(
        main,
        ["threat-baseline", "accept", "--category", "Spoofing", "--asset", "login",
         "--file", str(f)],
    )
    assert rc.exit_code == 0, rc.output
    assert f.is_file()
    out = runner.invoke(main, ["threat-baseline", "list", "--file", str(f)])
    assert out.exit_code == 0
    assert "Spoofing" in out.output


def test_cli_accept_all_from_manifest(tmp_path: Path) -> None:
    import json

    manifest = tmp_path / "run_manifest.json"
    manifest.write_text(
        json.dumps(
            {
                "stages": [
                    {
                        "stage_id": "s2_threat_model",
                        "artifacts": {
                            "threat_model": {
                                "stride": [
                                    {"category": "Spoofing", "asset": "login"},
                                    {"category": "Tampering", "asset": "db"},
                                ]
                            }
                        },
                    }
                ]
            }
        ),
        encoding="utf-8",
    )
    f = tmp_path / "tb.yaml"
    runner = CliRunner()
    rc = runner.invoke(
        main,
        ["threat-baseline", "accept", "--manifest", str(manifest), "--all", "--file", str(f)],
    )
    assert rc.exit_code == 0, rc.output
    sigs = _load_threat_baseline(str(f))
    assert "spoofing|login" in sigs
    assert "tampering|db" in sigs
