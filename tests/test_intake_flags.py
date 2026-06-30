"""Tests for the S1 intake CLI flags, scope merge, and the Markdown
external-scanner section."""

from __future__ import annotations

import json
from pathlib import Path

from click.testing import CliRunner

from redeye.cli import main
from redeye.commands.scan import _merge_list, _scope_kwargs
from redeye.config import load_profile
from redeye.output.markdown import write_markdown_report
from redeye.schema import Finding, Location, Severity


def test_merge_list_unions_and_dedupes() -> None:
    assert _merge_list(["b", "c"], ["a", "b"]) == ["a", "b", "c"]
    assert _merge_list(None, None) == []


def test_scope_kwargs_cli_overrides_and_merges() -> None:
    cfg = load_profile("full")
    # full.yaml seeds exclude_dirs with [migrations, generated, fixtures].
    kwargs = _scope_kwargs(
        cfg,
        cli={
            "exclude_dirs": ["node_modules"],
            "max_file_kb": 64,
            "follow_symlinks": True,
        },
    )
    # CLI value merged with config baseline (union).
    assert "node_modules" in kwargs["exclude_dirs"]
    assert "migrations" in kwargs["exclude_dirs"]
    # Scalar CLI wins over config (full.yaml had 512).
    assert kwargs["max_file_kb"] == 64
    # Boolean CLI True overrides config False.
    assert kwargs["follow_symlinks"] is True


def test_scan_intake_flags_run(tiny_repo: Path) -> None:
    runner = CliRunner()
    result = runner.invoke(
        main,
        [
            "scan",
            "--repo",
            str(tiny_repo),
            "--profile",
            "mock",
            "--exclude-dir",
            "config",
            "--exclude-ext",
            ".md",
            "--exclude-glob",
            "**/*.snap",
            "--max-file-kb",
            "256",
            "--dedupe-configs",
            "--output-dir",
            str(tiny_repo / "out"),
        ],
    )
    assert result.exit_code == 0, result.output


def test_scan_external_scan_flag_and_report(tiny_repo: Path) -> None:
    sarif = {
        "version": "2.1.0",
        "runs": [
            {
                "tool": {"driver": {"name": "Semgrep"}},
                "results": [
                    {
                        "ruleId": "sql-inj",
                        "level": "error",
                        "message": {"text": "sqli"},
                        "locations": [
                            {
                                "physicalLocation": {
                                    "artifactLocation": {"uri": "src/api/users.py"},
                                    "region": {"startLine": 40},
                                }
                            }
                        ],
                    }
                ],
            }
        ],
    }
    ext = tiny_repo / "ext.sarif"
    ext.write_text(json.dumps(sarif), encoding="utf-8")
    out = tiny_repo / "out"
    runner = CliRunner()
    result = runner.invoke(
        main,
        [
            "scan",
            "--repo",
            str(tiny_repo),
            "--profile",
            "mock",
            "--external-scan",
            str(ext),
            "--output-dir",
            str(out),
        ],
    )
    assert result.exit_code == 0, result.output
    md = next(out.glob("*_report.md"))
    text = md.read_text(encoding="utf-8")
    assert "External scanner ingestion" in text
    assert "Semgrep" in text


def test_estimate_applies_intake_config(tmp_path: Path) -> None:
    """estimate must count from the same Scope a scan uses, honoring the
    profile's intake knobs (parity)."""
    from redeye.commands.estimate import _enumerate
    from redeye.commands.scan import _scope_kwargs
    from redeye.scope import Scope

    (tmp_path / "src").mkdir()
    (tmp_path / "src" / "a.py").write_text("x = 1\n", encoding="utf-8")
    (tmp_path / "src" / "b.py").write_text("y = 1\n", encoding="utf-8")

    cfg = load_profile("full")
    # Inject an exclusion into the loaded profile's S1 params.
    cfg.stages["s1_attack_surface"].params["exclude_globs"] = ["**/b.py"]
    scope = Scope.build(target=tmp_path, **_scope_kwargs(cfg, cli={}))
    files, _total, _langs = _enumerate(scope)
    names = {p.name for p in scope.files}
    assert "a.py" in names
    assert "b.py" not in names
    assert files == len(scope.files)


def test_markdown_external_section_unit(tmp_path: Path) -> None:
    f = Finding(
        id="F-0001",
        title="t",
        severity=Severity.HIGH,
        description="d",
        locations=[Location(path="a.py", start_line=1)],
    )
    path = tmp_path / "r.md"
    write_markdown_report(
        path=path,
        target=tmp_path,
        application_id=None,
        findings=[f],
        external_summary={
            "count": 3,
            "hits_added": 3,
            "by_tool": {"Semgrep": 2, "CodeQL": 1},
            "sources": ["/tmp/a.json"],
            "errors": [],
        },
    )
    text = path.read_text(encoding="utf-8")
    assert "External scanner ingestion" in text
    assert "| Semgrep | 2 |" in text
    assert "Merged as structural hits:** 3" in text
