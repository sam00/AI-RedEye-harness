"""Tests for the verified-outputs improvements: verification surfacing,
flat findings export, the standalone `report` command, and the opt-in LLM
response cache."""

from __future__ import annotations

import json
from pathlib import Path

from click.testing import CliRunner

from redeye.backends.base import BackendBase, CompletionResult
from redeye.cli import main
from redeye.llm_cache import CachingBackend
from redeye.output.findings_export import FIELDS, export_findings, flatten_findings
from redeye.output.markdown import write_markdown_report
from redeye.schema import Finding, Location, Severity, TaintFlow, VerificationResult

_FINDING_DICT = {
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
    "locations": [{"path": "app/x.py", "start_line": 5, "end_line": 5}],
    "remediation": "use params",
    "externally_corroborated": True,
    "corroborating_tools": ["semgrep", "codeql"],
    "verification": {
        "verified": True,
        "score": 0.83,
        "signals": {"grounded": True, "taint_complete": True, "vote_confirmed": True},
        "threshold": 3,
        "method": "deterministic",
        "rationale": "3/3 signals passed.",
    },
}

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
    "stages": [{"stage_id": "s9_emit", "skill": "emit", "findings": [_FINDING_DICT]}],
}


def _write_manifest(tmp_path: Path) -> Path:
    p = tmp_path / "run_manifest.json"
    p.write_text(json.dumps(_MANIFEST), encoding="utf-8")
    return p


# --- Markdown verification surfacing ---------------------------------------


def _finding_with_verification() -> Finding:
    return Finding(
        id="F-0001",
        title="SQL injection",
        severity=Severity.HIGH,
        cwe="CWE-89",
        description="bad",
        locations=[Location(path="app/x.py", start_line=5)],
        taint=TaintFlow(source="request.args['q']", sink="cursor.execute"),
        corroborating_tools=["semgrep"],
        externally_corroborated=True,
        verification=VerificationResult(
            verified=True,
            score=0.83,
            signals={"grounded": True, "taint_complete": True, "vote_confirmed": True},
            threshold=3,
            rationale="3/3 signals passed.",
        ),
    )


def test_markdown_surfaces_verification(tmp_path: Path) -> None:
    out = tmp_path / "report.md"
    write_markdown_report(
        path=out,
        target=Path("/tmp/demo"),
        application_id=None,
        findings=[_finding_with_verification()],
    )
    text = out.read_text(encoding="utf-8")
    assert "Verification (S8c)" in text
    assert "[VERIFIED]" in text
    assert "Verification summary" in text
    assert "Corroborated by:" in text
    assert "semgrep" in text


# --- Flat findings export ---------------------------------------------------


def test_flatten_findings_columns() -> None:
    rows = flatten_findings([_FINDING_DICT])
    assert len(rows) == 1
    row = rows[0]
    for col in FIELDS:
        assert col in row, f"missing column {col}"
    assert row["verified"] is True
    assert row["externally_corroborated"] is True
    assert row["corroborating_tools"] == "semgrep;codeql"
    assert row["path"] == "app/x.py"


def test_export_findings_writes_json_and_csv(tmp_path: Path) -> None:
    manifest = _write_manifest(tmp_path)
    json_path, csv_path = export_findings(manifest, tmp_path)
    assert json_path.is_file() and csv_path.is_file()
    data = json.loads(json_path.read_text(encoding="utf-8"))
    assert data[0]["id"] == "F-0001"
    header = csv_path.read_text(encoding="utf-8").splitlines()[0]
    assert "verified" in header and "severity" in header


# --- report command ---------------------------------------------------------


def test_report_command_regenerates_all_formats(tmp_path: Path) -> None:
    manifest = _write_manifest(tmp_path)
    out = tmp_path / "reports"
    rc = CliRunner().invoke(
        main,
        ["report", "--manifest", str(manifest), "--format", "all", "--output-dir", str(out)],
    )
    assert rc.exit_code == 0, rc.output
    assert (out / "report.html").is_file()
    assert (out / "report.md").is_file()
    assert (out / "findings.json").is_file()
    assert (out / "findings.csv").is_file()


def test_report_command_missing_manifest(tmp_path: Path) -> None:
    rc = CliRunner().invoke(
        main, ["report", "--manifest", str(tmp_path / "nope.json"), "--format", "html"]
    )
    # click rejects a non-existent --manifest path at parse time (exit 2).
    assert rc.exit_code == 2


# --- eval command (regression: Orchestrator needs application_id) -----------


def test_eval_command_runs_and_writes_metrics(tmp_path: Path) -> None:
    out_json = tmp_path / "eval.json"
    rc = CliRunner().invoke(
        main,
        [
            "eval",
            "--profile",
            "mock",
            "--max-hallucination",
            "1.0",
            "--output-json",
            str(out_json),
        ],
    )
    # Must not crash (previously raised TypeError: missing application_id).
    assert rc.exit_code == 0, rc.output
    assert out_json.is_file()
    metrics = json.loads(out_json.read_text(encoding="utf-8"))
    for key in ("precision", "recall", "f1", "hallucination_rate", "total_predicted"):
        assert key in metrics


# --- opt-in LLM cache -------------------------------------------------------


class _CountingBackend(BackendBase):
    name = "counting"

    def __init__(self) -> None:
        super().__init__({})
        self.calls = 0

    def has_credential(self) -> bool:
        return True

    def health_check(self) -> bool:
        return True

    def complete(self, *, system, user, model, max_tokens, temperature):  # type: ignore[no-untyped-def]
        self.calls += 1
        return CompletionResult(text=f"resp-{self.calls}", tokens_in=1, tokens_out=1, cost_usd=0.01)


def test_cache_serves_deterministic_calls(tmp_path: Path) -> None:
    inner = _CountingBackend()
    cached = CachingBackend(inner, tmp_path / "cache")
    kwargs = dict(system="s", user="u", model="m", max_tokens=10, temperature=0.0)
    first = cached.complete(**kwargs)
    second = cached.complete(**kwargs)
    assert inner.calls == 1  # second call served from disk
    assert first.text == second.text
    assert second.cost_usd == 0.0  # hit reports no new spend


def test_cache_bypasses_stochastic_calls(tmp_path: Path) -> None:
    inner = _CountingBackend()
    cached = CachingBackend(inner, tmp_path / "cache")
    kwargs = dict(system="s", user="u", model="m", max_tokens=10, temperature=0.7)
    cached.complete(**kwargs)
    cached.complete(**kwargs)
    # temperature > 0 must never be cached (preserves sampling diversity).
    assert inner.calls == 2
