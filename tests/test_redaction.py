"""Secret-redaction tests for human-facing report text."""

from __future__ import annotations

from pathlib import Path

from redeye.output.markdown import write_markdown_report
from redeye.redaction import MASK, redact_secrets
from redeye.schema import Finding, Location, Severity


def test_redacts_known_token_shapes() -> None:
    assert "sk-ant-" not in redact_secrets("key sk-ant-abcdefghijklmnopqrstuvwxyz1234")
    assert "AKIA" not in redact_secrets("aws AKIAIOSFODNN7EXAMPLE here")
    assert "ghp_" not in redact_secrets("token ghp_" + "a" * 36)
    out = redact_secrets("header.eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxIn0.sig_part_here")
    assert MASK in out


def test_redacts_assignment_keeps_key_name() -> None:
    out = redact_secrets('api_key: "supersecretvalue123"')
    assert "api_key" in out  # key name preserved
    assert "supersecretvalue123" not in out
    assert MASK in out


def test_non_secret_text_untouched() -> None:
    text = "def add(a, b):\n    return a + b\n"
    assert redact_secrets(text) == text


def test_markdown_report_redacts_by_default(tmp_path: Path) -> None:
    f = Finding(
        id="F-0001",
        title="Hardcoded credential",
        severity=Severity.HIGH,
        description='Found api_key: "sk-ant-abcdefghijklmnopqrstuvwxyz1234" in config',
        locations=[Location(path="config/defaults.yaml", start_line=12)],
    )
    path = tmp_path / "r.md"
    write_markdown_report(path=path, target=tmp_path, application_id=None, findings=[f])
    text = path.read_text(encoding="utf-8")
    assert "sk-ant-abcdefghijklmnopqrstuvwxyz1234" not in text
    assert MASK in text


def test_markdown_report_redact_opt_out(tmp_path: Path) -> None:
    f = Finding(
        id="F-0001",
        title="t",
        severity=Severity.LOW,
        description="token ghp_" + "a" * 36,
        locations=[Location(path="a.py", start_line=1)],
    )
    path = tmp_path / "r.md"
    write_markdown_report(
        path=path, target=tmp_path, application_id=None, findings=[f], redact=False
    )
    assert "ghp_" + "a" * 36 in path.read_text(encoding="utf-8")
