"""PoC gate skill tests."""

from __future__ import annotations

from pathlib import Path

from redeye.backends.mock import MockBackend
from redeye.schema import Finding, Location, Severity, TaintFlow
from redeye.skills.poc_gate import _is_concrete, gate_findings


def test_is_concrete_for_real_curl() -> None:
    assert _is_concrete(
        "admin' OR 1=1 --",
        'curl -X POST http://localhost/api -d \'{"u": "admin\\u0027 OR 1=1 --"}\'',
    )


def test_is_concrete_rejects_placeholder() -> None:
    assert not _is_concrete("malicious_input", "<exploit_here>")
    assert not _is_concrete("", "")


def test_gate_marks_concrete_poc_and_keeps_severity(tmp_path: Path) -> None:
    f = Finding(
        id="F-0001",
        title="SQLi",
        severity=Severity.HIGH,
        cwe="CWE-89",
        description="x",
        locations=[Location(path="src/x.py", start_line=1)],
        remediation="bind",
        taint=TaintFlow(source="request.json['u']", sink="cursor.execute"),
    )
    findings, totals, metrics = gate_findings(
        findings=[f],
        target=tmp_path,
        backend=MockBackend({}),
        model="mock-fast",
        temperature=0.0,
        max_tokens=512,
        max_budget_usd=0.0,
    )
    assert len(findings) == 1
    assert findings[0].poc is not None
    assert findings[0].poc.is_concrete is True
    assert findings[0].severity == Severity.HIGH
    assert "poc:concrete" in findings[0].tags
    assert metrics["with_poc"] == 1


def test_gate_demotes_when_poc_missing(tmp_path: Path, monkeypatch) -> None:
    """Force the backend to return an empty PoC by patching the stub."""
    f = Finding(
        id="F-0002",
        title="Vague",
        severity=Severity.HIGH,
        cwe="CWE-200",
        description="x",
        locations=[Location(path="src/x.py", start_line=1)],
        remediation="x",
    )

    class _EmptyBackend(MockBackend):
        def complete(self, *, system, user, model, max_tokens, temperature):  # type: ignore[no-untyped-def]
            from redeye.backends.base import CompletionResult

            return CompletionResult(
                text='```json\n{"payload": "", "invocation": "", "expected_effect": "n/a"}\n```',
                tokens_in=10,
                tokens_out=20,
                cost_usd=0.0,
                model=model,
            )

    findings, _, metrics = gate_findings(
        findings=[f],
        target=tmp_path,
        backend=_EmptyBackend({}),
        model="mock-fast",
        temperature=0.0,
        max_tokens=512,
        max_budget_usd=0.0,
    )
    assert findings[0].severity == Severity.MEDIUM
    assert "no-poc:placeholder" in findings[0].tags
    assert metrics["no_poc_demoted"] == 1
