"""Grounding pass tests."""

from __future__ import annotations

from pathlib import Path

from redeye.ast_grounding import sink_call_on_line
from redeye.grounding import ground_findings, ground_one
from redeye.schema import Finding, Location, Severity


def _f(path: str, line: int, cwe: str = "CWE-89", title: str = "x") -> Finding:
    return Finding(
        id="F-0001",
        title=title,
        severity=Severity.HIGH,
        cwe=cwe,
        description="x",
        locations=[Location(path=path, start_line=line)],
        remediation="parameterise",
        confidence=0.7,
    )


def test_ground_one_passes_for_real_file_with_matching_token(tmp_path: Path) -> None:
    target = tmp_path
    f_path = target / "src.py"
    f_path.parent.mkdir(parents=True, exist_ok=True)
    f_path.write_text(
        "def lookup(u):\n    cursor.execute(f'SELECT * FROM t WHERE n={u}')\n", encoding="utf-8"
    )

    finding = _f("src.py", 2, cwe="CWE-89")
    ground_one(finding=finding, target=target)
    assert finding.grounded is True
    kinds = {(e.kind, e.check) for e in finding.evidence}
    assert ("file_exists", "pass") in kinds
    assert ("line_resolves", "pass") in kinds
    assert ("snippet_match", "pass") in kinds


def test_ground_one_fails_for_missing_path(tmp_path: Path) -> None:
    finding = _f("does/not/exist.py", 1)
    ground_one(finding=finding, target=tmp_path)
    assert finding.grounded is False
    assert "hallucinated:bad-path" in finding.tags


def test_ground_one_fails_for_out_of_range_line(tmp_path: Path) -> None:
    f_path = tmp_path / "x.py"
    f_path.write_text("x = 1\n", encoding="utf-8")
    finding = _f("x.py", 99)
    ground_one(finding=finding, target=tmp_path)
    assert "hallucinated:bad-line" in finding.tags


def test_ground_one_weak_when_tokens_mismatch(tmp_path: Path) -> None:
    f_path = tmp_path / "x.py"
    f_path.write_text("x = 1 + 1\n", encoding="utf-8")
    finding = _f("x.py", 1, cwe="CWE-89")  # SQL CWE but file has no SQL tokens
    ground_one(finding=finding, target=tmp_path)
    assert finding.grounded is False
    assert "weak-evidence" in finding.tags


def test_strict_grounding_drops_hallucinations(tmp_path: Path) -> None:
    findings = [
        _f("does/not/exist.py", 1),  # hallucinated path
        _f("nope.py", 9999),  # hallucinated line
    ]
    kept, dropped, report = ground_findings(findings=findings, target=tmp_path, strict=True)
    assert kept == []
    assert len(dropped) == 2
    assert report.dropped == 2


def test_non_strict_grounding_keeps_but_tags(tmp_path: Path) -> None:
    findings = [_f("does/not/exist.py", 1)]
    kept, dropped, report = ground_findings(findings=findings, target=tmp_path, strict=False)
    assert len(kept) == 1
    assert dropped == []
    assert "hallucinated:bad-path" in kept[0].tags


def test_ast_ambiguous_names_require_name_qualification() -> None:
    # Bare / literal-receiver calls to ambiguous sink names prove nothing...
    assert sink_call_on_line('csv = ",".join(parts)\n', 1, "CWE-22") is False
    assert sink_call_on_line("data = get(url)\n", 1, "CWE-918") is False
    # ...while name-qualified calls still count.
    assert sink_call_on_line("p = os.path.join(base, name)\n", 1, "CWE-22") is True
    assert sink_call_on_line("r = requests.get(url)\n", 1, "CWE-918") is True
    # Unambiguous names keep matching even as bare calls.
    assert sink_call_on_line("execute(q)\n", 1, "CWE-89") is True


def test_bare_join_is_not_ast_grounded_for_cwe22(tmp_path: Path) -> None:
    f_path = tmp_path / "j.py"
    f_path.write_text('parts = ["a", "b"]\ncsv = ",".join(parts)\n', encoding="utf-8")
    finding = _f("j.py", 2, cwe="CWE-22")
    ground_one(finding=finding, target=tmp_path)
    kinds = {(e.kind, e.check) for e in finding.evidence}
    # The AST must not treat a bare ``",".join(...)`` as a CWE-22 sink call;
    # the coarse token check may still apply, but no AST rescue happens.
    assert ("ast_sink_match", "fail") in kinds
    assert ("ast_sink_match", "pass") not in kinds


def test_qualified_join_still_ast_grounds_cwe22(tmp_path: Path) -> None:
    f_path = tmp_path / "p.py"
    f_path.write_text("import os\np = os.path.join(base, user_name)\n", encoding="utf-8")
    finding = _f("p.py", 2, cwe="CWE-22")
    ground_one(finding=finding, target=tmp_path)
    kinds = {(e.kind, e.check) for e in finding.evidence}
    assert ("ast_sink_match", "pass") in kinds
    assert finding.grounded is True
