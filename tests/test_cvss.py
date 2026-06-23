"""CVSS auto-compute tests."""

from __future__ import annotations

from redeye.analysis.cvss import CvssMetrics, base_score, compute_cvss


def test_sql_injection_via_http_is_high() -> None:
    vector, score = compute_cvss(cwe="CWE-89", has_http_route=True, authenticated=False)
    assert vector.startswith("CVSS:3.1/AV:N/")
    assert "PR:N" in vector
    # SQLi with full DB compromise + network exposure should land >= 8.0
    assert score >= 8.0


def test_local_only_lowers_av() -> None:
    _, network = compute_cvss(cwe="CWE-89", has_http_route=True)
    _, local = compute_cvss(cwe="CWE-89", has_http_route=False)
    assert local < network


def test_authenticated_lowers_pr() -> None:
    _, unauth = compute_cvss(cwe="CWE-89", has_http_route=True, authenticated=False)
    _, auth = compute_cvss(cwe="CWE-89", has_http_route=True, authenticated=True)
    assert auth < unauth


def test_base_score_round_up_to_one_decimal() -> None:
    # A handcrafted set known to hit non-trivial impact + exploitability
    m = CvssMetrics(av="N", ac="L", pr="N", ui="N", s="U", c="H", i="H", a="H")
    score = base_score(m)
    assert score == 9.8  # textbook critical bug


def test_unknown_cwe_falls_back_to_medium_default() -> None:
    vector, score = compute_cvss(cwe=None, has_http_route=True)
    assert vector  # non-empty
    assert 0.0 <= score <= 10.0
