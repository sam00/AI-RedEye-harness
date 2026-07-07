"""Tests for the behavioral PoC oracle (improvement #6)."""

from __future__ import annotations

import pytest

from redeye.poc_oracle import evaluate


@pytest.mark.parametrize(
    "payload,cwe,expected",
    [
        ("' OR '1'='1", "CWE-89", True),
        ("1 OR 1=1", "CWE-89", True),
        ("'; DROP TABLE users;--", "CWE-89", True),
        ("1 UNION SELECT a,b FROM users", "CWE-89", True),
        ("admin'--", "CWE-89", True),
        ("hello world", "CWE-89", False),
        ("-- just a comment", "CWE-89", False),
        ("127.0.0.1; cat /etc/passwd", "CWE-78", True),
        ("$(whoami)", "CWE-78", True),
        ("8.8.8.8", "CWE-78", False),
        ("../../../../etc/passwd", "CWE-22", True),
        ("../config", "CWE-22", False),
        ("http://169.254.169.254/latest/meta-data/", "CWE-918", True),
        ("http://metadata.google.internal/", "CWE-918", True),
        ("https://example.com/x", "CWE-918", False),
        ("<script>alert(1)</script>", "CWE-79", True),
        ("__import__('os').system('id')", "CWE-95", True),
    ],
)
def test_oracle_verdicts(payload, cwe, expected):
    assert evaluate(payload, cwe).demonstrated is expected


def test_unsupported_and_empty():
    assert evaluate("anything", "CWE-1234").vuln_class == "unsupported"
    assert evaluate("", "CWE-89").demonstrated is False
    assert evaluate("   ", "CWE-78").vuln_class == "empty"
