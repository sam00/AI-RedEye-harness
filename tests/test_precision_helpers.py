"""Tests for the deterministic precision helpers (improvements #4, #5, #7)."""

from __future__ import annotations

from redeye.abstention import decide, fit_platt
from redeye.ast_grounding import sink_call_on_line
from redeye.precision import in_closed_set, quote_is_grounded, self_consistency_keep
from redeye.provenance import make_stamp


# --- #4 closed-set ---------------------------------------------------------
def test_closed_set():
    inv = [("app/users.py", 42), ("app/api.py", 10)]
    assert in_closed_set("app/users.py", 43, inv) is True
    assert in_closed_set("src/app/users.py", 42, inv) is True  # basename tolerant
    assert in_closed_set("app/ghost.py", 5, inv) is False
    assert in_closed_set("x.py", 1, []) is True  # no constraint


# --- #5 self-consistency ---------------------------------------------------
def test_self_consistency_keeps_recurring():
    s1 = [("a.py", 10, "CWE-89"), ("b.py", 20, "CWE-78")]
    s2 = [("a.py", 11, "CWE-89"), ("c.py", 30, "CWE-22")]
    s3 = [("a.py", 10, "CWE-89")]
    kept = {k[0] for k in self_consistency_keep([s1, s2, s3], quorum=2)}
    assert "a.py" in kept and "b.py" not in kept and "c.py" not in kept


# --- #7 evidence-quoting verdicts ------------------------------------------
def test_quote_grounding():
    src = "def get(req):\n    cur.execute('SELECT * FROM t WHERE x='+q)\n    return 1"
    assert quote_is_grounded("cur.execute('SELECT * FROM t WHERE x='+q)", src) is True
    assert quote_is_grounded("cur.execute( 'SELECT * FROM t WHERE x=' + q )", src) is True  # ws
    assert quote_is_grounded("os.system(payload)", src) is False
    assert quote_is_grounded("q", src) is False  # too short


# --- #1 AST grounding ------------------------------------------------------
def test_ast_sink_detection():
    src = "import sqlite3\ndef h(r):\n    cur.execute('SELECT '+r)\n    return 1\n"
    assert sink_call_on_line(src, 3, "CWE-89") is True
    assert sink_call_on_line(src, 1, "CWE-89") is False
    assert sink_call_on_line(src, 3, "CWE-000") is None  # unmodelled cwe
    assert sink_call_on_line("def (:", 1, "CWE-89") is None  # unparseable


# --- #8 calibration + abstention -------------------------------------------
def test_platt_and_abstention():
    import random

    random.seed(0)
    scores, labels = [], []
    for _ in range(200):
        y = random.random() < 0.5
        s = min(1.0, max(0.0, (0.7 if y else 0.3) + random.uniform(-0.15, 0.15)))
        scores.append(s)
        labels.append(1 if y else 0)
    cal = fit_platt(scores, labels)
    assert cal.fitted and cal.predict(0.8) > cal.predict(0.2)
    assert fit_platt([0.5] * 3, [1, 1, 1]).fitted is False  # degenerate passthrough
    assert decide(0.9).verdict == "confirm"
    assert decide(0.5).abstained is True
    assert decide(0.1).verdict == "reject"


# --- #10 provenance --------------------------------------------------------
def test_provenance_stamp_is_hashed_and_stable():
    a = make_stamp(model="claude-opus-4-8", prompt="p", temperature=0.0, structural_index="idx")
    b = make_stamp(model="claude-opus-4-8", prompt="p", temperature=0.0, structural_index="idx")
    assert a == b  # deterministic
    assert a["model"] == "claude-opus-4-8"
    assert len(a["prompt_sha256"]) == 64
    assert "structural_index_sha" in a
