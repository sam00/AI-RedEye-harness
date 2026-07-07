"""Tests for the labeled-benchmark eval metrics (improvement #3)."""

from __future__ import annotations

import json
from pathlib import Path

from redeye.eval_harness import LabeledVuln, Prediction, evaluate

_BENCH = Path(__file__).resolve().parent.parent / "redeye" / "eval" / "benchmark"


def test_precision_recall_and_hallucination():
    preds = [
        Prediction("app/users.py", 42, "CWE-89"),  # TP
        Prediction("app/x.py", 5, "CWE-79"),  # FP (real file, no label)
        Prediction("ghost.py", 999, "CWE-89"),  # hallucination + FP
    ]
    truth = [
        LabeledVuln("app/users.py", 43, "CWE-89"),
        LabeledVuln("app/z.py", 7, "CWE-22"),  # FN
    ]
    res = evaluate(preds, truth, line_tol=3, source_lines={"app/users.py": 100, "app/x.py": 50})
    assert res.tp == 1 and res.fp == 2 and res.fn == 1
    assert res.hallucinated == 1
    assert abs(res.precision - 0.3333) < 0.01
    assert abs(res.recall - 0.5) < 0.01


def test_cwe_mismatch_is_not_tp():
    preds = [Prediction("a.py", 10, "CWE-78")]
    truth = [LabeledVuln("a.py", 10, "CWE-89")]
    res = evaluate(preds, truth)
    assert res.tp == 0 and res.fp == 1 and res.fn == 1


def test_each_label_matched_once():
    preds = [Prediction("a.py", 10, "CWE-89"), Prediction("a.py", 11, "CWE-89")]
    truth = [LabeledVuln("a.py", 10, "CWE-89")]
    res = evaluate(preds, truth, line_tol=3)
    assert res.tp == 1 and res.fp == 1


def test_bundled_labels_resolve_to_real_lines():
    data = json.loads((_BENCH / "labels.json").read_text())
    for v in data["vulns"]:
        lines = (_BENCH / v["path"]).read_text().splitlines()
        assert 1 <= v["line"] <= len(lines)
