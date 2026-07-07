"""Labeled-benchmark evaluation metrics (improvement #3).

The hallucination counters RedEye already emits (``ungrounded_dropped`` etc.)
measure what the pipeline *pruned* -- they say nothing about whether the
reported findings are actually correct. To claim "validated and verified"
output you need ground truth. This module computes precision / recall / F1 and
a true **hallucination rate** for a scan against a labeled benchmark, so a
change to a prompt, model, or gate can be proven to help (or not) and a CI job
can block regressions.

Pure Python operating on tuples, so it is unit-testable offline and reusable
by the ``redeye eval`` command (see :mod:`redeye.commands.eval`).

Matching rules:
- A predicted finding *matches* a labeled vuln when path (basename-tolerant),
  line (within ``line_tol``) and CWE (when both present) agree.
- Each labeled vuln can be matched at most once (greedy nearest-line).
- **Hallucination**: a predicted finding whose cited location does not exist
  in the benchmark's ``source_lines`` map (missing file, or line past EOF).
  This is the strongest, ground-truth-free notion of "invented code".
"""

from __future__ import annotations

from dataclasses import dataclass, field


def _norm_path(p: str) -> str:
    return (p or "").replace("\\", "/").lstrip("./").lower()


def _base(p: str) -> str:
    return _norm_path(p).rsplit("/", 1)[-1]


def _norm_cwe(c: str | None) -> str:
    return (c or "").upper().strip()


@dataclass(frozen=True)
class Prediction:
    path: str
    line: int
    cwe: str | None = None


@dataclass(frozen=True)
class LabeledVuln:
    path: str
    line: int
    cwe: str | None = None


@dataclass
class EvalResult:
    tp: int = 0
    fp: int = 0
    fn: int = 0
    hallucinated: int = 0
    total_predicted: int = 0
    total_labeled: int = 0
    matched_labels: list[int] = field(default_factory=list)

    @property
    def precision(self) -> float:
        d = self.tp + self.fp
        return round(self.tp / d, 4) if d else 0.0

    @property
    def recall(self) -> float:
        d = self.tp + self.fn
        return round(self.tp / d, 4) if d else 0.0

    @property
    def f1(self) -> float:
        p, r = self.precision, self.recall
        return round(2 * p * r / (p + r), 4) if (p + r) else 0.0

    @property
    def hallucination_rate(self) -> float:
        return round(self.hallucinated / self.total_predicted, 4) if self.total_predicted else 0.0

    def to_dict(self) -> dict[str, float | int]:
        return {
            "tp": self.tp,
            "fp": self.fp,
            "fn": self.fn,
            "hallucinated": self.hallucinated,
            "total_predicted": self.total_predicted,
            "total_labeled": self.total_labeled,
            "precision": self.precision,
            "recall": self.recall,
            "f1": self.f1,
            "hallucination_rate": self.hallucination_rate,
        }


def _match(pred: Prediction, truth: LabeledVuln, line_tol: int) -> int | None:
    """Return line delta if pred matches truth, else None."""
    if _norm_path(pred.path) != _norm_path(truth.path) and _base(pred.path) != _base(truth.path):
        return None
    delta = abs(int(pred.line or 0) - int(truth.line or 0))
    if delta > line_tol:
        return None
    pc, tc = _norm_cwe(pred.cwe), _norm_cwe(truth.cwe)
    if pc and tc and pc != tc:
        return None
    return delta


def evaluate(
    predictions: list[Prediction],
    labeled: list[LabeledVuln],
    *,
    line_tol: int = 3,
    source_lines: dict[str, int] | None = None,
) -> EvalResult:
    """Score ``predictions`` against ``labeled`` ground truth.

    ``source_lines`` maps normalised path -> line count; when provided, any
    prediction citing a missing file or an out-of-range line is counted as a
    hallucination.
    """
    res = EvalResult(total_predicted=len(predictions), total_labeled=len(labeled))
    used: set[int] = set()

    for pred in predictions:
        # Hallucination check first (independent of TP/FP bookkeeping).
        if source_lines is not None:
            key = _norm_path(pred.path)
            n = source_lines.get(key)
            if n is None:
                # try basename match
                n = next(
                    (v for k, v in source_lines.items() if _base(k) == _base(pred.path)),
                    None,
                )
            if n is None or not (1 <= int(pred.line or 0) <= n):
                res.hallucinated += 1

        best_i, best_delta = None, None
        for i, truth in enumerate(labeled):
            if i in used:
                continue
            delta = _match(pred, truth, line_tol)
            if delta is None:
                continue
            if best_delta is None or delta < best_delta:
                best_i, best_delta = i, delta
        if best_i is None:
            res.fp += 1
        else:
            res.tp += 1
            used.add(best_i)
            res.matched_labels.append(best_i)

    res.fn = len(labeled) - len(used)
    return res
