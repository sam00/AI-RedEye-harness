"""Probability calibration + abstention banding (improvement #8).

This complements :mod:`redeye.calibration` (which nudges a finding's raw
confidence using per-CWE / per-skill reliability learned from the feedback
store). Here we go one step further and turn a raw score into a *calibrated
probability* via **Platt scaling** (a 1-D logistic fit trained with plain
gradient descent -- no scikit-learn dependency), then band that probability
into a decision with an explicit **abstention** zone so borderline findings
are routed to a human as ``uncertain`` rather than asserted or silently
dropped.

Everything here is pure Python operating on floats, so it is fully
unit-testable offline and adds no runtime dependency.
"""

from __future__ import annotations

import math
from dataclasses import dataclass


def _sigmoid(z: float) -> float:
    if z >= 0:
        return 1.0 / (1.0 + math.exp(-z))
    ez = math.exp(z)
    return ez / (1.0 + ez)


@dataclass
class PlattCalibrator:
    """1-D logistic calibrator: ``p = sigmoid(a * score + b)``.

    Defaults to a pass-through-ish mapping (``a=1, b=0``) so an unfit
    calibrator degrades gracefully rather than raising.
    """

    a: float = 1.0
    b: float = 0.0
    fitted: bool = False
    n: int = 0

    def predict(self, score: float) -> float:
        return _sigmoid(self.a * float(score) + self.b)

    def to_dict(self) -> dict[str, float | bool | int]:
        return {"a": self.a, "b": self.b, "fitted": self.fitted, "n": self.n}


def fit_platt(
    scores: list[float],
    labels: list[int],
    *,
    lr: float = 0.5,
    epochs: int = 2000,
) -> PlattCalibrator:
    """Fit Platt scaling on ``(score, label)`` pairs (label 1 = confirmed TP,
    0 = FP).

    Falls back to an unfitted pass-through calibrator when there is not enough
    signal (fewer than 8 samples, or a single class present) -- calibrating on
    degenerate data does more harm than good.
    """
    if len(scores) != len(labels):
        raise ValueError("scores and labels must be the same length")
    pos = sum(1 for y in labels if y == 1)
    neg = len(labels) - pos
    if len(scores) < 8 or pos == 0 or neg == 0:
        return PlattCalibrator(a=1.0, b=0.0, fitted=False, n=len(scores))

    a, b = 1.0, 0.0
    m = len(scores)
    for _ in range(epochs):
        ga = gb = 0.0
        for s, y in zip(scores, labels, strict=True):
            p = _sigmoid(a * s + b)
            err = p - y
            ga += err * s
            gb += err
        a -= lr * ga / m
        b -= lr * gb / m
    return PlattCalibrator(a=a, b=b, fitted=True, n=m)


@dataclass(frozen=True)
class Decision:
    """A banded decision over a calibrated probability."""

    probability: float
    verdict: str  # "confirm" | "uncertain" | "reject"
    abstained: bool


def decide(
    probability: float,
    *,
    reject_below: float = 0.3,
    confirm_at_or_above: float = 0.7,
) -> Decision:
    """Band a calibrated probability into confirm / uncertain / reject.

    The middle band is the *abstention* zone -- these findings are surfaced to
    a human as ``uncertain`` rather than asserted or dropped.
    """
    if not 0.0 <= reject_below <= confirm_at_or_above <= 1.0:
        raise ValueError("require 0 <= reject_below <= confirm_at_or_above <= 1")
    if probability >= confirm_at_or_above:
        return Decision(probability, "confirm", False)
    if probability < reject_below:
        return Decision(probability, "reject", False)
    return Decision(probability, "uncertain", True)
