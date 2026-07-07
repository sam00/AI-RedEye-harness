"""Deterministic precision helpers for improvements #4, #5, #7.

These are the pure, LLM-free cores of three model-side precision controls. The
prompt/sampling plumbing lives in the S4/S6 stages; the *decisions* live here
so they are deterministic and unit-testable offline.

- #4 Closed-set citation (:func:`in_closed_set`): a lens finding may only cite
  a sink location that exists in the S1b structural inventory. This makes
  "invented sink/route" structurally impossible rather than caught later.
- #5 Self-consistency (:func:`self_consistency_keep`): keep only findings that
  recur across k independently-sampled lens passes (or prompt-perturbed passes
  on temperature-rejecting models), killing stochastic one-off hallucinations.
- #7 Evidence-quoting verdicts (:func:`quote_is_grounded`): a judge
  (validator/adversary) verdict must quote real source; a verdict whose quote
  does not appear in the file is not trustworthy.
"""

from __future__ import annotations

import re


def _norm_path(p: str) -> str:
    return (p or "").replace("\\", "/").lstrip("./").lower()


# --- #4 closed-set citation -------------------------------------------------
def in_closed_set(
    path: str,
    line: int,
    inventory: list[tuple[str, int]],
    *,
    line_tol: int = 2,
) -> bool:
    """True iff (path, line) is within ``line_tol`` of an inventory entry.

    ``inventory`` is the list of real (path, line) sink/source locations the
    structural pre-index (S1b) extracted -- the closed set a lens is allowed to
    cite. An empty inventory returns True (no constraint to enforce).
    """
    if not inventory:
        return True
    fp = _norm_path(path)
    fb = fp.rsplit("/", 1)[-1]
    for ip, il in inventory:
        nip = _norm_path(ip)
        if nip != fp and nip.rsplit("/", 1)[-1] != fb:
            continue
        if abs(int(il) - int(line or 0)) <= line_tol:
            return True
    return False


# --- #5 self-consistency ----------------------------------------------------
def self_consistency_keep(
    samples: list[list[tuple]],
    *,
    quorum: int = 2,
    line_tol: int = 3,
) -> list[tuple]:
    """Given ``samples`` (one list of finding keys per sampled pass), return the
    keys that appear in at least ``quorum`` passes. A key is
    ``(path, line, cwe)``; two keys agree when path+cwe match and lines are
    within ``line_tol``. Returns the representative key from the first pass that
    reached quorum, plus its support count folded in via ``agreement``-friendly
    ordering.
    """
    flat: list[tuple] = [k for s in samples for k in s]
    kept: list[tuple] = []
    used: list[int] = []
    for i, key in enumerate(flat):
        if i in used:
            continue
        support = 1
        group = [i]
        for j in range(i + 1, len(flat)):
            if j in used:
                continue
            if _keys_agree(key, flat[j], line_tol):
                support += 1
                group.append(j)
        used.extend(group)
        # Count distinct passes represented (not raw duplicates).
        passes = _passes_covered(group, samples)
        if passes >= quorum:
            kept.append(key)
    return kept


def _pass_index(flat_index: int, samples: list[list[tuple]]) -> int:
    seen = 0
    for pi, s in enumerate(samples):
        if flat_index < seen + len(s):
            return pi
        seen += len(s)
    return -1


def _passes_covered(group: list[int], samples: list[list[tuple]]) -> int:
    return len({_pass_index(i, samples) for i in group})


def _keys_agree(a: tuple, b: tuple, line_tol: int) -> bool:
    pa, la, ca = a[0], int(a[1]), (a[2] if len(a) > 2 else None)
    pb, lb, cb = b[0], int(b[1]), (b[2] if len(b) > 2 else None)
    if _norm_path(pa).rsplit("/", 1)[-1] != _norm_path(pb).rsplit("/", 1)[-1]:
        return False
    if ca and cb and str(ca).upper() != str(cb).upper():
        return False
    return abs(la - lb) <= line_tol


# --- #7 evidence-quoting verdicts -------------------------------------------
_WS = re.compile(r"\s+")


def _canon(s: str) -> str:
    """Remove all whitespace and lowercase, so a quote matches the source
    regardless of the judge's re-indentation or spacing of code."""
    return _WS.sub("", (s or "")).lower()


def quote_is_grounded(quote: str, source: str, *, min_len: int = 8) -> bool:
    """True iff ``quote`` (a snippet the judge claims to have read) actually
    appears in ``source``, ignoring whitespace. Short/empty quotes fail -- a
    judge that can't cite at least a few real characters isn't grounded.
    """
    q = _canon(quote)
    if len(q) < min_len:
        return False
    return q in _canon(source)
