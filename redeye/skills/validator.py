"""Single-pass validator skill (S6.5).

Pattern from ai-sast: a *separate* model runs one pass over each finding
and marks it true-positive / false-positive / uncertain. Findings marked
false-positive are dropped (preserved in the dropped-findings appendix);
findings marked uncertain pass through but get a tag.

This is conceptually different from S6 multi-agent voting:

- **Voting** is N-of-M: needs sampling diversity, used to suppress noise
  when temperature-capable backends are available.
- **Validator** is 1-of-1: deterministic gate, optimised for cheap models
  (Haiku, Gemini Flash) doing high-precision filtering.

In the 0.3 redesign, the validator also consumes the *grounding artifact*
attached to each finding by S4b. Findings whose grounding evidence
already failed (``hallucinated:bad-path``, ``hallucinated:bad-line``)
are auto-rejected without spending a token; findings tagged
``weak-evidence`` are downgraded but allowed through if the validator
otherwise confirms.
"""

from __future__ import annotations

import json
from pathlib import Path

from redeye.backends.base import BackendBase
from redeye.schema import Evidence, Finding
from redeye.skills._helpers import CompletionTotals, extract_json

_SYSTEM = """\
You are a precision filter for security findings. For each finding, decide
whether it is a true positive (real vulnerability), a false positive
(model hallucination, test fixture, or otherwise non-exploitable), or
uncertain.

You are given:

1. The candidate finding's title, severity, CWE, location, description,
   remediation, and (when available) its taint flow.
2. The deterministic grounding evidence already collected for it
   (file_exists / line_resolves / snippet_match results). Trust this
   evidence -- it was produced by reading the actual file.
3. The structural inventory's relevant entries for the finding's path.

Reply ONLY with a JSON object:
{"verdict": "confirm|reject|uncertain", "rationale": "..."}.

Rules:
- If the grounding evidence shows ``snippet_match: pass`` AND the taint
  flow has a plausible source + sink in real code, lean toward ``confirm``.
- If the grounding evidence shows any ``fail``, lean toward ``reject``.
- If a sanitizer is observed in the taint block that fully neutralises
  the source, ``reject``.
- If the finding's only evidence is the lens's prose, choose ``uncertain``.
- Be strict on test files, mock fixtures, generators, and example code:
  ``reject``.
"""


def _autoreject(finding: Finding) -> tuple[bool, str]:
    """Determine if a finding can be rejected without spending an LLM call."""
    if "hallucinated:bad-path" in finding.tags:
        return True, "auto-reject: cited path does not exist (S4b)"
    if "hallucinated:bad-line" in finding.tags:
        return True, "auto-reject: cited line does not resolve (S4b)"
    if "hallucinated:no-location" in finding.tags:
        return True, "auto-reject: no location information"
    return False, ""


def validate_findings(
    *,
    findings: list[Finding],
    target: Path,
    backend: BackendBase,
    model: str,
    temperature: float | None,
    max_tokens: int,
    max_budget_usd: float,
) -> tuple[list[Finding], list[Finding], CompletionTotals]:
    """Return (kept, rejected, totals).

    Findings marked ``confirm`` or ``uncertain`` are kept; findings marked
    ``reject`` are returned in ``rejected`` so the report can include them
    in the dropped-findings appendix.
    """
    totals = CompletionTotals()
    kept: list[Finding] = []
    rejected: list[Finding] = []

    for f in findings:
        # Deterministic floor: a finding asserted by the regex/AST structural
        # detectors (tag ``deterministic``) is corroborated by ground-truth
        # source, not model prose. A weak single-pass validator must NOT be
        # allowed to veto it -- that is exactly how true positives were lost
        # on local models. Confirm it for free and move on.
        if "deterministic" in f.tags:
            f.validator_verdict = "confirm"
            f.validator_rationale = "deterministic-floor: structurally corroborated; not subject to LLM veto"
            f.evidence.append(
                Evidence(kind="validator", check="pass", detail="deterministic floor (structural_hit)")
            )
            f.tags.append("validator:deterministic-floor")
            kept.append(f)
            continue

        # Auto-reject cases first -- saves tokens on hallucinations.
        auto, reason = _autoreject(f)
        if auto:
            f.validator_verdict = "reject"
            f.validator_rationale = reason
            f.tags.append("dropped:validator:auto-reject")
            f.evidence.append(Evidence(kind="validator", check="fail", detail=reason))
            rejected.append(f)
            continue

        primary = f.locations[0] if f.locations else None
        loc_str = f"{primary.path}:{primary.start_line}" if primary else "unknown"

        # Compose a compact dossier for the validator.
        evidence_summary = [
            {"kind": e.kind, "check": e.check, "detail": e.detail[:200]}
            for e in f.evidence[:8]
        ]
        taint_summary = {
            "source": f.taint.source,
            "sink": f.taint.sink,
            "sanitizer_missing": f.taint.sanitizer_missing,
            "sanitizers_observed": f.taint.sanitizers_observed[:5],
            "path_steps": len(f.taint.taint_path),
        }
        prompt = (
            f"Title: {f.title}\nSeverity: {f.severity.value}\nCWE: {f.cwe or 'unknown'}\n"
            f"Location: {loc_str}\nGrounded: {f.grounded}\n\n"
            f"Description:\n{f.description}\n\n"
            f"Remediation:\n{f.remediation or '(none)'}\n\n"
            f"Taint:\n{json.dumps(taint_summary, indent=2)}\n\n"
            f"Evidence collected:\n{json.dumps(evidence_summary, indent=2)}\n"
        )
        completion = backend.complete(
            system=_SYSTEM,
            user=prompt,
            model=model,
            max_tokens=max_tokens,
            temperature=temperature,
        )
        totals.add(
            tokens_in=completion.tokens_in,
            tokens_out=completion.tokens_out,
            cost_usd=completion.cost_usd,
        )
        parsed = extract_json(completion.text) or {}
        verdict = "uncertain"
        rationale = ""
        if isinstance(parsed, dict):
            verdict_raw = str(parsed.get("verdict", "uncertain")).lower()
            if verdict_raw in {"confirm", "reject", "uncertain"}:
                verdict = verdict_raw
            rationale = str(parsed.get("rationale", ""))[:1500]
        f.validator_verdict = verdict
        f.validator_rationale = rationale
        f.evidence.append(Evidence(kind="validator", check={"confirm": "pass", "reject": "fail"}.get(verdict, "unknown"), detail=rationale[:300]))
        if verdict == "reject":
            f.tags.append("dropped:validator:reject")
            rejected.append(f)
        else:
            if verdict == "uncertain":
                f.tags.append("validator:uncertain")
                f.confidence = min(f.confidence, 0.6)
            kept.append(f)
    return kept, rejected, totals
