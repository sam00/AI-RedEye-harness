"""Shared lens runner. Each lens just picks a system prompt and a name.

The 0.3 redesign forces lenses to:

1. Reason about the *structural inventory* (real routes / sources / sinks
   pre-extracted by S1b) rather than imagine where bugs live.
2. Return a strict JSON shape that includes an explicit ``taint`` block --
   no source + sink claim => the finding is rejected as hand-wavy.
3. Cite *real* file:line ranges -- the grounding pass (S4b) verifies each
   one by reading the file. Hallucinated paths get tagged and (in strict
   mode) dropped.
4. List the evidence they relied on, including any *negative* evidence
   ("I checked for a sanitizer; none was present"). Negative evidence is
   how we distinguish "real bug" from "vibes".
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from redeye.backends.base import BackendBase, CompletionResult
from redeye.schema import Evidence, Finding, Location, Severity, TaintFlow
from redeye.skills._helpers import extract_json


def _normalise_severity(value: Any) -> Severity:
    if isinstance(value, Severity):
        return value
    if isinstance(value, str):
        try:
            return Severity(value.lower())
        except ValueError:
            mapping = {
                "crit": Severity.CRITICAL,
                "high": Severity.HIGH,
                "med": Severity.MEDIUM,
                "low": Severity.LOW,
                "info": Severity.INFO,
                "informational": Severity.INFO,
            }
            return mapping.get(value.lower(), Severity.MEDIUM)
    return Severity.MEDIUM


def _location_from(
    record: dict[str, Any], *, key_path: str = "path", key_line: str = "start_line"
) -> Location | None:
    p = record.get(key_path) or record.get("file")
    if not p:
        return None
    try:
        start = int(record.get(key_line) or record.get("line") or 1)
    except (TypeError, ValueError):
        start = 1
    end = record.get("end_line")
    try:
        end_int = int(end) if end is not None else None
    except (TypeError, ValueError):
        end_int = None
    return Location(path=str(p), start_line=start, end_line=end_int, snippet=record.get("snippet"))


def _extract_taint(record: dict[str, Any]) -> TaintFlow:
    """Pull the ``taint`` sub-object out of the lens response.

    Accepts either a fully-typed taint block or a flatter shape. We're
    permissive in what we read but strict in what we eventually emit.
    """
    raw = record.get("taint") or {}
    if not isinstance(raw, dict):
        raw = {}

    def _maybe_loc(key: str) -> Location | None:
        sub = raw.get(key)
        if isinstance(sub, dict):
            return _location_from(sub)
        return None

    sanitizer_missing = raw.get("sanitizer_missing")
    if isinstance(sanitizer_missing, str):
        sanitizer_missing = sanitizer_missing.lower() in {"true", "yes", "1"}

    sanitizers_observed = raw.get("sanitizers_observed") or []
    if not isinstance(sanitizers_observed, list):
        sanitizers_observed = []

    taint_path_raw = raw.get("taint_path") or []
    taint_path: list[Location] = []
    if isinstance(taint_path_raw, list):
        for step in taint_path_raw[:20]:
            if isinstance(step, dict):
                loc = _location_from(step)
                if loc is not None:
                    taint_path.append(loc)

    return TaintFlow(
        source=str(raw.get("source") or "")[:300] or None,
        source_location=_maybe_loc("source_location"),
        sink=str(raw.get("sink") or "")[:300] or None,
        sink_location=_maybe_loc("sink_location"),
        sanitizer_missing=sanitizer_missing if isinstance(sanitizer_missing, bool) else None,
        sanitizers_observed=[str(s)[:200] for s in sanitizers_observed[:10]],
        taint_path=taint_path,
    )


def _record_to_finding(record: dict[str, Any], lens_name: str) -> Finding | None:
    title = (record.get("title") or "").strip()
    if not title:
        return None

    primary = _location_from(record)
    if primary is None:
        # No file:line at all -> the lens is hand-waving. Skip.
        return None

    cvss_score_raw = record.get("cvss_score")
    try:
        cvss_score: float | None = float(cvss_score_raw) if cvss_score_raw is not None else None
    except (TypeError, ValueError):
        cvss_score = None

    taint = _extract_taint(record)

    # Convert the lens's self-reported evidence list into Evidence rows. We
    # keep this lightweight; the canonical evidence comes from S4b.
    evidence: list[Evidence] = []
    raw_evidence = record.get("evidence") or []
    if isinstance(raw_evidence, list):
        for item in raw_evidence[:10]:
            if isinstance(item, dict):
                evidence.append(
                    Evidence(
                        kind=str(item.get("kind", "lens-claim"))[:64],
                        check=str(item.get("check", "unknown"))[:16],
                        detail=str(item.get("detail", ""))[:1000],
                    )
                )
            elif isinstance(item, str):
                evidence.append(Evidence(kind="lens-claim", check="unknown", detail=item[:1000]))

    return Finding(
        id="",  # orchestrator stamps this
        title=title[:200],
        severity=_normalise_severity(record.get("severity")),
        cwe=record.get("cwe"),
        cvss_vector=record.get("cvss_vector") or record.get("cvss") or None,
        cvss_score=cvss_score,
        description=str(record.get("description") or "")[:4000],
        locations=[primary],
        attack_chain=record.get("attack_chain") or [],
        remediation=str(record.get("remediation") or "")[:2000],
        confidence=float(record.get("confidence", 0.5) or 0.5),
        skill=lens_name,
        taint=taint,
        evidence=evidence,
    )


_BASE_RULES = """\
You are a precision-first security researcher. You are reasoning about a
codebase whose *structural inventory* (the real routes, sources, and sinks
pre-extracted by deterministic regex/AST) is provided as ground truth.

Constraints, in priority order:

1. Cite ONLY file:line locations that exist in the structural inventory or
   in files you have inspected. Inventing paths is a hard fail.
2. Every finding MUST include a ``taint`` block with ``source``, ``sink``,
   and an explicit ``sanitizer_missing`` boolean (or null if you genuinely
   cannot decide). Findings without a taint shape will be dropped.
3. Use the inventory's ``cwe`` hint when emitting findings around a sink.
4. Prefer NO finding to a hand-wavy finding. The pipeline penalises false
   positives more heavily than misses (FPs train the feedback loop and
   poison future runs).
5. State sanitizers/validators that you DID observe in
   ``taint.sanitizers_observed`` -- this is how you disprove your own
   suspicion when the code is actually safe.
6. Keep ``description`` <= 600 characters. Be terse and concrete.

Output strict JSON:

{
  "findings": [
    {
      "title": str,
      "severity": "critical|high|medium|low|informational",
      "cwe": "CWE-NNN",
      "cvss_vector": "CVSS:3.1/AV:N/...",      // optional but preferred
      "cvss_score": float,                     // 0..10, optional
      "path": "src/...",
      "start_line": int,
      "end_line": int,
      "description": str,
      "remediation": str,
      "confidence": 0..1,
      "taint": {
        "source": str,                         // e.g. "request.json['username']"
        "source_location": {"path": "...", "start_line": int},
        "sink": str,                           // e.g. "cursor.execute(query)"
        "sink_location": {"path": "...", "start_line": int},
        "sanitizer_missing": bool,
        "sanitizers_observed": [str, ...],
        "taint_path": [{"path": "...", "start_line": int}, ...]
      },
      "evidence": [
        {"kind": "structural_hit|reads_pattern|negative_observation",
         "check": "pass|fail|unknown",
         "detail": str}
      ]
    }
  ]
}
"""


def run_lens(
    *,
    lens_name: str,
    system_prompt: str,
    target: Path,
    attack_surface: dict[str, Any],
    research_plan: dict[str, Any],
    backend: BackendBase,
    model: str,
    temperature: float | None,
    max_tokens: int,
    max_budget_usd: float,
    extra_system: str = "",
    feedback: list[dict[str, Any]] | None = None,
    structural_index: dict[str, Any] | None = None,
) -> tuple[list[Finding], CompletionResult]:
    composed_system = system_prompt + "\n\n" + _BASE_RULES
    if extra_system:
        composed_system += f"\n\n# Operator-supplied instructions\n{extra_system.strip()}"

    if feedback:
        bullets = []
        for entry in feedback[:25]:
            verdict = entry.get("verdict", "?")
            title = entry.get("title", "")[:80]
            cwe = entry.get("cwe", "")
            path = entry.get("path", "")[:60]
            bullets.append(f"- [{verdict}] {cwe} {title} ({path})")
        composed_system += (
            "\n\n# Prior reviewer feedback (calibrate confidence; "
            "FPs here are repeat hallucinations to AVOID)\n" + "\n".join(bullets)
        )

    user_parts = [f"Target repo: {target}"]
    if structural_index:
        # Structural inventory is the ground truth -- list it in full so the
        # lens cites real paths.
        user_parts.append(
            "Structural inventory (deterministically extracted -- "
            "treat as ground truth, do not invent additional paths):\n"
            + json.dumps(structural_index, indent=2)[:8000]
        )
    user_parts.extend(
        [
            "Attack surface (LLM-derived, may be incomplete -- prefer the structural inventory above):\n"
            + json.dumps(attack_surface, indent=2)[:2000],
            "Research plan:\n" + json.dumps(research_plan, indent=2)[:2000],
            f"Run the {lens_name} lens. Reply with the strict JSON object described "
            "in your system instructions. If you have nothing to report, return "
            '{"findings": []}.',
        ]
    )
    user = "\n\n".join(user_parts)

    completion = backend.complete(
        system=composed_system,
        user=user,
        model=model,
        max_tokens=max_tokens,
        temperature=temperature,
    )
    parsed = extract_json(completion.text) or {}
    findings: list[Finding] = []
    if isinstance(parsed, dict):
        for record in parsed.get("findings") or []:
            if isinstance(record, dict):
                f = _record_to_finding(record, lens_name)
                if f is not None:
                    findings.append(f)
    return findings, completion
