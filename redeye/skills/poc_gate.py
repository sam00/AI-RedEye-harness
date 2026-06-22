"""PoC gate skill (S8b).

Asks the model to write a *concrete* exploit string for each finding. We
parse the result and decide whether the PoC counts as concrete using
syntactic checks -- it must contain at least one of: a quoted payload, a
URL/path, an HTTP verb, a structured body, an injection metacharacter
(quote, backtick, semicolon, ``../``, ``${``, ``<script``).

If we cannot produce a concrete PoC, the finding is *not* dropped --
some bugs are real and yet hard to demo in a one-shot prompt -- but its
severity is capped one notch (HIGH -> MEDIUM, MEDIUM -> LOW) and it's
tagged ``no-poc``. This is intentional: we'd rather keep a real bug
without a payload than drop it.

This skill is *cheap*: the prompt is short and Haiku-class models do it well.
"""

from __future__ import annotations

import re
from pathlib import Path

from redeye.backends.base import BackendBase
from redeye.schema import Evidence, Finding, ProofOfConcept, Severity
from redeye.skills._helpers import CompletionTotals, extract_json

_SYSTEM = """\
You write proof-of-concept payloads for confirmed security findings.

Given a finding, return a JSON object:

{
  "payload": "<concrete attacker-controlled string -- quotes, separators, real keys>",
  "invocation": "<exact one-line curl / function call that delivers it>",
  "expected_effect": "<what you expect to observe (DB error, file read, RCE, etc.)>"
}

DO NOT use placeholders like 'malicious_input', '<exploit_here>', or 'TBD'.
If you genuinely cannot construct a PoC (e.g. there's no network reachability),
return {"payload": "", "invocation": "", "expected_effect": "no-poc-possible: <why>"}.
"""


# A PoC is "concrete" if it contains at least one of these signals.
_CONCRETE_SIGNALS = [
    re.compile(r"['\"][^'\"]{2,}['\"]"),                 # quoted string
    re.compile(r"https?://"),                             # URL
    re.compile(r"\b(curl|wget|http|GET|POST|PUT|DELETE|PATCH)\b"),
    re.compile(r"[`;|]"),                                 # shell injection metacharacters
    re.compile(r"\.\./"),                                 # path traversal
    re.compile(r"\$\{|<\?|<%"),                           # template injection
    re.compile(r"<script", re.IGNORECASE),                # XSS
    re.compile(r"\bUNION\b|\bSELECT\b|\bDROP\b", re.IGNORECASE),  # SQLi
    re.compile(r"jwt|token|cookie|session", re.IGNORECASE),
]
_PLACEHOLDER_SIGNALS = [
    re.compile(r"<[a-z_]+_?here>", re.IGNORECASE),
    re.compile(r"\bTODO\b|\bTBD\b|\bplaceholder\b", re.IGNORECASE),
    re.compile(r"malicious_input|some_payload|EXAMPLE", re.IGNORECASE),
]


def _is_concrete(payload: str, invocation: str) -> bool:
    blob = f"{payload}\n{invocation}"
    if not blob.strip():
        return False
    if any(p.search(blob) for p in _PLACEHOLDER_SIGNALS):
        return False
    return any(p.search(blob) for p in _CONCRETE_SIGNALS)


def _demote(severity: Severity) -> Severity:
    return {
        Severity.CRITICAL: Severity.HIGH,
        Severity.HIGH: Severity.MEDIUM,
        Severity.MEDIUM: Severity.LOW,
        Severity.LOW: Severity.INFO,
        Severity.INFO: Severity.INFO,
    }[severity]


def gate_findings(
    *,
    findings: list[Finding],
    target: Path,
    backend: BackendBase,
    model: str,
    temperature: float | None,
    max_tokens: int,
    max_budget_usd: float,
) -> tuple[list[Finding], CompletionTotals, dict[str, int]]:
    """Run the PoC gate. Returns (findings, totals, metrics)."""
    totals = CompletionTotals()
    metrics = {"with_poc": 0, "no_poc_demoted": 0}

    for f in findings:
        # Deterministic findings are corroborated structurally; a missing or
        # non-concrete PoC must NOT demote their severity. Keep any PoC the
        # detector already attached and skip the gate entirely.
        if "deterministic" in f.tags:
            if f.poc is not None and f.poc.is_concrete:
                metrics["with_poc"] += 1
                f.evidence.append(
                    Evidence(kind="poc_runnable", check="pass", detail="deterministic PoC")
                )
                f.tags.append("poc:concrete")
            else:
                f.tags.append("poc:deterministic-floor")
            continue

        # Skip findings that already failed grounding hard -- no point asking
        # for a PoC against fictional code.
        if "hallucinated:bad-path" in f.tags or "hallucinated:bad-line" in f.tags:
            f.tags.append("no-poc:hallucinated")
            f.severity = _demote(f.severity)
            metrics["no_poc_demoted"] += 1
            continue

        primary = f.locations[0] if f.locations else None
        prompt = (
            f"Title: {f.title}\nSeverity: {f.severity.value}\nCWE: {f.cwe or 'unknown'}\n"
            f"Location: {primary.path}:{primary.start_line}\n" if primary else ""
        )
        prompt += f"\nDescription:\n{f.description}\n"
        if f.taint and (f.taint.source or f.taint.sink):
            prompt += (
                f"\nKnown taint flow:\n  source: {f.taint.source or '?'}\n"
                f"  sink: {f.taint.sink or '?'}\n"
                f"  sanitizer_missing: {f.taint.sanitizer_missing}\n"
            )

        try:
            completion = backend.complete(
                system=_SYSTEM, user=prompt, model=model, max_tokens=max_tokens, temperature=temperature
            )
        except Exception:  # noqa: BLE001 -- backend errors must never crash the pipeline
            f.tags.append("no-poc:backend-error")
            f.severity = _demote(f.severity)
            f.evidence.append(Evidence(kind="poc_runnable", check="fail", detail="backend error"))
            metrics["no_poc_demoted"] += 1
            continue

        totals.add(
            tokens_in=completion.tokens_in,
            tokens_out=completion.tokens_out,
            cost_usd=completion.cost_usd,
        )

        parsed = extract_json(completion.text) or {}
        if not isinstance(parsed, dict):
            parsed = {}
        payload = str(parsed.get("payload", "") or "")[:4000]
        invocation = str(parsed.get("invocation", "") or "")[:2000]
        expected = str(parsed.get("expected_effect", "") or "")[:1000]
        is_concrete = _is_concrete(payload, invocation)

        f.poc = ProofOfConcept(
            payload=payload,
            invocation=invocation,
            expected_effect=expected,
            is_concrete=is_concrete,
        )
        if is_concrete:
            metrics["with_poc"] += 1
            f.evidence.append(Evidence(kind="poc_runnable", check="pass", detail=expected[:120]))
            f.tags.append("poc:concrete")
        else:
            metrics["no_poc_demoted"] += 1
            f.evidence.append(
                Evidence(
                    kind="poc_runnable",
                    check="fail",
                    detail=f"no concrete PoC: {expected[:160]}",
                )
            )
            f.tags.append("no-poc:placeholder")
            f.severity = _demote(f.severity)
    return findings, totals, metrics
