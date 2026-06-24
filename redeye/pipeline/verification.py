"""Outcome-verification layer (stage S8c).

This module turns the independent signals that earlier stages already
gathered for each finding -- grounding evidence (S4b), taint completeness
(S4), a concrete PoC (S8b), computed reachability, and voter/validator
agreement (S6 / S6.5) -- into a single auditable verdict.

It is *deterministic*: no LLM call is required, so verification behaves
identically on every backend, including ones that reject ``temperature``
(Opus / cli) where multi-agent voting is a no-op. A finding is ``verified``
when at least ``threshold`` of the independent signals pass. The calling
stage decides what to do with unverified findings (flag, or drop under
``--require-verified``).

The core below is intentionally backend-free so it can be unit-tested in
isolation; the S8c stage wires it into the pipeline and records metrics.
"""

from __future__ import annotations

from dataclasses import dataclass

from redeye.schema import Finding, VerificationResult

# Independent signals, named + ordered so the per-finding ``signals`` dict is
# stable and easy to render in the report. Each is derived from state a
# *different* stage produced, so the verdict cross-checks the pipeline
# against itself rather than trusting any single stage.
SIGNAL_NAMES: tuple[str, ...] = (
    "grounded",
    "taint_complete",
    "concrete_poc",
    "reachable",
    "vote_confirmed",
)


@dataclass
class VerificationConfig:
    """Knobs for the outcome-verification layer."""

    threshold: int = 3  # K-of-N independent signals required for verified=True
    reachable_threshold: float = 0.5

    def __post_init__(self) -> None:
        n = len(SIGNAL_NAMES)
        if not 1 <= self.threshold <= n:
            raise ValueError(f"threshold must be between 1 and {n}, got {self.threshold}")


def deterministic_signals(finding: Finding, *, reachable_threshold: float = 0.5) -> dict[str, bool]:
    """Compute the independent pass/fail signals for a finding."""
    taint = finding.taint
    taint_complete = bool(
        (taint.source or taint.source_location) and (taint.sink or taint.sink_location)
    )
    vote_confirmed = any(v.verdict == "confirm" for v in finding.votes) or (
        finding.validator_verdict == "confirm"
    )
    reachable = finding.reachability is not None and finding.reachability >= reachable_threshold
    return {
        "grounded": bool(finding.grounded or finding.has_grounding_evidence()),
        "taint_complete": taint_complete,
        "concrete_poc": finding.has_concrete_poc(),
        "reachable": reachable,
        "vote_confirmed": bool(vote_confirmed),
    }


def verify_finding(finding: Finding, cfg: VerificationConfig | None = None) -> VerificationResult:
    """Produce a deterministic :class:`VerificationResult` for one finding."""
    cfg = cfg or VerificationConfig()
    signals = deterministic_signals(finding, reachable_threshold=cfg.reachable_threshold)
    passed = sum(1 for ok in signals.values() if ok)
    considered = len(signals)
    passing = [name for name, ok in signals.items() if ok]
    rationale = (
        f"{passed}/{considered} independent signals passed "
        f"(need {cfg.threshold}): {', '.join(passing) or 'none'}."
    )
    return VerificationResult(
        verified=passed >= cfg.threshold,
        score=round(passed / considered, 3) if considered else 0.0,
        signals=signals,
        threshold=cfg.threshold,
        method="deterministic",
        rationale=rationale,
    )


def verify_findings(
    findings: list[Finding], cfg: VerificationConfig | None = None
) -> list[Finding]:
    """Attach a :class:`VerificationResult` to every finding (in place).

    Returns the same list for chaining. The caller decides what to do with
    unverified findings (flag / drop).
    """
    cfg = cfg or VerificationConfig()
    for finding in findings:
        finding.verification = verify_finding(finding, cfg)
    return findings
