"""Internal data schema shared by stages, skills, and output emitters.

Pydantic v2 is used so we get free JSON serialisation for the
``run_manifest.json`` and the SARIF emitter doesn't have to hand-roll
validation.
"""

from __future__ import annotations

import enum
from datetime import datetime
from typing import Any

from pydantic import BaseModel, Field


class Severity(str, enum.Enum):
    """SARIF-aligned severity ordering.

    The string values match the SARIF ``level`` vocabulary so the SARIF
    emitter can pass them through verbatim.
    """

    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "informational"

    @property
    def numeric(self) -> int:
        """Higher = worse. Useful for sorting findings deterministically."""
        return {
            Severity.CRITICAL: 5,
            Severity.HIGH: 4,
            Severity.MEDIUM: 3,
            Severity.LOW: 2,
            Severity.INFO: 1,
        }[self]


class Location(BaseModel):
    """A single file:line[:end_line] reference attached to a finding."""

    path: str = Field(..., description="Repository-relative POSIX path.")
    start_line: int = Field(..., ge=1)
    end_line: int | None = Field(default=None, ge=1)
    snippet: str | None = Field(
        default=None, description="?25 lines of context for human reviewers."
    )


class Vote(BaseModel):
    """One model's vote on a candidate finding (used during S6 voting)."""

    role: str = Field(..., description="Logical role name from the profile.")
    model: str = Field(..., description="Concrete model identifier.")
    verdict: str = Field(..., description="confirm | reject | uncertain")
    rationale: str = Field(..., max_length=2000)


class TaintFlow(BaseModel):
    """The shape every research-lens finding must fill in.

    A vulnerability without a *source*, a *sink*, and a path between them is
    a vibe, not a finding. Forcing the lens to declare these three slots
    explicitly is the single biggest hallucination reducer in this harness:
    if the model can't name them, it shouldn't be writing the finding.
    """

    source: str | None = Field(
        default=None,
        description="Where attacker-controlled data enters (e.g. 'request.json[\"username\"]').",
    )
    source_location: Location | None = Field(
        default=None, description="Concrete file:line for the source."
    )
    sink: str | None = Field(
        default=None,
        description="The dangerous operation (e.g. 'db.execute(...)' or 'subprocess.run(...)').",
    )
    sink_location: Location | None = Field(
        default=None, description="Concrete file:line for the sink."
    )
    sanitizer_missing: bool | None = Field(
        default=None,
        description="True if the lens claims no sanitizer is present on the path.",
    )
    sanitizers_observed: list[str] = Field(
        default_factory=list,
        description="Sanitizers the lens *did* see on the path (helps disprove FPs).",
    )
    taint_path: list[Location] = Field(
        default_factory=list,
        description="Ordered list of locations the data flows through, source to sink.",
    )


class Evidence(BaseModel):
    """One piece of corroboration (or refutation) for a finding.

    The pipeline accumulates these as it runs. A finding is 'grounded' when
    it has at least one ``check == 'pass'`` Evidence whose ``kind`` is
    ``file_exists`` *and* one whose ``kind`` is ``snippet_match`` (or
    equivalent ground-truth signal). Findings without grounding evidence
    get their severity capped at ``MEDIUM`` and tagged ``weak-evidence``.
    """

    kind: str = Field(
        ...,
        description="file_exists | line_resolves | snippet_match | structural_hit | poc_runnable | reachable",
    )
    check: str = Field(..., description="pass | fail | unknown")
    detail: str = Field(default="", max_length=1000)


class ProofOfConcept(BaseModel):
    """Concrete demonstration that the finding is exploitable.

    A real PoC is a string the operator could paste into curl, a file, or
    a request body. A *generic* PoC ("send a malicious value") is treated
    as no PoC at all -- this is enforced by :class:`Finding.is_concrete_poc`.
    """

    payload: str = Field(default="", max_length=4000)
    invocation: str = Field(
        default="",
        max_length=2000,
        description="How to deliver the payload (curl line, function call, etc.).",
    )
    expected_effect: str = Field(default="", max_length=1000)
    is_concrete: bool = Field(
        default=False,
        description="True only if payload + invocation contain non-placeholder content.",
    )


class VerificationResult(BaseModel):
    """Final outcome-verification verdict for a finding (stage S8c).

    Collapses the independent signals earlier stages already gathered
    (grounding, taint completeness, concrete PoC, reachability, voter
    agreement) into a single auditable verdict. Deterministic by default,
    so it works identically on every backend -- including ones that reject
    ``temperature`` (Opus / cli) where multi-agent voting is a no-op.
    """

    verified: bool = False
    score: float = Field(
        default=0.0, ge=0.0, le=1.0, description="signals_passed / signals_considered"
    )
    signals: dict[str, bool] = Field(
        default_factory=dict,
        description="Per-signal pass/fail (grounded, taint_complete, concrete_poc, reachable, vote_confirmed).",
    )
    threshold: int = Field(
        default=3, ge=1, description="K independent signals required for verified=True."
    )
    method: str = Field(default="deterministic", description="deterministic | self_consistency")
    samples: int = Field(default=0, ge=0, description="Self-consistency samples taken (0 = none).")
    agreement: float | None = Field(
        default=None,
        ge=0.0,
        le=1.0,
        description="Fraction of self-consistency samples that confirmed.",
    )
    rationale: str = Field(default="", max_length=1000)


class Finding(BaseModel):
    """A single triage candidate produced by the pipeline.

    Findings are immutable once emitted — stages that ``refine`` a finding
    construct a new one with the same ``id`` and a bumped revision count.
    """

    id: str = Field(..., description="Stable per-run id (e.g. F-0001).")
    title: str = Field(..., max_length=200)
    severity: Severity
    cwe: str | None = Field(default=None, description="e.g. CWE-89")
    cvss_vector: str | None = Field(
        default=None,
        description="CVSS v3.1 vector string, e.g. CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N",
    )
    cvss_score: float | None = Field(
        default=None, ge=0.0, le=10.0, description="CVSS v3.1 base score 0-10."
    )
    description: str = Field(..., max_length=4000)
    locations: list[Location] = Field(default_factory=list, min_length=1)
    attack_chain: list[str] = Field(
        default_factory=list,
        description="Ordered narrative of how an attacker reaches the sink.",
    )
    remediation: str = Field(default="", max_length=2000)
    confidence: float = Field(default=0.5, ge=0.0, le=1.0)
    votes: list[Vote] = Field(default_factory=list)
    validator_verdict: str | None = Field(
        default=None, description="confirm | reject | uncertain (single-pass S6.5 validator)."
    )
    validator_rationale: str | None = Field(default=None, max_length=2000)
    # ---- hallucination-reduction layer (added in 0.3) -----------------
    taint: TaintFlow = Field(default_factory=TaintFlow)
    evidence: list[Evidence] = Field(
        default_factory=list,
        description="Pass/fail records produced by the grounding pass and other checks.",
    )
    grounded: bool = Field(
        default=False,
        description="True iff S4b grounding pass verified file + line + snippet.",
    )
    reachability: float | None = Field(
        default=None,
        ge=0.0,
        le=1.0,
        description="0..1 -- can an external entrypoint reach this sink? (None = not computed)",
    )
    poc: ProofOfConcept | None = Field(
        default=None, description="Concrete exploit demonstration (S8b)."
    )
    verification: VerificationResult | None = Field(
        default=None, description="Outcome-verification verdict (S8c)."
    )
    # ---- audit trail ---------------------------------------------------
    tags: list[str] = Field(default_factory=list)
    skill: str | None = Field(default=None, description="Producing skill name.")
    stage: str | None = Field(default=None, description="Producing stage id.")
    revision: int = Field(default=1, ge=1)

    def has_concrete_poc(self) -> bool:
        return self.poc is not None and self.poc.is_concrete

    def has_grounding_evidence(self) -> bool:
        return any(e.check == "pass" and e.kind == "snippet_match" for e in self.evidence)


class StageResult(BaseModel):
    """The output of one pipeline stage."""

    stage_id: str
    skill: str
    findings: list[Finding] = Field(default_factory=list)
    artifacts: dict[str, Any] = Field(default_factory=dict)
    duration_seconds: float = 0.0
    tokens_in: int = 0
    tokens_out: int = 0
    cost_usd: float = 0.0
    error: str | None = None


class RunManifest(BaseModel):
    """Audit record written next to every scan output."""

    tool: str = "redeye"
    version: str
    started_at: datetime
    ended_at: datetime | None = None
    profile: str
    config_hash: str
    target_repo: str
    target_sha: str | None = None
    application_id: str | None = None
    stages: list[StageResult] = Field(default_factory=list)
    total_cost_usd: float = 0.0
    finding_count: int = 0
    dropped_count: int = 0
    # ---- quality / hallucination metrics (added in 0.3) ---------------
    hallucination_metrics: dict[str, int] = Field(
        default_factory=dict,
        description=(
            "Counters surfaced by the grounding and PoC stages. Keys: "
            "raw_lens, ungrounded_dropped, ungrounded_downgraded, missing_poc, "
            "missing_taint, validator_rejected, voted_out."
        ),
    )
    # ---- incremental scan support -------------------------------------
    file_hashes: dict[str, str] = Field(
        default_factory=dict,
        description=(
            "Per-file content hashes (relative path -> sha256) for the scanned "
            "scope. Used by --incremental to skip unchanged files next run."
        ),
    )
    # ---- cost governance ----------------------------------------------
    max_budget_usd: float = Field(
        default=0.0, description="Global per-run budget ceiling (0 = unlimited)."
    )
    budget_exceeded: bool = Field(
        default=False,
        description="True if the run hit the global budget and skipped remaining paid stages.",
    )
