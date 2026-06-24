"""Pipeline orchestrator -- runs all 9 stages, gathers results, writes outputs.

The orchestrator owns the *flow* but knows almost nothing about the *content*
of each stage. Each stage is a callable that takes a :class:`StageContext`
and returns a :class:`StageResult`. This keeps the orchestrator stable while
the skills evolve.
"""

from __future__ import annotations

import logging
import subprocess
import time
from collections.abc import Callable
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from rich.console import Console

from redeye import __version__
from redeye.backends import BACKENDS, BackendBase
from redeye.config import Profile
from redeye.pipeline.stages import (
    s1_attack_surface,
    s1b_structural,
    s2_threat_model,
    s3_strategize,
    s4_research,
    s4b_grounding,
    s5_policy_gate,
    s6_adversarial,
    s6b_validator,
    s7_dedupe,
    s8_chain,
    s8b_poc,
    s8c_verify,
    s9_emit,
)
from redeye.pipeline.voting import vote_on_findings
from redeye.schema import Finding, RunManifest, StageResult
from redeye.scope import Scope

log = logging.getLogger(__name__)

_STAGE_ORDER: list[tuple[str, Callable[..., StageResult]]] = [
    ("s1_attack_surface", s1_attack_surface.run),
    ("s1b_structural", s1b_structural.run),  # optional; deterministic, no LLM
    ("s2_threat_model", s2_threat_model.run),
    ("s3_strategize", s3_strategize.run),
    ("s4_research", s4_research.run),
    ("s4b_grounding", s4b_grounding.run),  # optional; deterministic, no LLM
    ("s5_policy_gate", s5_policy_gate.run),
    ("s6_adversarial", s6_adversarial.run),
    ("s6b_validator", s6b_validator.run),  # optional
    ("s7_dedupe", s7_dedupe.run),
    ("s8_chain", s8_chain.run),
    ("s8b_poc", s8b_poc.run),  # optional; demands concrete PoC
    ("s8c_verify", s8c_verify.run),  # optional; deterministic outcome verification
    ("s9_emit", s9_emit.run),
]


@dataclass
class StageContext:
    """Everything a stage skill needs to do its job."""

    stage_id: str
    profile: Profile
    target: Path
    output_dir: Path
    application_id: str | None
    findings: list[Finding] = field(default_factory=list)
    artifacts: dict[str, Any] = field(default_factory=dict)
    dry_run: bool = False
    scope: Scope | None = None
    custom_prompt: str = ""
    feedback: list[dict[str, Any]] = field(default_factory=list)

    def get_backend(self, role_name: str) -> tuple[BackendBase, str, float | None, int]:
        role = self.profile.roles[role_name]
        factory = BACKENDS[role.via]
        backend = factory({})
        return backend, role.model, role.temperature, role.max_tokens


class Orchestrator:
    def __init__(
        self,
        *,
        config: Profile,
        console: Console,
        target: Path,
        output_dir: Path,
        application_id: str | None,
        dry_run: bool = False,
        scope: Scope | None = None,
        custom_prompt: str = "",
        feedback: list[dict[str, Any]] | None = None,
    ) -> None:
        self.config = config
        self.console = console
        self.target = target.resolve()
        self.output_dir = output_dir
        self.application_id = application_id
        self.dry_run = dry_run
        self.scope = scope
        self.custom_prompt = custom_prompt
        self.feedback = feedback or []

    def _resolve_target_sha(self) -> str | None:
        try:
            out = subprocess.run(
                ["git", "rev-parse", "HEAD"],
                cwd=self.target,
                capture_output=True,
                text=True,
                timeout=5,
                check=False,
            )
            if out.returncode == 0:
                return out.stdout.strip()
        except (subprocess.SubprocessError, OSError):
            pass
        return None

    def run(self) -> RunManifest:
        manifest = RunManifest(
            version=__version__,
            started_at=datetime.now(timezone.utc),
            profile=self.config.name,
            config_hash=self.config.config_hash(),
            target_repo=str(self.target),
            target_sha=self._resolve_target_sha(),
            application_id=self.application_id,
        )

        ctx = StageContext(
            stage_id="",
            profile=self.config,
            target=self.target,
            output_dir=self.output_dir,
            application_id=self.application_id,
            dry_run=self.dry_run,
            scope=self.scope,
            custom_prompt=self.custom_prompt,
            feedback=self.feedback,
        )

        all_findings: list[Finding] = []
        dropped: list[Finding] = []

        for stage_id, stage_fn in _STAGE_ORDER:
            stage_cfg = self.config.stages.get(stage_id)
            if stage_cfg is None:
                log.info("Stage %s not in profile; skipping.", stage_id)
                continue

            ctx.stage_id = stage_id
            ctx.findings = list(all_findings)
            # Make the running hallucination metrics visible to S9.
            ctx.artifacts["_hallucination_metrics"] = dict(manifest.hallucination_metrics)
            self.console.print(f"  [dim]> {stage_id}[/dim]")
            start = time.monotonic()

            try:
                result = stage_fn(ctx)
            except Exception as exc:  # noqa: BLE001
                log.exception("stage %s crashed", stage_id)
                result = StageResult(
                    stage_id=stage_id,
                    skill=stage_cfg.skill,
                    error=f"{type(exc).__name__}: {exc}",
                )

            result.duration_seconds = time.monotonic() - start
            manifest.stages.append(result)
            manifest.total_cost_usd += result.cost_usd

            # Propagate artifacts forward so e.g. S2 sees S1's attack_surface.
            ctx.artifacts.update(result.artifacts)

            if stage_id == "s4_research":
                all_findings.extend(result.findings)
                manifest.hallucination_metrics["raw_lens"] = manifest.hallucination_metrics.get(
                    "raw_lens", 0
                ) + len(result.findings)
            elif stage_id == "s4b_grounding":
                # Grounding either drops (strict mode) or just tags. In both
                # cases ``result.findings`` is what survives.
                report = result.artifacts.get("grounding_report", {}) or {}
                manifest.hallucination_metrics.setdefault("ungrounded_dropped", 0)
                manifest.hallucination_metrics["ungrounded_dropped"] += int(
                    report.get("dropped", 0)
                )
                manifest.hallucination_metrics["ungrounded_downgraded"] = (
                    manifest.hallucination_metrics.get("ungrounded_downgraded", 0)
                    + int(report.get("weak_evidence", 0))
                )
                # Findings dropped by S4b in strict mode go into the dropped pile.
                pre = {f.id for f in all_findings}
                post = {f.id for f in result.findings}
                drop_ids = pre - post
                if drop_ids:
                    dropped.extend(f for f in all_findings if f.id in drop_ids)
                all_findings = result.findings
            elif stage_id == "s5_policy_gate":
                all_findings = result.findings
            elif stage_id == "s6_adversarial":
                # First swap in the adversarial-refined records...
                all_findings = result.findings or all_findings
                # ...then run the multi-agent voter, partitioning into kept/dropped.
                vote_outcome = vote_on_findings(all_findings, self.config)
                all_findings = vote_outcome.kept
                # Voting can drop additional findings beyond what S4b/S5 dropped;
                # extend rather than replace so earlier drops are preserved.
                dropped.extend(vote_outcome.dropped)
                result.artifacts["voting_kept"] = len(vote_outcome.kept)
                result.artifacts["voting_dropped"] = len(vote_outcome.dropped)
                manifest.hallucination_metrics["voted_out"] = manifest.hallucination_metrics.get(
                    "voted_out", 0
                ) + len(vote_outcome.dropped)
            elif stage_id == "s6b_validator":
                # Validator partitions: kept survives, rejected goes to the
                # dropped pile so the report can show why each one died.
                pre_ids = {f.id for f in all_findings}
                post_ids = {f.id for f in result.findings}
                rejected_now = [f for f in all_findings if f.id in (pre_ids - post_ids)]
                dropped.extend(rejected_now)
                all_findings = result.findings
                manifest.hallucination_metrics["validator_rejected"] = (
                    manifest.hallucination_metrics.get("validator_rejected", 0) + len(rejected_now)
                )
            elif stage_id == "s7_dedupe":
                all_findings = result.findings
                # Baseline filter: drop findings the operator already
                # accepted in ``.redeye-baseline.yaml``. No-op when the
                # file doesn't exist.
                from redeye.baseline import Baseline, filter_findings

                baseline = Baseline.load(self.target)
                if baseline.entries:
                    kept, filtered = filter_findings(all_findings, baseline)
                    all_findings = kept
                    if filtered:
                        result.artifacts["baseline_filtered"] = len(filtered)
                        manifest.hallucination_metrics["baseline_filtered"] = (
                            manifest.hallucination_metrics.get("baseline_filtered", 0)
                            + len(filtered)
                        )
                        dropped.extend(filtered)
            elif stage_id == "s8_chain":
                all_findings = result.findings or all_findings
            elif stage_id == "s8b_poc":
                all_findings = result.findings
                metrics = result.artifacts.get("poc_metrics", {}) or {}
                manifest.hallucination_metrics["missing_poc"] = manifest.hallucination_metrics.get(
                    "missing_poc", 0
                ) + int(metrics.get("no_poc_demoted", 0))
            elif stage_id == "s8c_verify":
                vmetrics = result.artifacts.get("verification_metrics", {}) or {}
                pre_ids = {f.id for f in all_findings}
                post_ids = {f.id for f in result.findings}
                dropped_now = [f for f in all_findings if f.id in (pre_ids - post_ids)]
                all_findings = result.findings
                if dropped_now:
                    dropped.extend(dropped_now)
                    manifest.hallucination_metrics["outcome_unverified_dropped"] = (
                        manifest.hallucination_metrics.get("outcome_unverified_dropped", 0)
                        + len(dropped_now)
                    )
                manifest.hallucination_metrics["outcome_unverified"] = (
                    manifest.hallucination_metrics.get("outcome_unverified", 0)
                    + int(vmetrics.get("unverified", 0))
                )
            elif stage_id == "s9_emit":
                result.artifacts["finding_count"] = len(all_findings)
                result.artifacts["dropped_count"] = len(dropped)
                result.artifacts["_hallucination_metrics"] = dict(manifest.hallucination_metrics)

        manifest.ended_at = datetime.now(timezone.utc)
        manifest.finding_count = len(all_findings)
        manifest.dropped_count = len(dropped)

        from redeye.output.manifest import write_manifest

        write_manifest(self.output_dir, manifest)
        return manifest
