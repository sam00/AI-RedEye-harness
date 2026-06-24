"""The pipeline stages, one module each.

Each stage exposes a single ``run(ctx)`` callable that takes a
:class:`redeye.pipeline.orchestrator.StageContext` and returns a
:class:`redeye.schema.StageResult`.

S6b (validator) is optional -- it only runs if the profile lists it.
"""

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

__all__ = [
    "s1_attack_surface",
    "s1b_structural",
    "s2_threat_model",
    "s3_strategize",
    "s4_research",
    "s4b_grounding",
    "s5_policy_gate",
    "s6_adversarial",
    "s6b_validator",
    "s7_dedupe",
    "s8_chain",
    "s8b_poc",
    "s8c_verify",
    "s9_emit",
]
