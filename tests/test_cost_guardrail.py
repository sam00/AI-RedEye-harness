"""Global per-run cost guardrail predicate tests."""

from __future__ import annotations

from redeye.pipeline.orchestrator import _skip_for_budget


def test_no_budget_never_skips() -> None:
    assert (
        _skip_for_budget(total_cost=99.0, stage_budget=5.0, stage_id="s4_research", max_budget=0.0)
        is False
    )


def test_under_budget_runs() -> None:
    assert (
        _skip_for_budget(total_cost=1.0, stage_budget=5.0, stage_id="s4_research", max_budget=5.0)
        is False
    )


def test_over_budget_skips_paid_stage() -> None:
    assert (
        _skip_for_budget(
            total_cost=5.0, stage_budget=4.0, stage_id="s6_adversarial", max_budget=5.0
        )
        is True
    )


def test_over_budget_keeps_free_stage() -> None:
    # Deterministic (zero-budget) stages keep running.
    assert (
        _skip_for_budget(total_cost=5.0, stage_budget=0.0, stage_id="s4b_grounding", max_budget=5.0)
        is False
    )


def test_emit_always_runs() -> None:
    assert (
        _skip_for_budget(total_cost=99.0, stage_budget=0.1, stage_id="s9_emit", max_budget=5.0)
        is False
    )
