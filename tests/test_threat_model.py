"""S2 threat-model config knob tests (max_threats, baseline, evidence caps)."""

from __future__ import annotations

import json
from pathlib import Path

from redeye.backends.base import CompletionResult
from redeye.skills.threat_modeler import _build_evidence, build_threat_model


class _StubBackend:
    """Returns a fixed STRIDE doc and records the prompt it was given."""

    def __init__(self, stride: list[dict]) -> None:
        self._stride = stride
        self.last_user = ""

    def complete(self, *, system, user, model, max_tokens, temperature):  # type: ignore[no-untyped-def]
        self.last_user = user
        payload = {"actors": ["anon"], "stride": self._stride, "top_risks": ["r"]}
        return CompletionResult(text=json.dumps(payload), tokens_in=10, tokens_out=5)


def _make(stride):  # type: ignore[no-untyped-def]
    return _StubBackend(stride)


def test_max_threats_caps_output(tmp_path: Path) -> None:
    stride = [{"category": f"S{i}", "asset": f"a{i}"} for i in range(10)]
    backend = _make(stride)
    doc, _ = build_threat_model(
        target=tmp_path,
        attack_surface={"entrypoints": ["/login"]},
        backend=backend,
        model="x",
        temperature=0.0,
        max_tokens=512,
        max_budget_usd=0.0,
        params={"max_threats": 3},
    )
    assert len(doc["stride"]) == 3


def test_baseline_subtracts_accepted(tmp_path: Path) -> None:
    baseline = tmp_path / "threats.yaml"
    baseline.write_text(
        "accepted:\n  - {category: Spoofing, asset: login}\n", encoding="utf-8"
    )
    stride = [
        {"category": "Spoofing", "asset": "login"},
        {"category": "Tampering", "asset": "db"},
    ]
    backend = _make(stride)
    doc, _ = build_threat_model(
        target=tmp_path,
        attack_surface={},
        backend=backend,
        model="x",
        temperature=0.0,
        max_tokens=512,
        max_budget_usd=0.0,
        params={"baseline": str(baseline)},
    )
    cats = {t["category"] for t in doc["stride"]}
    assert "Spoofing" not in cats
    assert "Tampering" in cats


def test_evidence_caps_limit_prompt() -> None:
    index = {
        "routes": [{"path": f"r{i}.py", "snippet": f"/r{i}"} for i in range(10)],
        "secrets": [{"path": f"s{i}.py", "line": i} for i in range(10)],
        "sources": [],
        "sinks": [],
    }
    evidence = _build_evidence(
        {"entrypoints": [f"/e{i}" for i in range(10)]},
        index,
        {"modules": 0, "entry_points": 2, "config_reps": 3, "api_artifacts": 4},
    )
    assert len(evidence["entry_points"]) == 2
    assert len(evidence["config_reps"]) == 3
    assert len(evidence["api_artifacts"]) == 4


def test_evidence_injected_into_prompt(tmp_path: Path) -> None:
    backend = _make([{"category": "S", "asset": "a"}])
    index = {"routes": [{"path": "app.py", "snippet": "/login"}], "secrets": [], "sources": [], "sinks": []}
    build_threat_model(
        target=tmp_path,
        attack_surface={"entrypoints": ["/login"]},
        backend=backend,
        model="x",
        temperature=0.0,
        max_tokens=512,
        max_budget_usd=0.0,
        structural_index=index,
        params={"max_entry_points": 5},
    )
    assert "Structural evidence" in backend.last_user
