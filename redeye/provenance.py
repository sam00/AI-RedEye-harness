"""Per-finding provenance stamping (improvement #10).

For a finding to be *auditable* and *reproducible* -- the backbone of
"verified" output in a regulated environment -- the run must record exactly
how it was produced: which model, the exact prompt (by hash, so secrets in
the prompt never hit disk), the sampling parameters, and the hash of the
deterministic structural index the lens reasoned over. Combined with the
``mock`` backend, this makes any finding reproducible and any run auditable.

Pure ``hashlib``; no schema import, so it is unit-testable in isolation. The
stamp is a plain ``dict[str, str]`` that lands in ``Finding.provenance`` and
therefore flows into ``run_manifest.json`` for free.
"""

from __future__ import annotations

import hashlib


def _sha256(text: str) -> str:
    return hashlib.sha256((text or "").encode("utf-8", errors="replace")).hexdigest()


def make_stamp(
    *,
    model: str,
    prompt: str,
    temperature: float | None = None,
    seed: int | None = None,
    structural_index: str | None = None,
) -> dict[str, str]:
    """Build a provenance stamp. ``structural_index`` may be the raw index
    text (it will be hashed) or an already-computed hash."""
    stamp = {
        "model": str(model or "unknown"),
        "prompt_sha256": _sha256(prompt),
        "temperature": "none" if temperature is None else str(temperature),
        "seed": "none" if seed is None else str(seed),
    }
    if structural_index is not None:
        # Heuristic: a 64-char hex string is already a hash; otherwise hash it.
        is_hash = len(structural_index) == 64 and all(
            c in "0123456789abcdef" for c in structural_index.lower()
        )
        stamp["structural_index_sha"] = (
            structural_index.lower() if is_hash else _sha256(structural_index)
        )
    return stamp


def stamp_findings(
    findings: list,
    *,
    model: str,
    prompt: str,
    temperature: float | None = None,
    seed: int | None = None,
    structural_index: str | None = None,
) -> int:
    """Attach a provenance stamp to every finding lacking one. Returns count
    stamped. Existing stamps are preserved (a later stage that refined the
    finding keeps the original producer's provenance)."""
    stamp = make_stamp(
        model=model,
        prompt=prompt,
        temperature=temperature,
        seed=seed,
        structural_index=structural_index,
    )
    n = 0
    for f in findings:
        if not getattr(f, "provenance", None):
            f.provenance = dict(stamp)
            n += 1
    return n
