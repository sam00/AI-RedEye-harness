"""Opt-in, on-disk cache for deterministic LLM completions (improvement E).

Repeat scans of a codebase re-issue near-identical prompts to paid backends.
When a call is *deterministic* -- ``temperature`` is ``None`` or ``0`` -- the
model is expected to return the same answer, so caching it is safe and can cut
real cost on CI re-runs and iterative development.

Design choices that keep this low-risk:

- **Opt-in only.** The orchestrator wraps a backend in :class:`CachingBackend`
  only when the operator passed ``--cache`` (or set ``REDEYE_LLM_CACHE``).
  Nothing caches by default, so runs stay reproducible-by-fresh-call unless
  asked otherwise.
- **Deterministic calls only.** Calls with ``temperature > 0`` bypass the
  cache entirely, so multi-sample self-consistency / voting diversity is never
  suppressed by a stale hit.
- **Content-addressed key.** The key hashes backend name, model, token cap,
  temperature, and the full ``system`` + ``user`` prompts. Any prompt change
  (including a changed structural index folded into the prompt) misses the
  cache and re-queries the model.
- **Honest cost accounting.** A cache hit reports ``cost_usd = 0.0`` for the
  current run (the spend already happened), so the manifest reflects real new
  spend. The originally-paid cost is preserved in ``raw`` for auditing.
"""

from __future__ import annotations

import hashlib
import json
import logging
import os
from pathlib import Path

from redeye.backends.base import BackendBase, CompletionResult
from redeye.redaction import redact_secrets

log = logging.getLogger(__name__)


def _key(
    *, name: str, model: str, system: str, user: str, max_tokens: int, temperature: float | None
) -> str:
    h = hashlib.sha256()
    for part in (name, model, str(max_tokens), str(temperature), system, user):
        h.update(part.encode("utf-8", errors="replace"))
        h.update(b"\x00")
    return h.hexdigest()


def _is_deterministic(temperature: float | None) -> bool:
    return temperature is None or temperature == 0 or temperature == 0.0


class CachingBackend(BackendBase):
    """Wrap a backend so deterministic completions are read/written to disk."""

    def __init__(self, inner: BackendBase, cache_dir: Path) -> None:
        super().__init__(getattr(inner, "options", {}) or {})
        self.inner = inner
        self.name = f"cached:{getattr(inner, 'name', 'backend')}"
        self.cache_dir = Path(cache_dir)
        self.cache_dir.mkdir(parents=True, exist_ok=True)
        try:
            os.chmod(self.cache_dir, 0o700)  # cached completions are private
        except OSError:
            pass
        self.hits = 0
        self.misses = 0

    # Delegate capability probes straight through -- caching never fakes creds.
    def has_credential(self) -> bool:
        return self.inner.has_credential()

    def health_check(self) -> bool:
        return self.inner.health_check()

    def _path_for(self, key: str) -> Path:
        return self.cache_dir / f"{key}.json"

    def complete(
        self,
        *,
        system: str,
        user: str,
        model: str,
        max_tokens: int,
        temperature: float | None,
    ) -> CompletionResult:
        if not _is_deterministic(temperature):
            # Preserve sampling diversity: never serve stochastic calls from cache.
            return self.inner.complete(
                system=system,
                user=user,
                model=model,
                max_tokens=max_tokens,
                temperature=temperature,
            )

        key = _key(
            name=getattr(self.inner, "name", "backend"),
            model=model,
            system=system,
            user=user,
            max_tokens=max_tokens,
            temperature=temperature,
        )
        path = self._path_for(key)
        if path.is_file():
            try:
                data = json.loads(path.read_text(encoding="utf-8"))
                self.hits += 1
                log.debug("llm cache hit %s", key[:12])
                return CompletionResult(
                    text=data.get("text", ""),
                    tokens_in=int(data.get("tokens_in", 0)),
                    tokens_out=int(data.get("tokens_out", 0)),
                    cost_usd=0.0,  # already paid on a prior run
                    model=data.get("model", model),
                    raw={"cache": "hit", "original_cost_usd": data.get("cost_usd", 0.0)},
                )
            except (OSError, json.JSONDecodeError):
                log.debug("llm cache read failed for %s; re-querying", key[:12])

        self.misses += 1
        result = self.inner.complete(
            system=system,
            user=user,
            model=model,
            max_tokens=max_tokens,
            temperature=temperature,
        )
        try:
            path.write_text(
                json.dumps(
                    {
                        # Model output can quote credentials from the scanned
                        # code -- never persist it raw.
                        "text": redact_secrets(result.text),
                        "tokens_in": result.tokens_in,
                        "tokens_out": result.tokens_out,
                        "cost_usd": result.cost_usd,
                        "model": result.model,
                    }
                ),
                encoding="utf-8",
            )
            os.chmod(path, 0o600)
        except OSError as exc:
            log.debug("llm cache write failed for %s: %s", key[:12], exc)
        return result
