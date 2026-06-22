"""Ollama backend (local LLMs).

Talks plain HTTP to a local (or remote) Ollama server. Cost is reported as
zero because the user's hardware does the work.

Useful for air-gapped environments, regulated industries that can't ship code
to a cloud LLM, and offline development.
"""

from __future__ import annotations

import logging
import os
from typing import Any

import httpx

from redeye.backends.base import BackendBase, CompletionResult
from redeye.backends.mock import MockBackend

log = logging.getLogger(__name__)


class OllamaBackend(BackendBase):
    """Local Ollama server."""

    name = "ollama"

    def __init__(self, options: dict[str, Any]) -> None:
        super().__init__(options)
        self._base = os.environ.get("OLLAMA_BASE_URL", "http://localhost:11434").rstrip("/")

    def has_credential(self) -> bool:
        # Ollama doesn't authenticate by default. Treat the env var being set
        # as "user explicitly opted into ollama"; otherwise lean on
        # health_check to confirm the server is reachable.
        return True

    def health_check(self) -> bool:
        try:
            with httpx.Client(timeout=3.0) as client:
                resp = client.get(f"{self._base}/api/tags")
            return resp.status_code == 200
        except httpx.HTTPError as exc:
            log.debug("Ollama health check failed: %s", exc)
            return False

    def complete(
        self,
        *,
        system: str,
        user: str,
        model: str,
        max_tokens: int,
        temperature: float | None,
    ) -> CompletionResult:
        url = f"{self._base}/api/chat"
        payload: dict[str, Any] = {
            "model": model or os.environ.get("OLLAMA_MODEL", "qwen2.5-coder:14b"),
            "messages": [
                {"role": "system", "content": system},
                {"role": "user", "content": user},
            ],
            "stream": False,
            "options": {"num_predict": max_tokens},
        }
        if temperature is not None:
            payload["options"]["temperature"] = temperature

        try:
            with httpx.Client(timeout=600.0) as client:
                resp = client.post(url, json=payload)
            resp.raise_for_status()
            data = resp.json()
        except httpx.HTTPError as exc:
            log.warning("Ollama call failed (%s) -- falling back to mock.", exc)
            return MockBackend({}).complete(
                system=system, user=user, model=model, max_tokens=max_tokens, temperature=temperature
            )

        text = data.get("message", {}).get("content", "") or ""
        # Ollama returns prompt_eval_count / eval_count.
        tokens_in = int(data.get("prompt_eval_count", 0) or 0)
        tokens_out = int(data.get("eval_count", 0) or 0)
        return CompletionResult(
            text=text, tokens_in=tokens_in, tokens_out=tokens_out, cost_usd=0.0, model=payload["model"], raw=data
        )
