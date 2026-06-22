"""OpenAI / OpenAI-compatible backend.

Works with the `openai` SDK against api.openai.com or any OpenAI-compatible
gateway (e.g. Azure OpenAI, vLLM, OpenRouter, internal corporate gateways)
via ``OPENAI_BASE_URL``.

Like the other backends, falls back to mock if the SDK or credentials are
missing.
"""

from __future__ import annotations

import logging
import os
from typing import Any

from redeye.backends.base import BackendBase, CompletionResult
from redeye.backends.mock import MockBackend

log = logging.getLogger(__name__)

_PRICE_PER_MTOK_IN = {"gpt-4o": 5.0, "gpt-4o-mini": 0.15}
_PRICE_PER_MTOK_OUT = {"gpt-4o": 15.0, "gpt-4o-mini": 0.60}


class OpenAIBackend(BackendBase):
    name = "openai"

    def __init__(self, options: dict[str, Any]) -> None:
        super().__init__(options)
        self._client: Any = None

    def has_credential(self) -> bool:
        return bool(os.environ.get("OPENAI_API_KEY"))

    def _get_client(self) -> Any | None:
        if self._client is not None:
            return self._client
        try:
            from openai import OpenAI  # type: ignore[import-not-found]
        except ImportError:
            log.warning(
                "openai SDK not installed (pip install redeye[openai]); "
                "falling back to mock backend for this call."
            )
            return None
        kwargs: dict[str, Any] = {"api_key": os.environ.get("OPENAI_API_KEY")}
        base_url = os.environ.get("OPENAI_BASE_URL")
        if base_url:
            kwargs["base_url"] = base_url
        self._client = OpenAI(**kwargs)
        return self._client

    def health_check(self) -> bool:
        if not self.has_credential():
            return False
        client = self._get_client()
        if client is None:
            return False
        try:
            client.models.list()
            return True
        except Exception as exc:  # noqa: BLE001
            log.debug("OpenAI health check failed: %s", exc)
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
        client = self._get_client()
        if client is None or not self.has_credential():
            return MockBackend({}).complete(
                system=system,
                user=user,
                model=model,
                max_tokens=max_tokens,
                temperature=temperature,
            )
        try:
            kwargs: dict[str, Any] = {
                "model": model,
                "max_tokens": max_tokens,
                "messages": [
                    {"role": "system", "content": system},
                    {"role": "user", "content": user},
                ],
            }
            if temperature is not None:
                kwargs["temperature"] = temperature
            resp = client.chat.completions.create(**kwargs)
        except Exception as exc:  # noqa: BLE001
            log.warning("OpenAI call failed (%s) — falling back to mock.", exc)
            return MockBackend({}).complete(
                system=system,
                user=user,
                model=model,
                max_tokens=max_tokens,
                temperature=temperature,
            )

        text = ""
        if resp.choices:
            text = resp.choices[0].message.content or ""

        usage = getattr(resp, "usage", None)
        tokens_in = getattr(usage, "prompt_tokens", 0) if usage else 0
        tokens_out = getattr(usage, "completion_tokens", 0) if usage else 0
        in_price = _PRICE_PER_MTOK_IN.get(model, 5.0) / 1_000_000
        out_price = _PRICE_PER_MTOK_OUT.get(model, 15.0) / 1_000_000
        cost = tokens_in * in_price + tokens_out * out_price
        return CompletionResult(
            text=text,
            tokens_in=tokens_in,
            tokens_out=tokens_out,
            cost_usd=cost,
            model=model,
            raw=resp,
        )
