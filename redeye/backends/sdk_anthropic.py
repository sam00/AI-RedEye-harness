"""Anthropic SDK backend.

Imports `anthropic` lazily so the dependency only matters when this backend
is actually used. Like the CLI backend, it gracefully degrades to the mock
backend when credentials or the SDK are missing.
"""

from __future__ import annotations

import logging
import os
from typing import Any

import httpx
from tenacity import (
    Retrying,
    retry_if_exception,
    stop_after_attempt,
    wait_exponential,
)

from redeye.backends.base import BackendBase, CompletionResult
from redeye.backends.mock import MockBackend

log = logging.getLogger(__name__)

# Best-effort price table. Override in the profile if precision matters.
_PRICE_PER_MTOK_IN = {
    "claude-sonnet-5": 3.0,
    "claude-haiku-4-5-20251001": 0.80,
    "claude-opus-4-8": 15.0,
    "claude-fable-5": 10.0,
}
_PRICE_PER_MTOK_OUT = {
    "claude-sonnet-5": 15.0,
    "claude-haiku-4-5-20251001": 4.0,
    "claude-opus-4-8": 75.0,
    "claude-fable-5": 50.0,
}

# The only valid Anthropic model ids (mid-2026). The SDK forwards the id to the
# API verbatim; an unknown id 400s and this backend silently degrades to mock,
# so we warn loudly before the call whenever the id isn't recognised.
KNOWN_MODEL_IDS = {
    "claude-opus-4-8",
    "claude-sonnet-5",
    "claude-haiku-4-5-20251001",
    "claude-fable-5",
}


def _is_transient_error(exc: BaseException) -> bool:
    """True only for errors worth retrying: timeouts, connection drops, 429, 5xx.

    Everything else (a 400 from a bad model id, auth failures, etc.) is a hard
    error and must fall straight through to the mock fallback -- retrying it
    would just waste time and money.
    """
    if isinstance(exc, (httpx.TimeoutException, httpx.TransportError)):
        return True
    status = getattr(exc, "status_code", None)
    if isinstance(status, int) and (status == 429 or status >= 500):
        return True
    name = type(exc).__name__.lower()
    return any(k in name for k in ("timeout", "connection", "ratelimit"))


def _degrade_to_mock(
    *, system: str, user: str, model: str, max_tokens: int, temperature: float | None
) -> CompletionResult:
    """Run the deterministic mock and label the result truthfully.

    The manifest/provenance must record that this stage ran on ``mock`` -- not
    the model that was *requested* but never actually produced the output.
    """
    result = MockBackend({}).complete(
        system=system,
        user=user,
        model=model,
        max_tokens=max_tokens,
        temperature=temperature,
    )
    result.model = "mock"
    return result


class AnthropicSdkBackend(BackendBase):
    name = "sdk"

    def __init__(self, options: dict[str, Any]) -> None:
        super().__init__(options)
        self._client: Any = None

    def has_credential(self) -> bool:
        return bool(os.environ.get("ANTHROPIC_SDK_API_KEY") or os.environ.get("ANTHROPIC_API_KEY"))

    def _get_client(self) -> Any | None:
        if self._client is not None:
            return self._client
        try:
            import anthropic  # type: ignore[import-not-found]
        except ImportError:
            log.warning(
                "anthropic SDK not installed (pip install redeye[sdk]); "
                "falling back to mock backend for this call."
            )
            return None
        api_key = os.environ.get("ANTHROPIC_SDK_API_KEY") or os.environ.get("ANTHROPIC_API_KEY")
        base_url = os.environ.get("ANTHROPIC_SDK_BASE_URL") or os.environ.get("ANTHROPIC_BASE_URL")
        kwargs: dict[str, Any] = {"api_key": api_key}
        if base_url:
            kwargs["base_url"] = base_url
        self._client = anthropic.Anthropic(**kwargs)
        return self._client

    def health_check(self) -> bool:
        if not self.has_credential():
            return False
        client = self._get_client()
        if client is None:
            return False
        # The SDK has no cheap "ping" endpoint; we trust credential presence
        # and let the first real call fail loudly if the gateway is down.
        return True

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
            log.error(
                "Anthropic SDK unavailable (missing SDK or credential) — "
                "STAGE DEGRADED TO MOCK; provenance records model='mock', not %r.",
                model,
            )
            return _degrade_to_mock(
                system=system,
                user=user,
                model=model,
                max_tokens=max_tokens,
                temperature=temperature,
            )

        if model not in KNOWN_MODEL_IDS:
            log.warning("unrecognized Anthropic model id %r — may 400 and fall back to mock", model)

        kwargs: dict[str, Any] = {
            "model": model,
            "max_tokens": max_tokens,
            "system": system,
            "messages": [{"role": "user", "content": user}],
        }
        if temperature is not None:
            kwargs["temperature"] = temperature

        try:
            retryer = Retrying(
                retry=retry_if_exception(_is_transient_error),
                stop=stop_after_attempt(3),
                wait=wait_exponential(multiplier=1, max=10),
                reraise=True,
            )
            resp = retryer(client.messages.create, **kwargs)
        except Exception as exc:  # noqa: BLE001
            log.error(
                "Anthropic SDK call failed after retries (%s) — STAGE DEGRADED TO MOCK; "
                "provenance records model='mock', not the requested %r.",
                exc,
                model,
            )
            return _degrade_to_mock(
                system=system,
                user=user,
                model=model,
                max_tokens=max_tokens,
                temperature=temperature,
            )

        text_parts = []
        for block in getattr(resp, "content", []) or []:
            block_text = getattr(block, "text", None)
            if block_text:
                text_parts.append(block_text)
        text = "\n".join(text_parts)

        usage = getattr(resp, "usage", None)
        tokens_in = getattr(usage, "input_tokens", 0) if usage else 0
        tokens_out = getattr(usage, "output_tokens", 0) if usage else 0
        in_price = _PRICE_PER_MTOK_IN.get(model, 3.0) / 1_000_000
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
