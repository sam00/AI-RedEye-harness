"""Google Cloud Vertex AI backend (Gemini).

Lazy-imports the Vertex SDK so it stays optional. Falls back to mock if
the SDK or credentials are missing.
"""

from __future__ import annotations

import logging
import os
from typing import Any

from redeye.backends.base import BackendBase, CompletionResult
from redeye.backends.mock import MockBackend

log = logging.getLogger(__name__)

# Approximate Vertex prices per million tokens.
_PRICE_PER_MTOK_IN = {"gemini-2.5-pro": 1.25, "gemini-2.5-flash": 0.30, "gemini-1.5-pro": 1.25}
_PRICE_PER_MTOK_OUT = {"gemini-2.5-pro": 5.0, "gemini-2.5-flash": 2.50, "gemini-1.5-pro": 5.0}


class VertexBackend(BackendBase):
    """Vertex AI / Gemini."""

    name = "vertex"

    def __init__(self, options: dict[str, Any]) -> None:
        super().__init__(options)
        self._initialised = False

    def has_credential(self) -> bool:
        return bool(
            os.environ.get("GOOGLE_CLOUD_PROJECT")
            and (
                os.environ.get("GOOGLE_APPLICATION_CREDENTIALS")
                or os.environ.get("GOOGLE_TOKEN")
                or os.path.exists(
                    os.path.expanduser("~/.config/gcloud/application_default_credentials.json")
                )
            )
        )

    def _ensure_init(self) -> bool:
        if self._initialised:
            return True
        try:
            import vertexai  # type: ignore[import-not-found]
        except ImportError:
            log.warning(
                "google-cloud-aiplatform not installed (pip install redeye[vertex]); "
                "falling back to mock backend for this call."
            )
            return False
        project = os.environ.get("GOOGLE_CLOUD_PROJECT")
        location = os.environ.get("GOOGLE_LOCATION", "us-central1")
        if not project:
            return False
        try:
            vertexai.init(project=project, location=location)
            self._initialised = True
            return True
        except Exception as exc:  # noqa: BLE001
            log.warning("Vertex init failed: %s", exc)
            return False

    def health_check(self) -> bool:
        if not self.has_credential():
            return False
        return self._ensure_init()

    def complete(
        self,
        *,
        system: str,
        user: str,
        model: str,
        max_tokens: int,
        temperature: float | None,
    ) -> CompletionResult:
        if not self._ensure_init():
            return MockBackend({}).complete(
                system=system,
                user=user,
                model=model,
                max_tokens=max_tokens,
                temperature=temperature,
            )
        try:
            from vertexai.generative_models import (  # type: ignore[import-not-found]
                GenerationConfig,
                GenerativeModel,
            )
        except ImportError:
            return MockBackend({}).complete(
                system=system,
                user=user,
                model=model,
                max_tokens=max_tokens,
                temperature=temperature,
            )

        try:
            gen_model = GenerativeModel(model_name=model, system_instruction=system)
            cfg_kwargs: dict[str, Any] = {"max_output_tokens": max_tokens}
            if temperature is not None:
                cfg_kwargs["temperature"] = temperature
            resp = gen_model.generate_content(
                user, generation_config=GenerationConfig(**cfg_kwargs)
            )
        except Exception as exc:  # noqa: BLE001
            log.warning("Vertex generate_content failed (%s) -- falling back to mock.", exc)
            return MockBackend({}).complete(
                system=system,
                user=user,
                model=model,
                max_tokens=max_tokens,
                temperature=temperature,
            )

        text = getattr(resp, "text", "") or ""
        usage = getattr(resp, "usage_metadata", None)
        tokens_in = getattr(usage, "prompt_token_count", 0) if usage else 0
        tokens_out = getattr(usage, "candidates_token_count", 0) if usage else 0
        in_price = _PRICE_PER_MTOK_IN.get(model, 1.25) / 1_000_000
        out_price = _PRICE_PER_MTOK_OUT.get(model, 5.0) / 1_000_000
        cost = tokens_in * in_price + tokens_out * out_price
        return CompletionResult(
            text=text,
            tokens_in=tokens_in,
            tokens_out=tokens_out,
            cost_usd=cost,
            model=model,
            raw=resp,
        )
