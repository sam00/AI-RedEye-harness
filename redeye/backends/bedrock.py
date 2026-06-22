"""AWS Bedrock backend (Claude / Llama / Titan via Bedrock).

Lazy-imports `boto3` so it stays optional (`pip install redeye[bedrock]`).
Falls back to mock if boto3 or AWS credentials are missing.
"""

from __future__ import annotations

import json
import logging
import os
from typing import Any

from redeye.backends.base import BackendBase, CompletionResult
from redeye.backends.mock import MockBackend

log = logging.getLogger(__name__)

# Approximate Bedrock list-prices per million tokens. Override in profiles
# if precision matters.
_PRICE_PER_MTOK_IN = {
    "anthropic.claude-opus-4-5-20251101-v1:0": 15.0,
    "anthropic.claude-3-5-sonnet-20241022-v2:0": 3.0,
    "anthropic.claude-3-haiku-20240307-v1:0": 0.25,
}
_PRICE_PER_MTOK_OUT = {
    "anthropic.claude-opus-4-5-20251101-v1:0": 75.0,
    "anthropic.claude-3-5-sonnet-20241022-v2:0": 15.0,
    "anthropic.claude-3-haiku-20240307-v1:0": 1.25,
}


class BedrockBackend(BackendBase):
    """AWS Bedrock via boto3."""

    name = "bedrock"

    def __init__(self, options: dict[str, Any]) -> None:
        super().__init__(options)
        self._client: Any = None
        self._region = os.environ.get("AWS_REGION", "us-east-1")

    def has_credential(self) -> bool:
        # boto3's chain handles env vars, ~/.aws/, IAM role, SSO. We surface
        # the simple cases here for `doctor`; absence of explicit env vars
        # doesn't mean failure (an EC2 instance role would still work).
        return bool(
            os.environ.get("AWS_ACCESS_KEY_ID")
            or os.environ.get("AWS_SESSION_TOKEN")
            or os.environ.get("AWS_PROFILE")
            or os.path.expanduser("~/.aws/credentials")
        )

    def _get_client(self) -> Any | None:
        if self._client is not None:
            return self._client
        try:
            import boto3  # type: ignore[import-not-found]
        except ImportError:
            log.warning(
                "boto3 not installed (pip install redeye[bedrock]); "
                "falling back to mock backend for this call."
            )
            return None
        try:
            self._client = boto3.client("bedrock-runtime", region_name=self._region)
            return self._client
        except Exception as exc:  # noqa: BLE001
            log.warning("bedrock client init failed: %s", exc)
            return None

    def health_check(self) -> bool:
        if not self.has_credential():
            return False
        client = self._get_client()
        if client is None:
            return False
        try:
            # `list_foundation_models` lives on `bedrock`, not `bedrock-runtime`.
            # We do a cheap STS get-caller-identity instead.
            import boto3  # type: ignore[import-not-found]

            boto3.client("sts", region_name=self._region).get_caller_identity()
            return True
        except Exception as exc:  # noqa: BLE001
            log.debug("bedrock health check failed: %s", exc)
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
        if client is None:
            return MockBackend({}).complete(
                system=system,
                user=user,
                model=model,
                max_tokens=max_tokens,
                temperature=temperature,
            )

        # Bedrock's Anthropic invocation uses the messages API shape.
        body: dict[str, Any] = {
            "anthropic_version": "bedrock-2023-05-31",
            "max_tokens": max_tokens,
            "system": system,
            "messages": [{"role": "user", "content": user}],
        }
        if temperature is not None:
            body["temperature"] = temperature

        try:
            resp = client.invoke_model(
                modelId=model,
                body=json.dumps(body),
                contentType="application/json",
                accept="application/json",
            )
        except Exception as exc:  # noqa: BLE001
            log.warning("Bedrock invoke_model failed (%s) -- falling back to mock.", exc)
            return MockBackend({}).complete(
                system=system,
                user=user,
                model=model,
                max_tokens=max_tokens,
                temperature=temperature,
            )

        try:
            payload = json.loads(resp["body"].read())
        except Exception as exc:  # noqa: BLE001
            log.warning("Bedrock response parse failed (%s) -- falling back to mock.", exc)
            return MockBackend({}).complete(
                system=system,
                user=user,
                model=model,
                max_tokens=max_tokens,
                temperature=temperature,
            )

        text_parts: list[str] = []
        for block in payload.get("content", []) or []:
            if isinstance(block, dict) and block.get("type") == "text":
                text_parts.append(block.get("text", ""))
        text = "\n".join(text_parts)

        usage = payload.get("usage", {}) or {}
        tokens_in = int(usage.get("input_tokens", 0) or 0)
        tokens_out = int(usage.get("output_tokens", 0) or 0)
        in_price = _PRICE_PER_MTOK_IN.get(model, 3.0) / 1_000_000
        out_price = _PRICE_PER_MTOK_OUT.get(model, 15.0) / 1_000_000
        cost = tokens_in * in_price + tokens_out * out_price
        return CompletionResult(
            text=text,
            tokens_in=tokens_in,
            tokens_out=tokens_out,
            cost_usd=cost,
            model=model,
            raw=payload,
        )
