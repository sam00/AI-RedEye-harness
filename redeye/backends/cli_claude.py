"""Claude Code CLI backend.

Shells out to the `claude` binary, feeding the prompt on stdin and
collecting stdout. We deliberately keep this single-pass and non-streaming
so the orchestrator can treat it like any other backend.

If the `claude` binary or login is missing, we degrade to the mock backend's
behaviour (with a clear warning) rather than hard-failing — this keeps the
pipeline runnable on every developer's laptop.
"""

from __future__ import annotations

import logging
import os
import shutil
import subprocess
from typing import Any

from tenacity import (
    Retrying,
    retry_if_exception_type,
    stop_after_attempt,
    wait_exponential,
)

from redeye.backends.base import BackendBase, CompletionResult
from redeye.backends.mock import MockBackend

log = logging.getLogger(__name__)

# Approximate price (USD per million tokens) for cost reporting only. Real
# pricing depends on the model and any private-gateway markup; users should
# override this in their profile if the number matters.
_DEFAULT_PRICE_PER_MTOK = 6.0


def _degrade_to_mock(
    *, system: str, user: str, model: str, max_tokens: int, temperature: float | None
) -> CompletionResult:
    """Run the deterministic mock and label the result truthfully.

    Provenance/manifest must record that this stage ran on ``mock`` -- not the
    model that was *requested* but never actually produced the output.
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


class ClaudeCliBackend(BackendBase):
    """Wraps the `claude` CLI."""

    name = "cli"

    def has_credential(self) -> bool:
        if os.environ.get("CLAUDE_CODE_OAUTH_TOKEN"):
            return True
        return shutil.which("claude") is not None

    def health_check(self) -> bool:
        if not self.has_credential():
            return False
        binary = shutil.which("claude")
        if binary is None:
            return False
        try:
            result = subprocess.run(
                [binary, "--version"], capture_output=True, text=True, timeout=5, check=False
            )
            return result.returncode == 0
        except (subprocess.SubprocessError, OSError):
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
        binary = shutil.which("claude")
        if binary is None or not self.has_credential():
            log.error(
                "claude CLI not available — STAGE DEGRADED TO MOCK; provenance records "
                "model='mock'. Run `claude login` or set CLAUDE_CODE_OAUTH_TOKEN to use "
                "the real CLI."
            )
            return _degrade_to_mock(
                system=system,
                user=user,
                model=model,
                max_tokens=max_tokens,
                temperature=temperature,
            )

        cmd: list[Any] = [
            binary,
            "-p",
            "--model",
            model or "claude-sonnet-5",
            "--system-prompt",
            system,
            "--output-format",
            "text",
        ]
        # Current Claude Code CLI does not expose --max-tokens; output length is
        # governed by the model and optional --max-budget-usd (not wired here).

        def _run_cli() -> subprocess.CompletedProcess[str]:
            return subprocess.run(
                cmd,
                input=user,
                capture_output=True,
                text=True,
                timeout=600,
                check=False,
            )

        try:
            # Retry only the transient case (the CLI subprocess timing out); any
            # other SubprocessError is a hard failure -> mock fallback.
            retryer = Retrying(
                retry=retry_if_exception_type(subprocess.TimeoutExpired),
                stop=stop_after_attempt(3),
                wait=wait_exponential(multiplier=1, max=10),
                reraise=True,
            )
            proc = retryer(_run_cli)
        except subprocess.SubprocessError as exc:
            log.error(
                "claude CLI invocation failed (%s) — STAGE DEGRADED TO MOCK; "
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

        if proc.returncode != 0:
            log.error(
                "claude CLI exited %d (%s) — STAGE DEGRADED TO MOCK; provenance records "
                "model='mock', not the requested %r.",
                proc.returncode,
                proc.stderr[:300],
                model,
            )
            return _degrade_to_mock(
                system=system,
                user=user,
                model=model,
                max_tokens=max_tokens,
                temperature=temperature,
            )

        text = proc.stdout
        approx_in = len(system.split()) + len(user.split())
        approx_out = len(text.split())
        cost = (approx_in + approx_out) * (_DEFAULT_PRICE_PER_MTOK / 1_000_000)
        return CompletionResult(
            text=text,
            tokens_in=approx_in,
            tokens_out=approx_out,
            cost_usd=cost,
            model=model,
            raw=proc,
        )
