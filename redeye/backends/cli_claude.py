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

from redeye.backends.base import BackendBase, CompletionResult
from redeye.backends.mock import MockBackend

log = logging.getLogger(__name__)

# Approximate price (USD per million tokens) for cost reporting only. Real
# pricing depends on the model and any private-gateway markup; users should
# override this in their profile if the number matters.
_DEFAULT_PRICE_PER_MTOK = 6.0


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
            log.warning(
                "claude CLI not available; falling back to mock backend for this call. "
                "Run `claude login` or set CLAUDE_CODE_OAUTH_TOKEN to use the real CLI."
            )
            return MockBackend({}).complete(
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
            model or "claude-sonnet-4-6",
            "--system-prompt",
            system,
            "--output-format",
            "text",
        ]
        # Current Claude Code CLI does not expose --max-tokens; output length is
        # governed by the model and optional --max-budget-usd (not wired here).

        try:
            proc = subprocess.run(
                cmd,
                input=user,
                capture_output=True,
                text=True,
                timeout=600,
                check=False,
            )
        except subprocess.SubprocessError as exc:
            log.warning("claude CLI invocation failed: %s — falling back to mock.", exc)
            return MockBackend({}).complete(
                system=system,
                user=user,
                model=model,
                max_tokens=max_tokens,
                temperature=temperature,
            )

        if proc.returncode != 0:
            log.warning(
                "claude CLI exited %d: %s — falling back to mock.",
                proc.returncode,
                proc.stderr[:300],
            )
            return MockBackend({}).complete(
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
