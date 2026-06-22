"""LLM backend registry.

Each backend implements :class:`redeye.backends.base.BackendBase`
and registers itself in :data:`BACKENDS` below. The orchestrator looks up
the backend for a role by name (``role.via``) and never instantiates a
class directly -- that's how new backends get plugged in without touching
the pipeline code.
"""

from __future__ import annotations

from collections.abc import Callable
from typing import Any

from redeye.backends.base import BackendBase
from redeye.backends.bedrock import BedrockBackend
from redeye.backends.cli_claude import ClaudeCliBackend
from redeye.backends.mock import MockBackend
from redeye.backends.ollama import OllamaBackend
from redeye.backends.openai_compat import OpenAIBackend
from redeye.backends.sdk_anthropic import AnthropicSdkBackend
from redeye.backends.vertex import VertexBackend

BACKENDS: dict[str, Callable[[dict[str, Any]], BackendBase]] = {
    "mock": MockBackend,
    "cli": ClaudeCliBackend,
    "sdk": AnthropicSdkBackend,
    "openai": OpenAIBackend,
    "bedrock": BedrockBackend,
    "vertex": VertexBackend,
    "ollama": OllamaBackend,
}

__all__ = ["BACKENDS", "BackendBase"]
