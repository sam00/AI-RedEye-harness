"""Abstract base for all LLM backends."""

from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass
from typing import Any


@dataclass
class CompletionResult:
    """The minimal contract every backend returns to the orchestrator."""

    text: str
    tokens_in: int = 0
    tokens_out: int = 0
    cost_usd: float = 0.0
    model: str = ""
    raw: Any = None


class BackendBase(ABC):
    """Implement this to plug a new LLM provider into the harness."""

    name: str = "base"

    def __init__(self, options: dict[str, Any]) -> None:
        self.options = options

    @abstractmethod
    def has_credential(self) -> bool:
        """Return True if the credential the backend needs is present."""

    @abstractmethod
    def health_check(self) -> bool:
        """Best-effort liveness probe. Should not require an LLM call.

        Implementations may make a cheap network call (e.g. ``GET /v1/models``)
        but must time out within ~5 seconds and never raise.
        """

    @abstractmethod
    def complete(
        self,
        *,
        system: str,
        user: str,
        model: str,
        max_tokens: int,
        temperature: float | None,
    ) -> CompletionResult:
        """Run a single non-streaming completion."""
