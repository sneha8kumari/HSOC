"""
Base class for LLM providers.

All providers must implement ``complete(prompt, system, temperature)``.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass


@dataclass
class LLMResponse:
    """Raw response from a provider."""

    text: str
    model: str
    latency_seconds: float


class BaseProvider(ABC):
    """Abstract LLM provider interface."""

    @abstractmethod
    def complete(
        self,
        prompt: str,
        system: str,
        temperature: float = 0.2,
    ) -> LLMResponse:
        """
        Send a prompt and return the model response.

        Args:
            prompt: The user-turn prompt text.
            system: The system-turn instructions.
            temperature: Sampling temperature (0.0–1.0).

        Returns:
            ``LLMResponse`` with text, model name and wall-clock latency.
        """
        ...
