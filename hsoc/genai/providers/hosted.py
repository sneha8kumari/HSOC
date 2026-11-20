"""
Hosted LLM provider (OpenAI-compatible API).

Activated when LLM_PROVIDER=hosted in .env.
All prompt and system inputs are strictly sanitised according to the per-provider
data-egress policy (PII, credentials, and RFC-1918 IPs masked) before transmission.
"""

from __future__ import annotations

import os
import time

from hsoc.genai.providers.base import BaseProvider, LLMResponse
from hsoc.genai.sanitize import sanitize_for_provider


class HostedProvider(BaseProvider):
    """OpenAI-compatible hosted LLM provider with mandatory data egress sanitization."""

    def __init__(self) -> None:
        self.base_url = os.getenv("HOSTED_LLM_BASE_URL", "https://api.openai.com/v1")
        self.api_key = os.getenv("HOSTED_LLM_API_KEY", "")
        self.model = os.getenv("HOSTED_LLM_MODEL", "gpt-4o-mini")

    def complete(
        self,
        prompt: str,
        system: str,
        temperature: float = 0.2,
    ) -> LLMResponse:
        """
        Send a chat completion request to the hosted provider.
        Enforces PII/secret redaction before any external payload egress.
        """
        # Strict pre-transmission redaction under hosted data-egress policy
        sanitized_prompt = sanitize_for_provider(prompt, provider="hosted")
        sanitized_system = sanitize_for_provider(system, provider="hosted")

        t0 = time.perf_counter()

        # If no API key is set (e.g. offline testing/CI), provide safe structured stub response
        if not self.api_key or self.api_key.startswith("mock") or self.api_key.startswith("test"):
            elapsed = time.perf_counter() - t0
            return LLMResponse(
                text="{}",
                model=self.model,
                latency_seconds=round(elapsed, 4),
            )

        # Real hosted LLM call using urllib / requests / httpx if credentials present
        import urllib.request
        import json

        payload = {
            "model": self.model,
            "temperature": temperature,
            "messages": [
                {"role": "system", "content": sanitized_system},
                {"role": "user", "content": sanitized_prompt},
            ],
            "response_format": {"type": "json_object"},
        }

        req = urllib.request.Request(
            f"{self.base_url.rstrip('/')}/chat/completions",
            data=json.dumps(payload).encode("utf-8"),
            headers={
                "Content-Type": "application/json",
                "Authorization": f"Bearer {self.api_key}",
            },
            method="POST",
        )

        try:
            with urllib.request.urlopen(req, timeout=30) as resp:
                data = json.loads(resp.read().decode("utf-8"))
                text = data["choices"][0]["message"]["content"]
        except Exception as exc:
            text = f'{{"error": "{str(exc)}"}}'

        elapsed = time.perf_counter() - t0
        return LLMResponse(
            text=text,
            model=self.model,
            latency_seconds=round(elapsed, 4),
        )
