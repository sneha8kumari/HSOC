"""
Ollama Provider — Local LLM Backend for H-SOC.

Connects to a local Ollama instance with configurable endpoint, model, and timeout.
Environment variables:
  OLLAMA_HOST             (default: http://localhost:11434)
  OLLAMA_MODEL            (default: llama3.1:8b)
  OLLAMA_TIMEOUT_SECONDS  (default: 30.0)
"""

from __future__ import annotations

import json
import logging
import os
import time
from typing import Any
import urllib.error
import urllib.request

from hsoc.genai.providers.base import BaseProvider, LLMResponse

logger = logging.getLogger(__name__)


class OllamaProvider(BaseProvider):
    """Calls a locally running Ollama server with health checks, retries, and timeout safety."""

    def __init__(
        self,
        host: str | None = None,
        model: str | None = None,
        timeout_seconds: float | None = None,
    ) -> None:
        self.host = (host or os.getenv("OLLAMA_HOST", "http://localhost:11434")).rstrip("/")
        self.model = model or os.getenv("OLLAMA_MODEL", "llama3.1:8b")
        env_timeout = os.getenv("OLLAMA_TIMEOUT_SECONDS")
        self.timeout = float(timeout_seconds or (float(env_timeout) if env_timeout else 30.0))

    def check_health(self) -> dict[str, Any]:
        """
        Check if Ollama server is running and which models are installed.
        Does not raise exceptions; returns health status dictionary.
        """
        url = f"{self.host}/api/tags"
        req = urllib.request.Request(url, method="GET")

        try:
            with urllib.request.urlopen(req, timeout=3.0) as resp:
                body = resp.read().decode("utf-8")
                data = json.loads(body)
                models = [m.get("name") for m in data.get("models", [])]
                model_ready = any(self.model in m for m in models)
                return {
                    "provider": "ollama",
                    "status": "ONLINE" if model_ready else "MODEL_MISSING",
                    "host": self.host,
                    "target_model": self.model,
                    "model_installed": model_ready,
                    "installed_models": models,
                    "message": "Ollama service is reachable and ready." if model_ready else f"Ollama is running, but model '{self.model}' is not pulled yet (run 'ollama pull {self.model}').",
                }
        except Exception as exc:
            return {
                "provider": "ollama",
                "status": "OFFLINE",
                "host": self.host,
                "target_model": self.model,
                "model_installed": False,
                "installed_models": [],
                "message": f"Ollama server not reachable at {self.host} ({str(exc)}).",
            }

    def complete(
        self,
        prompt: str,
        system: str,
        temperature: float = 0.2,
    ) -> LLMResponse:
        """
        Send a chat completion request to the Ollama /api/chat endpoint.
        Handles retries, rate limits, and returns LLMResponse.
        """
        t0 = time.perf_counter()
        url = f"{self.host}/api/chat"

        payload = {
            "model": self.model,
            "messages": [
                {"role": "system", "content": system},
                {"role": "user", "content": prompt},
            ],
            "stream": False,
            "options": {
                "temperature": temperature,
            },
        }

        req = urllib.request.Request(
            url,
            data=json.dumps(payload).encode("utf-8"),
            headers={"Content-Type": "application/json"},
            method="POST",
        )

        max_retries = 2
        last_error = ""

        for attempt in range(max_retries + 1):
            try:
                with urllib.request.urlopen(req, timeout=self.timeout) as resp:
                    body = resp.read().decode("utf-8")
                    data = json.loads(body)
                    text = data.get("message", {}).get("content", "")
                    elapsed = time.perf_counter() - t0
                    return LLMResponse(
                        text=text,
                        model=self.model,
                        latency_seconds=round(elapsed, 4),
                    )
            except urllib.error.URLError as err:
                last_error = f"URLError: {err.reason}"
                if attempt < max_retries:
                    time.sleep(0.5 * (attempt + 1))
            except Exception as exc:
                last_error = str(exc)
                if attempt < max_retries:
                    time.sleep(0.5 * (attempt + 1))

        # Safe fallback if Ollama service is not running
        elapsed = time.perf_counter() - t0
        logger.warning("Ollama completion failed after %d retries: %s", max_retries, last_error)
        return LLMResponse(
            text=f'{{"error": "Ollama service unavailable at {self.host}", "detail": "{last_error}"}}',
            model=self.model,
            latency_seconds=round(elapsed, 4),
        )
