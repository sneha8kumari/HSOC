"""
Input sanitiser and data-egress redaction engine for LLM prompts.

Implements defense-in-depth protection:
  1. Delimiter isolation: wraps raw log telemetry inside <evidence>...</evidence>
     and neutralizes boundary breakouts (e.g. </evidence>, </context>).
  2. Per-provider data-egress policy: redacts PII (emails, SSNs, credit cards),
     high-entropy credentials (passwords, JWTs, AWS keys, Bearer tokens, private keys),
     and masks internal RFC-1918 IPs and usernames based on configuration in settings.yaml.
"""

from __future__ import annotations

import re
from typing import Any

from hsoc.config import get_settings


class RedactionEngine:
    """
    Config-driven PII and secret redaction engine enforcing per-provider data egress rules.
    """

    def __init__(self, policy: dict[str, Any] | None = None) -> None:
        if policy is None:
            genai_cfg = get_settings().genai
            policy = genai_cfg.get("data_egress_policy", {})

        self.policy = policy
        self.providers = policy.get("providers", {})
        self.patterns = policy.get("patterns", {})

        # Compile secret patterns
        self.compiled_secrets: list[tuple[re.Pattern, str]] = []
        for p in self.patterns.get("secrets", []):
            try:
                self.compiled_secrets.append(
                    (re.compile(p["regex"], re.MULTILINE), p.get("replacement", "[REDACTED_SECRET]"))
                )
            except re.error:
                continue

        # Compile PII patterns
        self.compiled_pii: list[tuple[re.Pattern, str]] = []
        for p in self.patterns.get("pii", []):
            try:
                self.compiled_pii.append(
                    (re.compile(p["regex"], re.MULTILINE), p.get("replacement", "[REDACTED_PII]"))
                )
            except re.error:
                continue

        # Compile network / IP patterns
        self.compiled_network: list[tuple[re.Pattern, str]] = []
        for p in self.patterns.get("network", []):
            try:
                self.compiled_network.append(
                    (re.compile(p["regex"], re.MULTILINE), p.get("replacement", "10.x.x.x"))
                )
            except re.error:
                continue

        # Username pattern
        self.username_pattern = re.compile(
            r"(?i)\b(user|username|account|login)\s*[:=]\s*['\"]?([A-Za-z0-9_.\-]+)['\"]?",
            re.MULTILINE,
        )

    def redact(self, text: str, provider: str = "hosted") -> str:
        """
        Apply redaction to text according to the specific provider's egress policy.

        Args:
            text: Input text containing prompts, evidence, or messages.
            provider: Target LLM provider (e.g. 'hosted', 'ollama').

        Returns:
            Sanitized text with PII/secrets redacted.
        """
        if not text:
            return ""

        provider_rules = self.providers.get(provider, {})
        # If provider is not explicitly listed, fall back to default hosted rules
        if not provider_rules and provider != "hosted":
            provider_rules = self.providers.get("hosted", {})

        redacted = text

        # 1. Redact secrets
        if provider_rules.get("redact_secrets", True):
            for pattern, replacement in self.compiled_secrets:
                redacted = pattern.sub(replacement, redacted)

        # 2. Redact PII
        if provider_rules.get("redact_pii", True):
            for pattern, replacement in self.compiled_pii:
                redacted = pattern.sub(replacement, redacted)

        # 3. Mask internal IPs
        if provider_rules.get("mask_internal_ips", True):
            for pattern, replacement in self.compiled_network:
                redacted = pattern.sub(replacement, redacted)

        # 4. Mask usernames
        if provider_rules.get("mask_usernames", False):
            redacted = self.username_pattern.sub(r"\1=[REDACTED_USER]", redacted)

        return redacted


# Global cached engine instance
_ENGINE: RedactionEngine | None = None


def get_redaction_engine() -> RedactionEngine:
    global _ENGINE
    if _ENGINE is None:
        _ENGINE = RedactionEngine()
    return _ENGINE


def sanitize_for_provider(text: str, provider: str = "hosted") -> str:
    """
    Sanitize text according to the configured egress policy for the given provider.

    Args:
        text: Prompt or payload string.
        provider: Provider name (e.g. 'hosted', 'ollama').

    Returns:
        Redacted string conforming to data egress policy.
    """
    engine = get_redaction_engine()
    return engine.redact(text, provider=provider)


def wrap_evidence(
    lines: list[str],
    sanitize: bool = True,
    provider: str | None = None,
) -> str:
    """
    Wrap raw log lines in a delimited evidence block to safeguard against prompt injection.

    Performs:
      1. Delimiter neutralization (escaping </evidence>, <context>, etc.)
      2. Optional PII/secret redaction before insertion into the prompt.

    Args:
        lines: Raw log lines.
        sanitize: Whether to apply redaction engine.
        provider: Target provider name if redaction is requested.

    Returns:
        A string enclosed in <evidence>...</evidence> delimiters.
    """
    cleaned_lines = []
    for line in lines:
        if not line or not line.strip():
            continue
        # Neutralize delimiter breakouts
        safe_line = (
            line.strip()
            .replace("<evidence>", "[evidence]")
            .replace("</evidence>", "[/evidence]")
            .replace("<context>", "[context]")
            .replace("</context>", "[/context]")
            .replace("<instructions>", "[instructions]")
            .replace("</instructions>", "[/instructions]")
        )
        if sanitize and provider:
            safe_line = sanitize_for_provider(safe_line, provider=provider)
        cleaned_lines.append(safe_line)

    content = "\n".join(cleaned_lines) if cleaned_lines else "No direct log evidence available."
    return f"<evidence>\n{content}\n</evidence>"


def mask_for_hosted(text: str) -> str:
    """
    Mask PII and internal credentials before forwarding to hosted models.
    Preserved for backward compatibility.
    """
    return sanitize_for_provider(text, provider="hosted")
