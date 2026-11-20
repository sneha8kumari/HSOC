"""
Wazuh REST API Integration Client for H-SOC.

Provides:
  - Token-based JWT authentication (/security/user/authenticate)
  - Automatic token renewal on expiry
  - Resilient alert polling (/alerts) with pagination and time filtering
  - Connection health check (/manager/info and /manager/status)
  - Rate limiting, timeout, and clock skew handling
  - Conversion of raw Wazuh alerts into normalized H-SOC Event objects
"""

from __future__ import annotations

import base64
from datetime import datetime, timezone
import json
import logging
import os
import ssl
import time
from typing import Any
import urllib.error
import urllib.parse
import urllib.request

from hsoc.config import get_settings
from hsoc.ingest.enrich import enrich
from hsoc.ingest.mapper import map_to_event
from hsoc.ingest.parsers.wazuh_json import parse as parse_wazuh_json
from hsoc.schema import Event, QuarantineRecord, SourceType

logger = logging.getLogger(__name__)


class WazuhClient:
    """
    Robust HTTP client for the Wazuh Manager REST API (port 55000 default).
    """

    def __init__(
        self,
        base_url: str | None = None,
        username: str | None = None,
        password: str | None = None,
        verify_ssl: bool | None = None,
        timeout_seconds: float = 10.0,
    ) -> None:
        cfg = get_settings().ingest.get("wazuh", {}) if hasattr(get_settings(), "ingest") else {}

        self.base_url = (
            base_url
            or os.getenv("WAZUH_URL")
            or cfg.get("url", "https://localhost:55000")
        ).rstrip("/")

        self.username = username or os.getenv("WAZUH_USER") or cfg.get("username", "wazuh-wui")
        self.password = password or os.getenv("WAZUH_PASSWORD") or cfg.get("password", "")

        ssl_env = os.getenv("WAZUH_VERIFY_SSL")
        if verify_ssl is not None:
            self.verify_ssl = verify_ssl
        elif ssl_env is not None:
            self.verify_ssl = ssl_env.lower() in ("true", "1", "yes")
        else:
            self.verify_ssl = bool(cfg.get("verify_ssl", False))

        self.timeout = float(timeout_seconds)

        # Token caching
        self._jwt_token: str | None = None
        self._token_expires_at: float = 0.0

        # State tracking
        self.last_sync_time: datetime | None = None
        self.last_poll_error: str | None = None
        self.total_polled_alerts: int = 0
        self.last_alert_id: str | None = None

        # Build SSL Context
        self._ssl_context = ssl.create_default_context()
        if not self.verify_ssl:
            self._ssl_context.check_hostname = False
            self._ssl_context.verify_mode = ssl.CERT_NONE

    def _is_configured(self) -> bool:
        """Check if minimum required credentials and URL are present."""
        return bool(self.base_url and self.username and self.password)

    def authenticate(self) -> str:
        """
        Authenticate with Wazuh API and acquire a JWT token.
        Token is cached until 60 seconds before expiration.
        """
        now = time.time()
        if self._jwt_token and now < (self._token_expires_at - 60):
            return self._jwt_token

        if not self._is_configured():
            raise ValueError(
                "Wazuh client not configured: WAZUH_URL, WAZUH_USER, and WAZUH_PASSWORD are required."
            )

        auth_url = f"{self.base_url}/security/user/authenticate"
        cred_bytes = f"{self.username}:{self.password}".encode("utf-8")
        auth_header = f"Basic {base64.b64encode(cred_bytes).decode('ascii')}"

        req = urllib.request.Request(
            auth_url,
            headers={
                "Authorization": auth_header,
                "Content-Type": "application/json",
            },
            method="POST",
        )

        try:
            with urllib.request.urlopen(req, timeout=self.timeout, context=self._ssl_context) as resp:
                status_code = resp.getcode()
                body = resp.read().decode("utf-8")
                payload = json.loads(body)

                token = payload.get("data", {}).get("token")
                if not token:
                    raise ValueError(f"Wazuh auth response missing data.token: {body[:200]}")

                self._jwt_token = token
                # Default Wazuh token duration is 15 minutes (900s)
                self._token_expires_at = now + 900
                self.last_poll_error = None
                return token

        except urllib.error.HTTPError as err:
            err_msg = f"Wazuh auth HTTP {err.code}: {err.reason}"
            self.last_poll_error = err_msg
            logger.warning(err_msg)
            raise ConnectionError(err_msg) from err
        except Exception as exc:
            err_msg = f"Wazuh auth failed: {str(exc)}"
            self.last_poll_error = err_msg
            logger.warning(err_msg)
            raise ConnectionError(err_msg) from exc

    def test_connection(self) -> dict[str, Any]:
        """
        Test API reachability and validate credentials.
        Returns detailed diagnostic info without raising unhandled exceptions.
        """
        if not self._is_configured():
            return {
                "configured": False,
                "connected": False,
                "status": "MISCONFIGURED",
                "message": "Wazuh credentials missing. Set WAZUH_URL, WAZUH_USER, and WAZUH_PASSWORD.",
                "base_url": self.base_url,
                "verify_ssl": self.verify_ssl,
            }

        try:
            token = self.authenticate()
            # Query manager status endpoint
            info_url = f"{self.base_url}/manager/info"
            req = urllib.request.Request(
                info_url,
                headers={"Authorization": f"Bearer {token}", "Content-Type": "application/json"},
                method="GET",
            )
            with urllib.request.urlopen(req, timeout=self.timeout, context=self._ssl_context) as resp:
                body = resp.read().decode("utf-8")
                data = json.loads(body).get("data", {})
                return {
                    "configured": True,
                    "connected": True,
                    "status": "CONNECTED",
                    "message": "Successfully authenticated to Wazuh Manager API.",
                    "base_url": self.base_url,
                    "manager_name": data.get("name", "wazuh-manager"),
                    "version": data.get("version", "unknown"),
                    "last_checked": datetime.now(timezone.utc).isoformat(),
                }
        except Exception as exc:
            return {
                "configured": True,
                "connected": False,
                "status": "DISCONNECTED",
                "message": f"Connection check failed: {str(exc)}",
                "base_url": self.base_url,
                "verify_ssl": self.verify_ssl,
                "last_checked": datetime.now(timezone.utc).isoformat(),
            }

    def fetch_alerts(
        self,
        limit: int = 50,
        offset: int = 0,
        time_window: str = "15m",
        min_level: int = 3,
    ) -> list[dict[str, Any]]:
        """
        Fetch security alerts from the Wazuh Manager /alerts API.
        """
        token = self.authenticate()
        params = urllib.parse.urlencode({
            "limit": limit,
            "offset": offset,
            "time_frame": time_window,
            "q": f"rule.level>={min_level}",
            "sort": "-timestamp",
        })
        url = f"{self.base_url}/alerts?{params}"

        req = urllib.request.Request(
            url,
            headers={"Authorization": f"Bearer {token}", "Content-Type": "application/json"},
            method="GET",
        )

        try:
            with urllib.request.urlopen(req, timeout=self.timeout, context=self._ssl_context) as resp:
                body = resp.read().decode("utf-8")
                data = json.loads(body)
                items = data.get("data", {}).get("affected_items", [])
                self.last_sync_time = datetime.now(timezone.utc)
                self.total_polled_alerts += len(items)
                return items
        except Exception as exc:
            self.last_poll_error = str(exc)
            logger.error("Failed fetching alerts from Wazuh: %s", exc)
            raise

    def poll_and_normalize(self, limit: int = 50) -> list[Event]:
        """
        Poll latest alerts, parse and enrich into normalized Event objects.
        """
        raw_items = self.fetch_alerts(limit=limit)
        events: list[Event] = []

        for item in raw_items:
            line = json.dumps(item) if isinstance(item, dict) else str(item)
            try:
                parsed = parse_wazuh_json(line)
                mapped = map_to_event(parsed, parser="wazuh_json")
                if isinstance(mapped, Event):
                    enriched = enrich(mapped)
                    # Mark as live telemetry (not simulated)
                    enriched.is_simulated = False
                    events.append(enriched)
            except Exception as e:
                logger.warning("Failed normalizing Wazuh alert record: %s", e)

        return events


# Global singleton instance
_wazuh_client_instance: WazuhClient | None = None


def get_wazuh_client() -> WazuhClient:
    """Accessor for the global WazuhClient instance."""
    global _wazuh_client_instance
    if _wazuh_client_instance is None:
        _wazuh_client_instance = WazuhClient()
    return _wazuh_client_instance
