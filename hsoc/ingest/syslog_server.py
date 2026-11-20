from __future__ import annotations
import uuid
"""
RFC 3164 and RFC 5424 Asynchronous Syslog Server for H-SOC.

Listens on configurable UDP and TCP ports (default 5514).
Extracts priority, timestamp, host, app name, and raw message,
routes into the existing parser registry, enriches events,
quarantines malformed records, and publishes to the Event Bus.
"""


import asyncio
import logging
import re
from datetime import datetime, timezone
from typing import Any

from hsoc.config import get_settings
from hsoc.db import EventORM, QuarantineORM, SessionLocal
from hsoc.ingest.collector import compute_raw_hash
from hsoc.ingest.dedup import get_deduplicator
from hsoc.ingest.enrich import enrich
from hsoc.ingest.mapper import map_to_event
from hsoc.ingest.parsers import PARSER_REGISTRY
from hsoc.schema import Event, QuarantineRecord, SourceType
from hsoc.streaming.bus import StreamMessage, get_event_bus

logger = logging.getLogger(__name__)

# RFC 5424 regex: <PRI>VERSION TIMESTAMP HOSTNAME APP-NAME PROCID MSGID [STRUCTURED-DATA] MSG
_RFC5424_PATTERN = re.compile(
    r"^<(\d{1,3})>1\s+(\S+)\s+(\S+)\s+(\S+)\s+(\S+)\s+(\S+)\s*(?:\[(.*?)\])?\s*(.*)$",
    re.DOTALL,
)

# RFC 3164 regex: <PRI>TIMESTAMP HOST APP[PID]: MSG
_RFC3164_PATTERN = re.compile(
    r"^<(\d{1,3})>([A-Za-z]{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})\s+(\S+)\s+([^:\[\s]+)(?:\[(\d+)\])?:\s*(.*)$",
    re.DOTALL,
)

# Simple fallback for syslog lines with leading <PRI>
_PRI_FALLBACK_PATTERN = re.compile(r"^<(\d{1,3})>(.*)$", re.DOTALL)


class SyslogRecord:
    """Parsed syslog message fields."""

    def __init__(
        self,
        facility: int = 1,
        severity: int = 6,
        timestamp: datetime | None = None,
        hostname: str = "unknown",
        app_name: str = "unknown",
        proc_id: str | None = None,
        msg: str = "",
        raw: str = "",
    ) -> None:
        self.facility = facility
        self.severity = severity
        self.timestamp = timestamp or datetime.now(timezone.utc)
        self.hostname = hostname
        self.app_name = app_name
        self.proc_id = proc_id
        self.msg = msg
        self.raw = raw


def parse_syslog_envelope(raw_line: str) -> SyslogRecord:
    """Parse raw line into SyslogRecord using RFC 5424, RFC 3164, or fallback."""
    line = raw_line.strip()
    now = datetime.now(timezone.utc)

    # 1. Try RFC 5424
    m5424 = _RFC5424_PATTERN.match(line)
    if m5424:
        pri = int(m5424.group(1))
        fac, sev = pri >> 3, pri & 7
        ts_str = m5424.group(2)
        try:
            ts = datetime.fromisoformat(ts_str.replace("Z", "+00:00"))
        except Exception:
            ts = now
        host = m5424.group(3)
        app = m5424.group(4)
        proc_id = m5424.group(5)
        msg = m5424.group(8) or ""
        return SyslogRecord(fac, sev, ts, host, app, proc_id, msg, line)

    # 2. Try RFC 3164
    m3164 = _RFC3164_PATTERN.match(line)
    if m3164:
        pri = int(m3164.group(1))
        fac, sev = pri >> 3, pri & 7
        host = m3164.group(3)
        app = m3164.group(4)
        proc_id = m3164.group(5)
        msg = m3164.group(6) or ""
        return SyslogRecord(fac, sev, now, host, app, proc_id, msg, line)

    # 3. PRI Fallback
    m_pri = _PRI_FALLBACK_PATTERN.match(line)
    if m_pri:
        pri = int(m_pri.group(1))
        fac, sev = pri >> 3, pri & 7
        remainder = m_pri.group(2).strip()
        return SyslogRecord(fac, sev, now, "unknown", "unknown", None, remainder, line)

    # 4. Plain raw text fallback
    return SyslogRecord(1, 6, now, "unknown", "unknown", None, line, line)


def detect_parser_for_syslog(rec: SyslogRecord) -> str:
    """Determine the appropriate registered parser name for a syslog record."""
    app = rec.app_name.lower()
    msg = rec.msg.strip()

    if app in ("sshd", "sudo", "su", "login", "auth", "pam"):
        return "linux_auth"
    if app in ("apache", "apache2", "httpd", "nginx", "caddy"):
        return "apache"
    if app in ("wazuh", "ossec") or (msg.startswith("{") and '"rule"' in msg):
        return "wazuh_json"
    if app in ("flow", "zeek", "suricata", "netflow"):
        return "flow"
    if app in ("win_security", "security-auditing") or (msg.startswith("{") and '"EventID"' in msg):
        return "win_security"

    # Heuristic checks on message body
    if msg.startswith("{"):
        if '"EventID"' in msg or '"event_id"' in msg:
            return "win_security"
        if '"rule"' in msg or '"agent"' in msg:
            return "wazuh_json"
    if "Failed password" in msg or "Accepted " in msg or "sudo:" in msg or "sshd[" in msg:
        return "linux_auth"
    if re.search(r'"(?:GET|POST|PUT|DELETE|HEAD)\s+\S+\s+HTTP/', msg):
        return "apache"

    return "linux_auth"


async def process_raw_syslog_line(raw_line: str, remote_ip: str | None = None) -> dict[str, Any]:
    """
    Ingest a single raw syslog line into the H-SOC real-time pipeline.

    Returns dict with status: 'accepted', 'duplicate', or 'quarantined'.
    """
    line_clean = raw_line.strip()
    if not line_clean:
        return {"status": "ignored", "reason": "empty line"}

    raw_hash = compute_raw_hash(line_clean)
    dedup = get_deduplicator()

    # Deduplication check
    if dedup.is_duplicate(raw_hash):
        return {"status": "duplicate", "raw_hash": raw_hash}

    rec = parse_syslog_envelope(line_clean)
    if remote_ip and rec.hostname in ("unknown", "-"):
        rec.hostname = remote_ip

    parser_name = detect_parser_for_syslog(rec)
    parser_fn = PARSER_REGISTRY.get(parser_name)

    db = SessionLocal()
    try:
        if not parser_fn:
            # Route to quarantine
            quarantine = QuarantineORM(
                record_id=f"QUAR-{uuid.uuid4().hex[:12]}",
                ts=rec.timestamp,
                source_type=parser_name,
                raw=line_clean,
                reason=f"No registered parser for source type '{parser_name}'",
                parser="syslog",
            )
            db.add(quarantine)
            db.commit()
            return {"status": "quarantined", "reason": quarantine.reason}

        # Parse message payload — try stripped syslog line then message body
        clean_line = re.sub(r"^<\d{1,3}>(?:1\s+)?", "", line_clean).strip()
        parsed_dict = None
        last_exc = None
        for candidate in [clean_line, rec.msg, line_clean]:
            if not candidate:
                continue
            try:
                parsed_dict = parser_fn(candidate)
                if parsed_dict:
                    break
            except Exception as e:
                last_exc = e

        if not parsed_dict:
            quarantine = QuarantineORM(
                record_id=f"QUAR-{uuid.uuid4().hex[:12]}",
                ts=rec.timestamp,
                source_type=parser_name,
                raw=line_clean,
                reason=f"Parser exception: {str(last_exc)}",
                parser=parser_name,
            )
            db.add(quarantine)
            db.commit()
            return {"status": "quarantined", "reason": quarantine.reason}

        try:
            if not parsed_dict.get("host") and rec.hostname != "unknown":
                parsed_dict["host"] = rec.hostname
            item = map_to_event(parsed_dict, parser_name)
        except Exception as exc:
            quarantine = QuarantineORM(
                record_id=f"QUAR-{uuid.uuid4().hex[:12]}",
                ts=rec.timestamp,
                source_type=parser_name,
                raw=line_clean,
                reason=f"Parser exception: {str(exc)}",
                parser=parser_name,
            )
            db.add(quarantine)
            db.commit()
            return {"status": "quarantined", "reason": quarantine.reason}

        if isinstance(item, QuarantineRecord):
            quarantine = QuarantineORM(
                record_id=item.record_id,
                ts=item.ts or rec.timestamp,
                source_type=item.source_type,
                raw=item.raw,
                reason=item.reason,
                parser=item.parser,
            )
            db.add(quarantine)
            db.commit()
            return {"status": "quarantined", "reason": item.reason}

        # Valid Event — Enrich and Persist
        enriched = enrich(item)
        source_type_val = enriched.source_type.value if hasattr(enriched.source_type, "value") else str(enriched.source_type)

        event_orm = EventORM(
            event_id=enriched.event_id,
            ts=enriched.ts,
            source_type=source_type_val,
            host=enriched.host,
            src_ip=enriched.src_ip,
            dst_ip=enriched.dst_ip,
            dst_port=enriched.dst_port,
            user=enriched.user,
            action=enriched.action,
            outcome=enriched.outcome.value if hasattr(enriched.outcome, "value") else str(enriched.outcome),
            asset_criticality=enriched.asset.criticality if enriched.asset else None,
            asset_role=enriched.asset.role if enriched.asset else None,
            asset_owner=enriched.asset.owner if enriched.asset else None,
            user_privileged=enriched.user_ctx.privileged if enriched.user_ctx else False,
            features=enriched.features,
            label=enriched.label,
            raw=enriched.raw or line_clean,
            repeat_count=enriched.repeat_count,
            raw_hash=raw_hash,
        )
        db.add(event_orm)
        db.commit()

        # Publish to Event Bus
        bus = get_event_bus()
        msg = StreamMessage(
            topic="events",
            event_type="event_ingested",
            payload={"event": enriched.model_dump(), "source": "syslog"},
        )
        await bus.publish("events", msg)

        return {"status": "accepted", "event_id": enriched.event_id, "raw_hash": raw_hash}

    except Exception as exc:
        db.rollback()
        logger.error("Syslog ingestion error: %s", exc, exc_info=True)
        return {"status": "error", "reason": str(exc)}
    finally:
        db.close()


class SyslogUDPProtocol(asyncio.DatagramProtocol):
    """Asyncio UDP datagram protocol handler for RFC 3164/5424 syslog."""

    def __init__(self) -> None:
        super().__init__()
        self.transport: asyncio.DatagramTransport | None = None
        self.received_count: int = 0

    def connection_made(self, transport: asyncio.DatagramTransport) -> None:
        self.transport = transport

    def datagram_received(self, data: bytes, addr: tuple[str, int]) -> None:
        self.received_count += 1
        raw_line = data.decode("utf-8", errors="replace")
        remote_ip = addr[0]
        # Dispatch background coroutine to avoid blocking the UDP event loop
        asyncio.create_task(process_raw_syslog_line(raw_line, remote_ip=remote_ip))


class SyslogServerManager:
    """Manages UDP and TCP syslog listener tasks."""

    def __init__(self, host: str = "127.0.0.1", port: int = 5514, max_connections: int = 100) -> None:
        self.host = host
        self.port = port
        self.max_connections = max_connections
        self.udp_transport: asyncio.DatagramTransport | None = None
        self.udp_protocol: SyslogUDPProtocol | None = None
        self.tcp_server: asyncio.Server | None = None
        self.is_running: bool = False
        self._active_tcp_conns: int = 0

    async def start(self) -> None:
        """Start UDP and TCP syslog listeners."""
        loop = asyncio.get_running_loop()

        # 1. Start UDP listener
        self.udp_transport, self.udp_protocol = await loop.create_datagram_endpoint(
            lambda: SyslogUDPProtocol(),
            local_addr=(self.host, self.port),
        )
        logger.info("Syslog UDP listener running on %s:%d", self.host, self.port)

        # 2. Start TCP listener
        async def handle_tcp_client(reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
            if self._active_tcp_conns >= self.max_connections:
                logger.warning("Syslog TCP connection cap reached (%d). Closing.", self.max_connections)
                writer.close()
                await writer.wait_closed()
                return

            self._active_tcp_conns += 1
            remote_ip = writer.get_extra_info("peername", ("unknown", 0))[0]
            try:
                while True:
                    line_bytes = await reader.readline()
                    if not line_bytes:
                        break
                    raw_line = line_bytes.decode("utf-8", errors="replace")
                    await process_raw_syslog_line(raw_line, remote_ip=remote_ip)
            except Exception as exc:
                logger.debug("Syslog TCP client error: %s", exc)
            finally:
                self._active_tcp_conns = max(0, self._active_tcp_conns - 1)
                writer.close()
                await writer.wait_closed()

        self.tcp_server = await asyncio.start_server(
            handle_tcp_client,
            host=self.host,
            port=self.port,
        )
        logger.info("Syslog TCP listener running on %s:%d", self.host, self.port)
        self.is_running = True

    async def stop(self) -> None:
        """Stop UDP and TCP listeners."""
        if self.udp_transport:
            self.udp_transport.close()
            self.udp_transport = None
        if self.tcp_server:
            self.tcp_server.close()
            await self.tcp_server.wait_closed()
            self.tcp_server = None
        self.is_running = False
        logger.info("Syslog server stopped.")


# Singleton syslog server manager instance
_syslog_manager: SyslogServerManager | None = None


def get_syslog_server() -> SyslogServerManager:
    """Return the configured SyslogServerManager singleton."""
    global _syslog_manager
    if _syslog_manager is None:
        cfg = get_settings().streaming.get("syslog", {})
        host = cfg.get("host", "127.0.0.1")
        port = int(cfg.get("port", 5514))
        max_conns = int(cfg.get("max_connections", 100))
        _syslog_manager = SyslogServerManager(host=host, port=port, max_connections=max_conns)
    return _syslog_manager
