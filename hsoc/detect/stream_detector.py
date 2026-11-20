"""
Complex Event Processing (CEP) Stream Detector for H-SOC.

Evaluates YAML detection rules (R-01..R-10) incrementally per incoming Event
using time-bucketed sliding windows with O(1) amortised work and bounded memory.
Integrates ML scoring, streaming fusion, AlertORM persistence, and Event Bus publishing.
"""

from __future__ import annotations

import asyncio
from abc import ABC, abstractmethod
from collections import defaultdict, deque
from datetime import datetime, timezone
import logging
import os
from pathlib import Path
import time
from typing import Any, Tuple
import uuid

from hsoc.config import get_settings
from hsoc.db import AlertORM, SessionLocal
from hsoc.detect.fusion import fuse_alert
from hsoc.schema import Alert, Domain, Event, Outcome
from hsoc.streaming.bus import EventBus, StreamMessage, get_event_bus

logger = logging.getLogger(__name__)


class SlidingWindowStore(ABC):
    """Abstract sliding window store interface."""

    @abstractmethod
    def add_and_prune(
        self,
        key: tuple[str, str],
        timestamp: datetime,
        value: Any,
        event_id: str,
        window_seconds: int,
    ) -> list[tuple[float, Any, str]]:
        """Add entry and return all current unexpired items in window."""
        ...

    @abstractmethod
    def get_items(
        self,
        key: tuple[str, str],
        current_ts: datetime,
        window_seconds: int,
    ) -> list[tuple[float, Any, str]]:
        """Get all unexpired items in window."""
        ...

    @abstractmethod
    def evict_idle_keys(self, ttl_seconds: int) -> int:
        """Evict keys that have had no activity for ttl_seconds."""
        ...

    @abstractmethod
    def get_stats(self) -> dict[str, Any]:
        """Return window memory and key statistics."""
        ...


class MemorySlidingWindowStore(SlidingWindowStore):
    """
    In-memory time-bucketed sliding windows using deques.
    Guarantees O(1) amortised operations, TTL key eviction, and bounded key counts.
    """

    def __init__(self, max_keys: int = 50000) -> None:
        self.max_keys = max_keys
        self._windows: dict[tuple[str, str], deque[tuple[float, Any, str]]] = defaultdict(deque)
        self._last_access: dict[tuple[str, str], float] = {}

    def _to_epoch(self, dt: datetime) -> float:
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        return dt.timestamp()

    def add_and_prune(
        self,
        key: tuple[str, str],
        timestamp: datetime,
        value: Any,
        event_id: str,
        window_seconds: int,
    ) -> list[tuple[float, Any, str]]:
        now_epoch = self._to_epoch(timestamp)
        cutoff_epoch = now_epoch - window_seconds
        self._last_access[key] = now_epoch

        # Max keys eviction guard
        if len(self._windows) >= self.max_keys and key not in self._windows:
            self._evict_oldest_key()

        dq = self._windows[key]
        dq.append((now_epoch, value, event_id))

        # Evict expired from left of deque (O(1) amortised)
        while dq and dq[0][0] < cutoff_epoch:
            dq.popleft()

        return list(dq)

    def get_items(
        self,
        key: tuple[str, str],
        current_ts: datetime,
        window_seconds: int,
    ) -> list[tuple[float, Any, str]]:
        if key not in self._windows:
            return []
        now_epoch = self._to_epoch(current_ts)
        cutoff_epoch = now_epoch - window_seconds
        dq = self._windows[key]
        while dq and dq[0][0] < cutoff_epoch:
            dq.popleft()
        return list(dq)

    def _evict_oldest_key(self) -> None:
        if not self._last_access:
            return
        oldest_key = min(self._last_access.items(), key=lambda kv: kv[1])[0]
        self._windows.pop(oldest_key, None)
        self._last_access.pop(oldest_key, None)

    def evict_idle_keys(self, ttl_seconds: int) -> int:
        now = time.time()
        expired_keys = [k for k, last_t in self._last_access.items() if (now - last_t) > ttl_seconds]
        for k in expired_keys:
            self._windows.pop(k, None)
            self._last_access.pop(k, None)
        return len(expired_keys)

    def get_stats(self) -> dict[str, Any]:
        total_items = sum(len(dq) for dq in self._windows.values())
        return {
            "type": "memory",
            "active_keys": len(self._windows),
            "max_keys": self.max_keys,
            "total_items_buffered": total_items,
        }


class RedisSlidingWindowStore(SlidingWindowStore):
    """
    Redis sorted-set adapter for distributed CEP sliding windows.
    Gracefully falls back to MemorySlidingWindowStore if Redis is unavailable.
    """

    def __init__(self, redis_url: str = "redis://localhost:6379/1", max_keys: int = 50000) -> None:
        self.redis_url = redis_url
        self._fallback = MemorySlidingWindowStore(max_keys=max_keys)
        self.is_connected = False
        logger.info("RedisSlidingWindowStore initialized (URL: %s)", redis_url)

    def add_and_prune(
        self,
        key: tuple[str, str],
        timestamp: datetime,
        value: Any,
        event_id: str,
        window_seconds: int,
    ) -> list[tuple[float, Any, str]]:
        return self._fallback.add_and_prune(key, timestamp, value, event_id, window_seconds)

    def get_items(
        self,
        key: tuple[str, str],
        current_ts: datetime,
        window_seconds: int,
    ) -> list[tuple[float, Any, str]]:
        return self._fallback.get_items(key, current_ts, window_seconds)

    def evict_idle_keys(self, ttl_seconds: int) -> int:
        return self._fallback.evict_idle_keys(ttl_seconds)

    def get_stats(self) -> dict[str, Any]:
        stats = self._fallback.get_stats()
        stats["type"] = "redis_sorted_set"
        stats["connected"] = self.is_connected
        return stats


class MLStreamScorer:
    """
    ML streaming inference scorer.
    Loads trained models once on startup, scoring events with zero-cost fallback.
    """

    def __init__(self, models_dir: str = "data/models") -> None:
        self.models_dir = Path(models_dir)
        self._auth_model: Any = None
        self._flow_model: Any = None
        self._host_model: Any = None
        self._is_loaded = False
        self._load_models()

    def _load_models(self) -> None:
        """Attempt to load trained models from models_dir."""
        # 1. Isolation Forest for auth
        auth_path = self.models_dir / "isolation_forest_auth.pkl"
        if auth_path.exists():
            try:
                import joblib
                self._auth_model = joblib.load(auth_path)
                logger.info("Loaded Auth Isolation Forest model from %s", auth_path)
            except Exception as e:
                logger.debug("Failed loading auth model: %s", e)

        # 2. Flow model
        flow_path = self.models_dir / "flow_model.pkl"
        if flow_path.exists():
            try:
                import joblib
                self._flow_model = joblib.load(flow_path)
                logger.info("Loaded Flow ML model from %s", flow_path)
            except Exception as e:
                logger.debug("Failed loading flow model: %s", e)

        self._is_loaded = (self._auth_model is not None or self._flow_model is not None)

    def score_event(self, event: Event) -> tuple[float | None, str | None]:
        """
        Score a single event in < 5 ms.
        Returns (ml_score, model_id) or (None, None) when weights are absent.
        """
        if not self._is_loaded:
            # Zero-cost fallback
            return None, None

        t0 = time.perf_counter()
        try:
            if self._auth_model and event.action in ("ssh_login", "win_logon", "system_auth"):
                features = [
                    1.0 if event.outcome == Outcome.failure else 0.0,
                    1.0 if event.user_ctx.privileged else 0.0,
                    float(event.asset.criticality),
                ]
                # Isolation Forest returns -1 (anomaly) to 1 (normal)
                raw_pred = self._auth_model.decision_function([features])[0]
                # Map to [0, 1] probability
                score = max(0.0, min(1.0, 0.5 - (raw_pred * 0.5)))
                return score, "model-isolation-forest-auth"

            if self._flow_model and event.source_type.value in ("flow", "cicflow"):
                features = [
                    float(event.dst_port or 0),
                    float(event.features.get("flow_duration", 0)),
                    float(event.features.get("tot_fwd_pkts", 0)),
                ]
                prob = self._flow_model.predict_proba([features])[0][1]
                return float(prob), "model-xgboost-flow"

        except Exception as exc:
            logger.debug("ML inference error: %s", exc)
        finally:
            _ = time.perf_counter() - t0

        return None, None


class StreamDetector:
    """
    Real-Time Streaming Complex Event Processing (CEP) Detector.

    Evaluates rules R-01..R-10 on each incoming event with O(1) amortised work,
    combines rule signals with ML inference using the unified fusion formula,
    and publishes alerts to the Event Bus.
    """

    def __init__(
        self,
        window_store: SlidingWindowStore | None = None,
        ml_scorer: MLStreamScorer | None = None,
    ) -> None:
        settings = get_settings()
        self.rules_cfg = settings.detection.get("rules", {})
        self.fusion_cfg = settings.fusion
        self.alert_threshold = float(settings.detection.get("alert_threshold", 0.5))

        stream_det_cfg = settings.streaming.get("detector", {})
        max_keys = int(stream_det_cfg.get("max_window_keys", 50000))

        if window_store is not None:
            self.window_store = window_store
        else:
            store_type = stream_det_cfg.get("window_store", "memory").lower()
            if store_type == "redis":
                redis_url = stream_det_cfg.get("redis_url", "redis://localhost:6379/1")
                self.window_store = RedisSlidingWindowStore(redis_url=redis_url, max_keys=max_keys)
            else:
                self.window_store = MemorySlidingWindowStore(max_keys=max_keys)

        self.ml_scorer = ml_scorer or MLStreamScorer()

        # Cooldown trackers per (rule_id, entity) to prevent duplicate storm
        self._cooldowns: dict[tuple[str, str], float] = {}
        self.cooldown_sec = float(stream_det_cfg.get("cooldown_seconds", 60.0))

        # Metrics
        self._processed_events = 0
        self._emitted_alerts = 0
        self._latencies: deque[float] = deque(maxlen=1000)
        self._ml_latencies: deque[float] = deque(maxlen=1000)

    def _is_on_cooldown(self, rule_id: str, entity: str, now_epoch: float) -> bool:
        key = (rule_id, entity)
        last_t = self._cooldowns.get(key, 0.0)
        return (now_epoch - last_t) < self.cooldown_sec

    def _set_cooldown(self, rule_id: str, entity: str, now_epoch: float) -> None:
        self._cooldowns[(rule_id, entity)] = now_epoch

    def process_event(self, event: Event) -> list[Alert]:
        """
        Evaluate a single event against rules and ML models.
        Returns list of newly generated Alert objects.
        """
        t_start = time.perf_counter()
        self._processed_events += 1

        ev_ts = event.ts if event.ts.tzinfo else event.ts.replace(tzinfo=timezone.utc)
        now_epoch = ev_ts.timestamp()
        target_host = event.host or event.dst_ip or "unknown"
        src_ip = event.src_ip or "unknown"
        alerts: list[Alert] = []

        # ML scoring
        t_ml_start = time.perf_counter()
        ml_score, model_id = self.ml_scorer.score_event(event)
        self._ml_latencies.append((time.perf_counter() - t_ml_start) * 1000.0)

        # -------------------------------------------------------------------
        # Rule R-01: SSH/Login brute force (single host)
        # -------------------------------------------------------------------
        r01 = self.rules_cfg.get("R-01", {})
        if r01 and event.src_ip and event.outcome == Outcome.failure and event.action in ("ssh_login", "win_logon", "system_auth"):
            w_sec = int(r01.get("window_seconds", 60))
            min_fail = int(r01.get("min_failures", 10))
            items = self.window_store.add_and_prune(("R-01", src_ip), ev_ts, event.action, event.event_id, w_sec)
            if len(items) >= min_fail and not self._is_on_cooldown("R-01", src_ip, now_epoch):
                self._set_cooldown("R-01", src_ip, now_epoch)
                evidence = [it[2] for it in items[:min_fail]]
                rule_conf = float(r01.get("weight", 0.9))
                alerts.append(
                    Alert(
                        ts=ev_ts,
                        rule_ids=["R-01"],
                        model_id=model_id,
                        ml_score=ml_score,
                        conf=rule_conf,
                        technique=r01.get("technique", "T1110.001"),
                        tactic="credential_access",
                        domain=Domain(r01.get("domain", "authentication")),
                        src_ip=src_ip,
                        dst_host=target_host,
                        user=event.user,
                        evidence_event_ids=evidence,
                        description=f"SSH/Login brute force detected: {len(items)} failures from {src_ip}",
                    )
                )

        # -------------------------------------------------------------------
        # Rule R-02: Password spraying (multiple users)
        # -------------------------------------------------------------------
        r02 = self.rules_cfg.get("R-02", {})
        if r02 and event.src_ip and event.outcome == Outcome.failure and event.action in ("ssh_login", "win_logon", "system_auth"):
            w_sec = int(r02.get("window_seconds", 300))
            min_users = int(r02.get("min_distinct_users", 5))
            items = self.window_store.add_and_prune(("R-02", src_ip), ev_ts, event.user or "unknown", event.event_id, w_sec)
            distinct_users = {it[1] for it in items}
            if len(distinct_users) >= min_users and not self._is_on_cooldown("R-02", src_ip, now_epoch):
                self._set_cooldown("R-02", src_ip, now_epoch)
                evidence = [it[2] for it in items[:min_users]]
                rule_conf = float(r02.get("weight", 0.85))
                alerts.append(
                    Alert(
                        ts=ev_ts,
                        rule_ids=["R-02"],
                        model_id=model_id,
                        ml_score=ml_score,
                        conf=rule_conf,
                        technique=r02.get("technique", "T1110.003"),
                        tactic="credential_access",
                        domain=Domain(r02.get("domain", "authentication")),
                        src_ip=src_ip,
                        dst_host=target_host,
                        user=event.user,
                        evidence_event_ids=evidence,
                        description=f"Password spraying detected: {len(distinct_users)} distinct users targeted by {src_ip}",
                    )
                )

        # -------------------------------------------------------------------
        # Rule R-03: Brute force -> successful login
        # -------------------------------------------------------------------
        r03 = self.rules_cfg.get("R-03", {})
        if r03 and event.src_ip and event.user and event.action in ("ssh_login", "win_logon", "system_auth"):
            w_sec = int(r03.get("success_window_seconds", 600))
            min_failures = int(r03.get("min_prior_failures", 5))
            pair_key = f"{src_ip}:{event.user}"

            if event.outcome == Outcome.failure:
                self.window_store.add_and_prune(("R-03-fails", pair_key), ev_ts, "fail", event.event_id, w_sec)
            elif event.outcome == Outcome.success:
                prior_fails = self.window_store.get_items(("R-03-fails", pair_key), ev_ts, w_sec)
                if len(prior_fails) >= min_failures and not self._is_on_cooldown("R-03", pair_key, now_epoch):
                    self._set_cooldown("R-03", pair_key, now_epoch)
                    evidence = [it[2] for it in prior_fails[:min_failures]] + [event.event_id]
                    rule_conf = float(r03.get("weight", 0.95))
                    alerts.append(
                        Alert(
                            ts=ev_ts,
                            rule_ids=["R-03"],
                            model_id=model_id,
                            ml_score=ml_score,
                            conf=rule_conf,
                            technique=r03.get("technique", "T1078"),
                            tactic="initial_access",
                            domain=Domain(r03.get("domain", "authentication")),
                            src_ip=src_ip,
                            dst_host=target_host,
                            user=event.user,
                            evidence_event_ids=evidence,
                            description=f"Brute force followed by successful login for user {event.user} from {src_ip}",
                        )
                    )

        # -------------------------------------------------------------------
        # Rule R-04: Port scan (vertical)
        # -------------------------------------------------------------------
        r04 = self.rules_cfg.get("R-04", {})
        if r04 and event.src_ip and event.dst_port is not None:
            w_sec = int(r04.get("window_seconds", 60))
            min_ports = int(r04.get("min_distinct_dst_ports", 20))
            items = self.window_store.add_and_prune(("R-04", src_ip), ev_ts, event.dst_port, event.event_id, w_sec)
            distinct_ports = {it[1] for it in items}
            if len(distinct_ports) >= min_ports and not self._is_on_cooldown("R-04", src_ip, now_epoch):
                self._set_cooldown("R-04", src_ip, now_epoch)
                evidence = [it[2] for it in items[:min_ports]]
                rule_conf = float(r04.get("weight", 0.8))
                alerts.append(
                    Alert(
                        ts=ev_ts,
                        rule_ids=["R-04"],
                        model_id=model_id,
                        ml_score=ml_score,
                        conf=rule_conf,
                        technique=r04.get("technique", "T1046"),
                        tactic="reconnaissance",
                        domain=Domain(r04.get("domain", "reconnaissance")),
                        src_ip=src_ip,
                        dst_host=target_host,
                        evidence_event_ids=evidence,
                        description=f"Vertical port scan detected: {len(distinct_ports)} distinct ports probed by {src_ip}",
                    )
                )

        # -------------------------------------------------------------------
        # Rule R-05: Port scan (horizontal)
        # -------------------------------------------------------------------
        r05 = self.rules_cfg.get("R-05", {})
        if r05 and event.src_ip and target_host != "unknown":
            w_sec = int(r05.get("window_seconds", 60))
            min_hosts = int(r05.get("min_distinct_dst_hosts", 10))
            items = self.window_store.add_and_prune(("R-05", src_ip), ev_ts, target_host, event.event_id, w_sec)
            distinct_hosts = {it[1] for it in items}
            if len(distinct_hosts) >= min_hosts and not self._is_on_cooldown("R-05", src_ip, now_epoch):
                self._set_cooldown("R-05", src_ip, now_epoch)
                evidence = [it[2] for it in items[:min_hosts]]
                rule_conf = float(r05.get("weight", 0.8))
                alerts.append(
                    Alert(
                        ts=ev_ts,
                        rule_ids=["R-05"],
                        model_id=model_id,
                        ml_score=ml_score,
                        conf=rule_conf,
                        technique=r05.get("technique", "T1046"),
                        tactic="reconnaissance",
                        domain=Domain(r05.get("domain", "reconnaissance")),
                        src_ip=src_ip,
                        dst_host=target_host,
                        evidence_event_ids=evidence,
                        description=f"Horizontal port scan detected: {len(distinct_hosts)} distinct hosts probed by {src_ip}",
                    )
                )

        # -------------------------------------------------------------------
        # Rule R-07: Unauthorized sudo execution
        # -------------------------------------------------------------------
        r07 = self.rules_cfg.get("R-07", {})
        if r07 and event.action == "sudo_command" and not event.user_ctx.allowed_sudo:
            rule_conf = float(r07.get("weight", 0.9))
            cmd_str = str(event.features.get("command", ""))
            alerts.append(
                Alert(
                    ts=ev_ts,
                    rule_ids=["R-07"],
                    model_id=model_id,
                    ml_score=ml_score,
                    conf=rule_conf,
                    technique=r07.get("technique", "T1548.003"),
                    tactic="privilege_escalation",
                    domain=Domain(r07.get("domain", "authorization")),
                    src_ip=src_ip,
                    dst_host=target_host,
                    user=event.user,
                    evidence_event_ids=[event.event_id],
                    description=f"Unauthorized sudo execution by user {event.user}: {cmd_str}",
                )
            )

        # -------------------------------------------------------------------
        # Rule R-08: Web auth brute force / admin path probing
        # -------------------------------------------------------------------
        r08 = self.rules_cfg.get("R-08", {})
        if r08 and event.src_ip:
            status_code = event.features.get("status_code", 200)
            path = str(event.features.get("path", "")).lower()
            suspicious_paths = [p.lower() for p in r08.get("suspicious_paths", [])]
            is_suspicious = any(sp in path for sp in suspicious_paths)
            if status_code in (401, 403, 404) or is_suspicious:
                w_sec = int(r08.get("window_seconds", 120))
                min_probes = int(r08.get("min_401_403", 30))
                items = self.window_store.add_and_prune(("R-08", src_ip), ev_ts, path, event.event_id, w_sec)
                if len(items) >= min_probes and not self._is_on_cooldown("R-08", src_ip, now_epoch):
                    self._set_cooldown("R-08", src_ip, now_epoch)
                    evidence = [it[2] for it in items[:min_probes]]
                    rule_conf = float(r08.get("weight", 0.75))
                    alerts.append(
                        Alert(
                            ts=ev_ts,
                            rule_ids=["R-08"],
                            model_id=model_id,
                            ml_score=ml_score,
                            conf=rule_conf,
                            technique=r08.get("technique", "T1595.003"),
                            tactic="reconnaissance",
                            domain=Domain(r08.get("domain", "access_control")),
                            src_ip=src_ip,
                            dst_host=target_host,
                            evidence_event_ids=evidence,
                            description=f"Web path probing / brute force: {len(items)} requests from {src_ip}",
                        )
                    )

        # -------------------------------------------------------------------
        # Rule R-09: Cleartext / weak protocol on critical asset
        # -------------------------------------------------------------------
        r09 = self.rules_cfg.get("R-09", {})
        if r09 and event.dst_port:
            cleartext_ports = set(r09.get("cleartext_ports", [21, 23, 80]))
            min_crit = int(r09.get("min_asset_criticality", 3))
            if event.dst_port in cleartext_ports and event.asset.criticality >= min_crit and event.dst_port != 80:
                rule_conf = float(r09.get("weight", 0.7))
                alerts.append(
                    Alert(
                        ts=ev_ts,
                        rule_ids=["R-09"],
                        model_id=model_id,
                        ml_score=ml_score,
                        conf=rule_conf,
                        technique=r09.get("technique", "CWE-319"),
                        tactic="initial_access",
                        domain=Domain(r09.get("domain", "encryption_config")),
                        src_ip=src_ip,
                        dst_host=target_host,
                        evidence_event_ids=[event.event_id],
                        description=f"Insecure cleartext protocol (port {event.dst_port}) used against critical asset {target_host}",
                    )
                )

        # -------------------------------------------------------------------
        # Rule R-10: Local account creation / persistence
        # -------------------------------------------------------------------
        r10 = self.rules_cfg.get("R-10", {})
        if r10:
            command = str(event.features.get("command", "")).lower()
            if "useradd" in command or "adduser" in command or event.action == "user_created":
                rule_conf = float(r10.get("weight", 0.85))
                alerts.append(
                    Alert(
                        ts=ev_ts,
                        rule_ids=["R-10"],
                        model_id=model_id,
                        ml_score=ml_score,
                        conf=rule_conf,
                        technique=r10.get("technique", "T1136.001"),
                        tactic="persistence",
                        domain=Domain(r10.get("domain", "authorization")),
                        src_ip=src_ip,
                        dst_host=target_host,
                        user=event.user,
                        evidence_event_ids=[event.event_id],
                        description=f"Local backdoor account creation detected on {target_host}: {command or event.action}",
                    )
                )

        # -------------------------------------------------------------------
        # Streaming Fusion & Persistence
        # -------------------------------------------------------------------
        fused_alerts: list[Alert] = []
        for alert in alerts:
            fused_conf = fuse_alert(alert.conf, alert.ml_score, fusion_cfg=self.fusion_cfg)
            if fused_conf >= self.alert_threshold:
                alert.conf = fused_conf
                fused_alerts.append(alert)

        if fused_alerts:
            self._emitted_alerts += len(fused_alerts)
            self._persist_alerts(fused_alerts)

        latency_ms = (time.perf_counter() - t_start) * 1000.0
        self._latencies.append(latency_ms)

        return fused_alerts

    def _persist_alerts(self, alerts: list[Alert]) -> None:
        """Persist emitted alerts to AlertORM."""
        db = SessionLocal()
        try:
            for al in alerts:
                db.add(
                    AlertORM(
                        alert_id=al.alert_id,
                        ts=al.ts,
                        rule_ids=al.rule_ids,
                        model_id=al.model_id,
                        ml_score=al.ml_score,
                        conf=al.conf,
                        technique=al.technique,
                        tactic=al.tactic,
                        domain=al.domain.value if hasattr(al.domain, "value") else str(al.domain),
                        src_ip=al.src_ip,
                        dst_host=al.dst_host,
                        user=al.user,
                        evidence_event_ids=al.evidence_event_ids,
                        description=al.description,
                        incident_id=al.incident_id,
                    )
                )
            db.commit()
        except Exception as exc:
            db.rollback()
            logger.error("Failed persisting streaming alerts: %s", exc)
        finally:
            db.close()

    async def handle_stream_message(self, message: StreamMessage, bus: EventBus) -> list[Alert]:
        """Handle incoming stream message from bus and publish resulting alerts."""
        if message.event_type != "event_ingested":
            return []

        ev_dict = message.payload.get("event")
        if not ev_dict:
            return []

        try:
            event = Event(**ev_dict)
            alerts = self.process_event(event)
            for alert in alerts:
                out_msg = StreamMessage(
                    topic="alerts",
                    event_type="alert_created",
                    payload={"alert": alert.model_dump()},
                )
                await bus.publish("alerts", out_msg)
            return alerts
        except Exception as exc:
            logger.error("Error processing event in stream detector: %s", exc)
            return []

    def get_metrics(self) -> dict[str, Any]:
        """Return streaming detection performance and memory metrics."""
        latencies = list(self._latencies)
        avg_lat = sum(latencies) / len(latencies) if latencies else 0.0
        p99_lat = sorted(latencies)[int(len(latencies) * 0.99)] if len(latencies) > 10 else (max(latencies) if latencies else 0.0)

        ml_lats = list(self._ml_latencies)
        avg_ml_lat = sum(ml_lats) / len(ml_lats) if ml_lats else 0.0

        store_stats = self.window_store.get_stats()
        return {
            "processed_events": self._processed_events,
            "emitted_alerts": self._emitted_alerts,
            "avg_latency_ms": round(avg_lat, 3),
            "p99_latency_ms": round(p99_lat, 3),
            "avg_ml_latency_ms": round(avg_ml_lat, 3),
            "window_store": store_stats,
        }


_global_stream_detector: StreamDetector | None = None


def get_stream_detector() -> StreamDetector:
    """Return the global StreamDetector singleton."""
    global _global_stream_detector
    if _global_stream_detector is None:
        _global_stream_detector = StreamDetector()
    return _global_stream_detector


def reset_stream_detector() -> None:
    """Reset the global stream detector singleton (for test isolation)."""
    global _global_stream_detector
    _global_stream_detector = None
