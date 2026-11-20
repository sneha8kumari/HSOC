"""
SQLAlchemy 2 ORM models and session management.

We use SQLite for the prototype.  The DATABASE_URL in .env can be
swapped for any SQLAlchemy-compatible database URL without code changes.
"""

from __future__ import annotations

import os
from datetime import datetime
from typing import Generator

from sqlalchemy import (
    JSON,
    Boolean,
    DateTime,
    Float,
    Integer,
    String,
    Text,
    create_engine,
)
from sqlalchemy.orm import DeclarativeBase, Mapped, Session, mapped_column, sessionmaker

# ---------------------------------------------------------------------------
# Engine and session factory
# ---------------------------------------------------------------------------

_DATABASE_URL: str = os.getenv("DATABASE_URL", "sqlite:///./data/hsoc.db")

# connect_args only needed for SQLite (thread safety)
_connect_args = {"check_same_thread": False} if _DATABASE_URL.startswith("sqlite") else {}

engine = create_engine(
    _DATABASE_URL,
    connect_args=_connect_args,
    echo=False,  # set to True for SQL debugging
)

if _DATABASE_URL.startswith("sqlite"):
    from sqlalchemy import event

    @event.listens_for(engine, "connect")
    def _set_sqlite_pragma(dbapi_connection: Any, connection_record: Any) -> None:
        try:
            cursor = dbapi_connection.cursor()
            cursor.execute("PRAGMA journal_mode=WAL")
            cursor.execute("PRAGMA synchronous=NORMAL")
            cursor.close()
        except Exception:
            pass

SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)


def get_db() -> Generator[Session, None, None]:
    """FastAPI dependency — yields a DB session and closes it afterwards."""
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


# ---------------------------------------------------------------------------
# ORM base
# ---------------------------------------------------------------------------


class Base(DeclarativeBase):
    """Declarative base for all ORM models."""


# ---------------------------------------------------------------------------
# ORM models
# ---------------------------------------------------------------------------


class EventORM(Base):
    """Persisted normalised security event."""

    __tablename__ = "events"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    event_id: Mapped[str] = mapped_column(String(36), unique=True, nullable=False, index=True)
    ts: Mapped[datetime] = mapped_column(DateTime, nullable=False, index=True)
    source_type: Mapped[str] = mapped_column(String(32), nullable=False)
    host: Mapped[str | None] = mapped_column(String(256))
    src_ip: Mapped[str | None] = mapped_column(String(45))
    dst_ip: Mapped[str | None] = mapped_column(String(45))
    dst_port: Mapped[int | None] = mapped_column(Integer)
    user: Mapped[str | None] = mapped_column(String(128))
    action: Mapped[str] = mapped_column(String(64), nullable=False)
    outcome: Mapped[str] = mapped_column(String(16), nullable=False, default="unknown")
    asset_criticality: Mapped[int] = mapped_column(Integer, default=1)
    asset_role: Mapped[str] = mapped_column(String(64), default="unknown")
    asset_owner: Mapped[str] = mapped_column(String(128), default="unknown")
    user_privileged: Mapped[bool] = mapped_column(Boolean, default=False)
    features: Mapped[dict] = mapped_column(JSON, default=dict)
    label: Mapped[str | None] = mapped_column(String(64))
    raw: Mapped[str] = mapped_column(Text, nullable=False)
    repeat_count: Mapped[int] = mapped_column(Integer, default=1)
    raw_hash: Mapped[str] = mapped_column(String(64), index=True)  # SHA-256 for dedup
    is_simulated: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False, index=True)


class QuarantineORM(Base):
    """Malformed or unrecognised log records."""

    __tablename__ = "quarantine"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    record_id: Mapped[str] = mapped_column(String(36), unique=True, nullable=False)
    ts: Mapped[datetime] = mapped_column(DateTime, nullable=False)
    source_type: Mapped[str | None] = mapped_column(String(32))
    raw: Mapped[str] = mapped_column(Text, nullable=False)
    reason: Mapped[str] = mapped_column(String(256), nullable=False)
    parser: Mapped[str] = mapped_column(String(64), nullable=False)


class AlertORM(Base):
    """Persisted detection alert."""

    __tablename__ = "alerts"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    alert_id: Mapped[str] = mapped_column(String(36), unique=True, nullable=False, index=True)
    ts: Mapped[datetime] = mapped_column(DateTime, nullable=False, index=True)
    rule_ids: Mapped[list] = mapped_column(JSON, default=list)
    model_id: Mapped[str | None] = mapped_column(String(64))
    ml_score: Mapped[float | None] = mapped_column(Float)
    conf: Mapped[float] = mapped_column(Float, nullable=False)
    technique: Mapped[str | None] = mapped_column(String(32))
    tactic: Mapped[str | None] = mapped_column(String(64))
    domain: Mapped[str] = mapped_column(String(32), default="unknown")
    src_ip: Mapped[str | None] = mapped_column(String(45))
    dst_host: Mapped[str | None] = mapped_column(String(256))
    user: Mapped[str | None] = mapped_column(String(128))
    evidence_event_ids: Mapped[list] = mapped_column(JSON, default=list)
    description: Mapped[str] = mapped_column(Text, default="")
    incident_id: Mapped[str | None] = mapped_column(String(36), index=True)
    is_simulated: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False, index=True)


class IncidentORM(Base):
    """Persisted correlated incident."""

    __tablename__ = "incidents"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    incident_id: Mapped[str] = mapped_column(String(36), unique=True, nullable=False, index=True)
    created_at: Mapped[datetime] = mapped_column(DateTime, nullable=False)
    updated_at: Mapped[datetime] = mapped_column(DateTime, nullable=False)
    status: Mapped[str] = mapped_column(String(16), default="open")
    alert_ids: Mapped[list] = mapped_column(JSON, default=list)
    entity_keys: Mapped[list] = mapped_column(JSON, default=list)
    timeline: Mapped[list] = mapped_column(JSON, default=list)
    techniques: Mapped[list] = mapped_column(JSON, default=list)
    tactics: Mapped[list] = mapped_column(JSON, default=list)
    domain: Mapped[str] = mapped_column(String(32), default="unknown")
    secondary_domains: Mapped[list] = mapped_column(JSON, default=list)
    severity: Mapped[str] = mapped_column(String(16), default="low")
    risk_score: Mapped[int] = mapped_column(Integer, default=0)
    risk_rationale: Mapped[str] = mapped_column(Text, default="")
    out_of_order_stage: Mapped[bool] = mapped_column(Boolean, default=False)
    predicted_next: Mapped[list] = mapped_column(JSON, default=list)
    report_id: Mapped[str | None] = mapped_column(String(36))
    is_simulated: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False, index=True)


class ReportORM(Base):
    """Persisted LLM/template report."""

    __tablename__ = "reports"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    report_id: Mapped[str] = mapped_column(String(36), unique=True, nullable=False, index=True)
    incident_id: Mapped[str] = mapped_column(String(36), nullable=False, index=True)
    generated_at: Mapped[datetime] = mapped_column(DateTime, nullable=False)
    generated_by: Mapped[str] = mapped_column(String(16), default="llm")
    model_name: Mapped[str] = mapped_column(String(128), default="")
    prompt_version: Mapped[str] = mapped_column(String(32), default="")
    latency_seconds: Mapped[float] = mapped_column(Float, default=0.0)
    retries: Mapped[int] = mapped_column(Integer, default=0)
    valid: Mapped[bool] = mapped_column(Boolean, default=False)
    severity: Mapped[str] = mapped_column(String(16), default="low")
    summary: Mapped[str] = mapped_column(Text, default="")
    evidence: Mapped[list] = mapped_column(JSON, default=list)
    attack_mapping: Mapped[list] = mapped_column(JSON, default=list)
    domain: Mapped[str] = mapped_column(String(32), default="unknown")
    predicted_next: Mapped[list] = mapped_column(JSON, default=list)
    remediation: Mapped[list] = mapped_column(JSON, default=list)
    uncertainty: Mapped[str] = mapped_column(Text, default="")
    chunk_ids_used: Mapped[list] = mapped_column(JSON, default=list)
    full_json: Mapped[dict] = mapped_column(JSON, default=dict)


class FeedbackORM(Base):
    """Analyst feedback on a report."""

    __tablename__ = "feedback"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    feedback_id: Mapped[str] = mapped_column(String(36), unique=True, nullable=False, index=True)
    report_id: Mapped[str] = mapped_column(String(36), nullable=False, index=True)
    incident_id: Mapped[str] = mapped_column(String(36), nullable=False, index=True)
    ts: Mapped[datetime] = mapped_column(DateTime, nullable=False)
    decision: Mapped[str] = mapped_column(String(16), nullable=False)
    edited_report: Mapped[dict | None] = mapped_column(JSON)
    comment: Mapped[str] = mapped_column(Text, default="")
    approved_steps: Mapped[list] = mapped_column(JSON, default=list)
    declined_steps: Mapped[list] = mapped_column(JSON, default=list)


class AgentTraceORM(Base):
    """Execution trace for an agent step in the orchestrator state machine."""

    __tablename__ = "agent_traces"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    trace_id: Mapped[str] = mapped_column(String(36), unique=True, nullable=False, index=True)
    incident_id: Mapped[str] = mapped_column(String(36), nullable=False, index=True)
    step_index: Mapped[int] = mapped_column(Integer, nullable=False)
    agent_name: Mapped[str] = mapped_column(String(64), nullable=False)
    state: Mapped[str] = mapped_column(String(32), nullable=False)
    inputs: Mapped[dict] = mapped_column(JSON, default=dict)
    tool_calls: Mapped[list] = mapped_column(JSON, default=list)
    output_message: Mapped[str] = mapped_column(Text, default="")
    latency_ms: Mapped[float] = mapped_column(Float, default=0.0)
    tokens: Mapped[int] = mapped_column(Integer, default=0)
    created_at: Mapped[datetime] = mapped_column(DateTime, nullable=False)



# ---------------------------------------------------------------------------


class SOARActionORM(Base):
    """Persisted SOAR containment action audit log."""

    __tablename__ = "soar_actions"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    action_id: Mapped[str] = mapped_column(String(64), unique=True, index=True, nullable=False)
    incident_id: Mapped[str] = mapped_column(String(64), index=True, nullable=False)
    action_type: Mapped[str] = mapped_column(String(32), nullable=False)  # block_ip, isolate_host, disable_user
    target: Mapped[str] = mapped_column(String(255), nullable=False)
    status: Mapped[str] = mapped_column(String(32), nullable=False)  # simulated, executed, rolled_back, rejected, refused, expired
    is_dry_run: Mapped[bool] = mapped_column(Boolean, default=True, nullable=False)
    approved_by: Mapped[str] = mapped_column(String(64), default="analyst", nullable=False)
    evidence_alert_ids: Mapped[list] = mapped_column(JSON, default=list, nullable=False)
    details: Mapped[dict] = mapped_column(JSON, default=dict, nullable=False)
    ttl_minutes: Mapped[int] = mapped_column(Integer, default=30, nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow, nullable=False)
    expires_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)
    rolled_back_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)
    rollback_reason: Mapped[str | None] = mapped_column(String(255), nullable=True)


# Database initialisation
# ---------------------------------------------------------------------------


def init_db() -> None:
    """Create all tables if they do not exist, and ensure backward-compatible schema migrations."""
    import os
    from sqlalchemy import text

    os.makedirs("data", exist_ok=True)
    Base.metadata.create_all(bind=engine)

    # Safe backward-compatible SQLite migration for new columns
    if _DATABASE_URL.startswith("sqlite"):
        try:
            with engine.connect() as conn:
                for table in ["events", "alerts", "incidents"]:
                    try:
                        conn.execute(text(f"ALTER TABLE {table} ADD COLUMN is_simulated BOOLEAN DEFAULT 0"))
                        conn.commit()
                    except Exception:
                        pass
        except Exception:
            pass
