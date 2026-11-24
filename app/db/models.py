"""SQLAlchemy 2.0 ORM models with pgvector playbook storage and full auditability."""

from __future__ import annotations

import uuid
from datetime import datetime, timezone
from typing import Any

from pgvector.sqlalchemy import Vector
from sqlalchemy import (
    JSON,
    Boolean,
    DateTime,
    Float,
    ForeignKey,
    Integer,
    String,
    Text,
)
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column, relationship


def _utcnow() -> datetime:
    return datetime.now(timezone.utc)


class Base(DeclarativeBase):
    """Base declarative class for all SOC triage database models."""


class RawLogBatch(Base):
    """Time-windowed batch of suspicious log events with SHA-256 idempotency hash."""

    __tablename__ = "raw_log_batches"

    id: Mapped[str] = mapped_column(
        String(36),
        primary_key=True,
        default=lambda: str(uuid.uuid4()),
    )
    content_hash: Mapped[str] = mapped_column(
        String(64),
        nullable=False,
        index=True,
    )
    source_type: Mapped[str] = mapped_column(String(32), nullable=False, index=True)
    window_start: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    window_end: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    total_lines_ingested: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    suspicious_event_count: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    extracted_ips: Mapped[list[str]] = mapped_column(JSON, nullable=False, default=list)
    extracted_usernames: Mapped[list[str]] = mapped_column(JSON, nullable=False, default=list)
    extracted_endpoints: Mapped[list[str]] = mapped_column(JSON, nullable=False, default=list)
    raw_excerpt: Mapped[str] = mapped_column(Text, nullable=False)
    ti_cache_hits: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    ti_cache_misses: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        default=_utcnow,
        index=True,
    )

    incidents: Mapped[list[Incident]] = relationship(
        back_populates="batch",
        cascade="all, delete-orphan",
    )


class IoCCache(Base):
    """24-hour TTL Threat Intelligence cache keyed by public IP address."""

    __tablename__ = "ioc_cache"

    ip_address: Mapped[str] = mapped_column(String(64), primary_key=True)
    abuse_confidence_score: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    total_reports: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    usage_type: Mapped[str] = mapped_column(String(128), nullable=False, default="Unknown")
    country_code: Mapped[str] = mapped_column(String(16), nullable=False, default="N/A")
    country_name: Mapped[str] = mapped_column(String(128), nullable=False, default="Unknown")
    isp: Mapped[str] = mapped_column(String(256), nullable=False, default="Unknown")
    asn: Mapped[str] = mapped_column(String(128), nullable=False, default="Unknown")
    is_tor: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    otx_checked: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    otx_pulse_count: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    otx_tags: Mapped[list[str]] = mapped_column(JSON, nullable=False, default=list)
    raw_payload: Mapped[dict[str, Any]] = mapped_column(JSON, nullable=False, default=dict)
    cached_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        default=_utcnow,
    )
    expires_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        index=True,
    )


class PlaybookChunk(Base):
    """pgvector-backed defensive SOC playbook section for single-DB RAG."""

    __tablename__ = "playbook_chunks"

    id: Mapped[str] = mapped_column(String(128), primary_key=True)
    playbook_file: Mapped[str] = mapped_column(String(128), nullable=False, index=True)
    section_title: Mapped[str] = mapped_column(String(256), nullable=False)
    mitre_id: Mapped[str] = mapped_column(String(32), nullable=False, index=True)
    content: Mapped[str] = mapped_column(Text, nullable=False)
    embedding: Mapped[list[float]] = mapped_column(Vector(768), nullable=False)
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        default=_utcnow,
        onupdate=_utcnow,
    )


class Incident(Base):
    """Auditable SOC triage verdict with tool evidence, prompt version, and cost telemetry."""

    __tablename__ = "incidents"

    id: Mapped[str] = mapped_column(
        String(36),
        primary_key=True,
        default=lambda: str(uuid.uuid4()),
    )
    batch_id: Mapped[str] = mapped_column(
        String(36),
        ForeignKey("raw_log_batches.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    severity: Mapped[str] = mapped_column(String(16), nullable=False, index=True)
    status: Mapped[str] = mapped_column(
        String(32),
        nullable=False,
        default="Open",
        index=True,
    )
    confidence_score: Mapped[float] = mapped_column(Float, nullable=False, default=0.75)
    false_positive_probability: Mapped[float] = mapped_column(Float, nullable=False, default=0.1)
    mitre_attack_id: Mapped[str] = mapped_column(String(32), nullable=False, index=True)
    technique_name: Mapped[str] = mapped_column(String(128), nullable=False)
    attack_story: Mapped[str] = mapped_column(Text, nullable=False)
    remediation_commands: Mapped[list[str]] = mapped_column(JSON, nullable=False, default=list)
    playbook_reference: Mapped[str] = mapped_column(String(256), nullable=False)
    ioc_enrichment: Mapped[list[dict[str, Any]]] = mapped_column(JSON, nullable=False, default=list)
    evidence: Mapped[dict[str, Any]] = mapped_column(JSON, nullable=False, default=dict)
    routing_reason: Mapped[str] = mapped_column(String(256), nullable=False, default="rapid_triage")
    prompt_version: Mapped[str] = mapped_column(String(32), nullable=False, default="v2.0")
    latency_ms: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    token_usage: Mapped[dict[str, Any]] = mapped_column(JSON, nullable=False, default=dict)
    source_type: Mapped[str] = mapped_column(String(32), nullable=False, default="auth.log")
    model_used: Mapped[str] = mapped_column(
        String(64),
        nullable=False,
        default="gemini-3.5-flash-lite",
    )
    otx_queried: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        default=_utcnow,
        index=True,
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        default=_utcnow,
        onupdate=_utcnow,
    )

    batch: Mapped[RawLogBatch] = relationship(back_populates="incidents")
