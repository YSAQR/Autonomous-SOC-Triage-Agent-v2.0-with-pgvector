"""SQLAlchemy 2.0 engine, pgvector extension bootstrap, and session factory."""

from __future__ import annotations

from collections.abc import Generator

from sqlalchemy import create_engine, text
from sqlalchemy.orm import Session, sessionmaker

from app.core.config import get_settings
from app.core.logging import get_logger
from app.db.models import Base

logger = get_logger(__name__)

settings = get_settings()

# pool_pre_ping + pool_recycle=300 handles Neon serverless scale-to-zero cleanly
engine = create_engine(
    settings.database_url,
    pool_pre_ping=True,
    pool_recycle=300,
    pool_size=5,
    max_overflow=10,
    future=True,
)

SessionLocal = sessionmaker(
    bind=engine,
    autocommit=False,
    autoflush=False,
    expire_on_commit=False,
    class_=Session,
)


def init_db() -> None:
    """Enable pgvector extension and create all PostgreSQL tables if missing."""
    logger.info("Initializing PostgreSQL + pgvector schema.")
    with engine.begin() as conn:
        conn.execute(text("CREATE EXTENSION IF NOT EXISTS vector"))
    Base.metadata.create_all(bind=engine)


def check_db_health() -> bool:
    """Verify live PostgreSQL connectivity."""
    try:
        with engine.connect() as conn:
            conn.execute(text("SELECT 1"))
        return True
    except Exception as exc:  # pragma: no cover - runtime connectivity check
        logger.error("Database health check failed: %s", exc)
        return False


def get_db() -> Generator[Session, None, None]:
    """FastAPI dependency yielding a scoped SQLAlchemy session."""
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()
