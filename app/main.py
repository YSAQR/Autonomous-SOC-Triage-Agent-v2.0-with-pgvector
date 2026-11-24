"""FastAPI application entrypoint with PostgreSQL + pgvector lifespan bootstrap."""

from __future__ import annotations

from collections.abc import AsyncIterator
from contextlib import asynccontextmanager

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from app.api.routes import router
from app.core.config import get_settings
from app.core.logging import configure_logging, get_logger
from app.db.session import SessionLocal, init_db
from app.engine.rag import get_playbook_rag

settings = get_settings()
configure_logging(settings.log_level)
logger = get_logger(__name__)


@asynccontextmanager
async def lifespan(_app: FastAPI) -> AsyncIterator[None]:
    """Initialize PostgreSQL + pgvector tables and index local Markdown SOC playbooks."""
    logger.info("Starting %s (%s, prompt=%s)", settings.app_name, settings.app_env, settings.prompt_version)
    try:
        init_db()
        with SessionLocal() as db:
            indexed = get_playbook_rag().index_playbooks(db)
            logger.info("pgvector Playbook RAG ready with %d indexed sections.", indexed)
    except Exception as exc:
        logger.error("Startup DB/RAG initialization deferred: %s", exc)

    yield
    logger.info("Shutting down %s", settings.app_name)


app = FastAPI(
    title=settings.app_name,
    version="2.0.0",
    description=(
        "Hardened Defensive Autonomous SOC Triage Pipeline powered by Google Gemini, "
        "LangGraph evidence-based routing, PostgreSQL + pgvector RAG, 24h Threat Intel "
        "caching, and an interactive SOC Analyst Copilot."
    ),
    lifespan=lifespan,
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

app.include_router(router)
