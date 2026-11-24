"""Application configuration using Pydantic Settings v2."""

from __future__ import annotations

from functools import lru_cache
from pathlib import Path

from pydantic import Field, field_validator
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    """Centralized runtime settings loaded from environment variables or .env."""

    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        case_sensitive=False,
        extra="ignore",
    )

    # Application
    app_name: str = "Autonomous SOC Triage Agent"
    app_env: str = "production"
    log_level: str = "INFO"
    prompt_version: str = "v2.0"
    api_host: str = "0.0.0.0"
    api_port: int = 8000
    api_base_url: str = "http://127.0.0.1:8000"

    # Single Database: PostgreSQL + pgvector (Docker local or Neon / Supabase)
    database_url: str = Field(
        default="postgresql+psycopg://soc_user:soc_pass@localhost:5432/soc_triage",
        description="SQLAlchemy-compatible PostgreSQL connection string.",
    )

    # Google Gemini API (Single Free Key — active model defaults)
    gemini_api_key: str = Field(default="", description="Google AI Studio Gemini API key.")
    gemini_flash_model: str = "gemini-3.5-flash-lite"
    gemini_pro_model: str = "gemini-3.6-flash"
    gemini_embedding_model: str = "gemini-embedding-001"
    embedding_dimensions: int = 768

    # Free Threat Intelligence APIs
    abuseipdb_api_key: str = Field(
        default="",
        description="AbuseIPDB v2 API key (free tier: 1,000 checks/day).",
    )
    otx_api_key: str = Field(
        default="",
        description="AlienVault OTX API key (free tier for deep IoC correlation).",
    )
    ip_api_base_url: str = "http://ip-api.com/json"
    ioc_cache_ttl_hours: int = 24
    otx_confidence_threshold: float = 0.60
    max_investigation_loops: int = 1
    http_timeout_seconds: float = 10.0

    # Local Playbooks & Sample Logs
    playbooks_dir: str = "./data/playbooks"
    sample_logs_dir: str = "./data/sample_logs"

    # Log Parser Batching
    batch_window_minutes: int = 5
    max_events_per_batch: int = 100

    @field_validator("database_url", mode="before")
    @classmethod
    def normalize_database_url(cls, value: str) -> str:
        """Normalize Neon/Supabase/Render postgres:// URLs for SQLAlchemy + psycopg3."""
        if not isinstance(value, str):
            return value
        cleaned = value.strip()
        if cleaned.startswith("postgres://"):
            return cleaned.replace("postgres://", "postgresql+psycopg://", 1)
        if cleaned.startswith("postgresql://") and "+psycopg" not in cleaned:
            return cleaned.replace("postgresql://", "postgresql+psycopg://", 1)
        return cleaned

    @property
    def playbooks_path(self) -> Path:
        """Resolved filesystem path to Markdown SOC playbooks."""
        return Path(self.playbooks_dir).resolve()

    @property
    def sample_logs_path(self) -> Path:
        """Resolved filesystem path to static sample attack logs."""
        return Path(self.sample_logs_dir).resolve()


@lru_cache(maxsize=1)
def get_settings() -> Settings:
    """Return a cached singleton instance of application settings."""
    return Settings()
