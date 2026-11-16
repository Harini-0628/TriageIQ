"""
Centralized application configuration.

Design decision: we use pydantic-settings instead of raw os.environ reads
because it gives us type validation, default values, and a single source
of truth for config that fails fast (at import time) if something required
is missing — rather than failing deep inside a request handler at 2am.
"""
from functools import lru_cache
from typing import List

from pydantic import Field, field_validator
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=".env", env_file_encoding="utf-8", extra="ignore")

    # --- App ---
    APP_NAME: str = "TriageIQ"
    APP_ENV: str = Field(default="development")  # development | staging | production
    DEBUG: bool = Field(default=False)
    API_V1_PREFIX: str = "/api/v1"

    # --- Security ---
    SECRET_KEY: str = Field(..., description="Used to sign JWTs. Must be set via env, never hardcoded.")
    ALGORITHM: str = "HS256"
    ACCESS_TOKEN_EXPIRE_MINUTES: int = 30
    REFRESH_TOKEN_EXPIRE_DAYS: int = 7

    # --- Database ---
    DATABASE_URL: str = Field(
        default="sqlite:///./triageiq_dev.db",
        description="Postgres in staging/prod (docker-compose), SQLite fallback for fast local dev/tests.",
    )

    # --- CORS ---
    ALLOWED_ORIGINS: List[str] = Field(default_factory=lambda: ["http://localhost:5173"])

    # --- Rate limiting ---
    RATE_LIMIT_PER_MINUTE: int = 60

    # --- External enrichment APIs ---
    NVD_API_BASE: str = "https://services.nvd.nist.gov/rest/json/cves/2.0"
    NVD_API_KEY: str = Field(default="", description="Optional — raises NVD rate limit from 5 to 50 req/30s")
    EPSS_API_BASE: str = "https://api.first.org/data/v1/epss"
    CISA_KEV_URL: str = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"

    # --- Logging ---
    LOG_LEVEL: str = "INFO"

    @field_validator("APP_ENV")
    @classmethod
    def validate_env(cls, v: str) -> str:
        allowed = {"development", "staging", "production", "test"}
        if v not in allowed:
            raise ValueError(f"APP_ENV must be one of {allowed}, got '{v}'")
        return v


@lru_cache
def get_settings() -> Settings:
    """
    Cached settings singleton. lru_cache means Settings() is constructed
    once per process, not on every request — cheap and avoids re-reading
    the .env file repeatedly.
    """
    return Settings()
