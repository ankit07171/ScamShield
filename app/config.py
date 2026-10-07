"""Runtime configuration, read from environment variables."""
from __future__ import annotations

import os
from dataclasses import dataclass
from functools import lru_cache
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent.parent


def _bool(name: str, default: bool) -> bool:
    return os.getenv(name, str(default)).strip().lower() in {"1", "true", "yes", "on"}


def _list(name: str) -> tuple[str, ...]:
    return tuple(x.strip() for x in os.getenv(name, "").split(",") if x.strip())


@dataclass(frozen=True)
class Settings:
    database_url: str
    redis_url: str | None
    api_keys: tuple[str, ...]
    admin_api_keys: tuple[str, ...]
    auth_required: bool
    rate_limit_per_minute: int
    network_enabled: bool  # follow redirects / fetch URLs (sandboxed)
    whois_enabled: bool
    model_path: str
    cache_ttl: int


@lru_cache
def get_settings() -> Settings:
    return Settings(
        database_url=os.getenv("DATABASE_URL", f"sqlite:///{BASE_DIR / 'scamshield.db'}"),
        redis_url=os.getenv("REDIS_URL") or None,
        api_keys=_list("API_KEYS"),
        admin_api_keys=_list("ADMIN_API_KEYS"),
        auth_required=_bool("AUTH_REQUIRED", False),
        rate_limit_per_minute=int(os.getenv("RATE_LIMIT_PER_MINUTE", "60")),
        network_enabled=_bool("SCAMSHIELD_NETWORK", True),
        whois_enabled=_bool("WHOIS_ENABLED", False),
        model_path=os.getenv("MODEL_PATH", str(BASE_DIR / "models" / "text_clf.joblib")),
        cache_ttl=int(os.getenv("CACHE_TTL", "3600")),
    )
