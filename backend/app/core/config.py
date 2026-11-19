"""Application configuration.

All paths are resolved relative to the *backend* directory so that the
application behaves identically no matter which working directory uvicorn or
alembic is started from. This removes the previous ambiguity where running
from the repository root and from ``backend/`` pointed at two different
SQLite files.
"""

from functools import lru_cache
from pathlib import Path
from typing import List

from pydantic_settings import BaseSettings, SettingsConfigDict

BACKEND_DIR = Path(__file__).resolve().parents[2]
PROJECT_ROOT = BACKEND_DIR.parent

_DEFAULT_CORS = "http://localhost:5173,http://127.0.0.1:5173"


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_file=(str(BACKEND_DIR / ".env"), str(PROJECT_ROOT / ".env")),
        env_file_encoding="utf-8",
        extra="ignore",
        case_sensitive=False,
        protected_namespaces=("settings_",),
    )

    app_name: str = "Dark Web Threat Actor De-anonymization and Intelligence Platform"
    app_version: str = "1.0.0"
    environment: str = "development"

    secret_key: str = "change-me"
    access_token_expire_minutes: int = 60
    database_url: str = "sqlite:///./data/app.db"

    cors_origins: str = _DEFAULT_CORS

    model_dir: str = "./models"
    synthetic_data_dir: str = "./data/synthetic"

    max_upload_bytes: int = 5_000_000

    # Minimum word count before a stylometric comparison is considered usable.
    min_style_words: int = 20
    # Minimum timeline events before behavioural comparison is considered usable.
    min_behaviour_events: int = 3
    # Score at or above which an ML similarity may be offered as an inferred link.
    inference_threshold: float = 0.6

    # ---- External intelligence feeds (all public unless noted) ----
    aptnotes_url: str = (
        "https://raw.githubusercontent.com/aptnotes/data/master/APTnotes.json"
    )
    threatfox_url: str = "https://threatfox-api.abuse.ch/api/v1/"
    urlhaus_recent_url: str = "https://urlhaus-api.abuse.ch/v1/urls/recent/"
    mitre_attack_url: str = (
        "https://raw.githubusercontent.com/mitre-attack/attack-stix-data/master/"
        "enterprise-attack/enterprise-attack.json"
    )
    # ThreatFox requires an Abuse.ch Auth-Key for queries; leave empty to disable.
    abuse_ch_auth_key: str = ""
    feed_timeout_seconds: float = 30.0
    feed_max_retries: int = 2

    # ---- Scoring defaults (weights sum to 1.0) ----
    weight_identifier: float = 0.35
    weight_stylometric: float = 0.2
    weight_behavioural: float = 0.2
    weight_temporal: float = 0.15
    weight_infrastructure: float = 0.1

    @property
    def default_weights(self) -> dict:
        return {
            "identifier": self.weight_identifier,
            "stylometric": self.weight_stylometric,
            "behavioural": self.weight_behavioural,
            "temporal": self.weight_temporal,
            "infrastructure": self.weight_infrastructure,
        }

    @property
    def cors_origin_list(self) -> List[str]:
        raw = (self.cors_origins or "").strip()
        if raw in ("", "*"):
            return ["*"]
        return [item.strip() for item in raw.split(",") if item.strip()]

    def resolve_path(self, value: str) -> Path:
        """Resolve a configured filesystem path relative to the backend dir."""
        path = Path(value).expanduser()
        return path if path.is_absolute() else (BACKEND_DIR / path).resolve()

    @property
    def model_path(self) -> Path:
        return self.resolve_path(self.model_dir)

    @property
    def sqlalchemy_url(self) -> str:
        """Return the database URL with SQLite relative paths made absolute."""
        url = self.database_url
        prefix = "sqlite:///"
        if not url.startswith(prefix):
            return url
        raw = url[len(prefix):]
        if not raw or raw.startswith(":memory:"):
            return url
        path = Path(raw)
        if not path.is_absolute():
            path = (BACKEND_DIR / path).resolve()
        # sqlite:///C:/... on Windows needs three slashes plus drive letter;
        # Path.as_posix() gives C:/... which sqlite:/// accepts.
        return f"sqlite:///{path.as_posix()}"

    @property
    def database_path(self) -> Path | None:
        url = self.sqlalchemy_url
        prefix = "sqlite:///"
        if not url.startswith(prefix):
            return None
        raw = url[len(prefix):]
        if not raw or raw.startswith(":memory:"):
            return None
        return Path(raw)


@lru_cache
def get_settings() -> Settings:
    return Settings()
