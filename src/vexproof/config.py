"""Runtime settings, read from environment variables and an optional .env file."""

from __future__ import annotations

from pathlib import Path
from typing import Literal

from pydantic import Field, SecretStr
from pydantic_settings import BaseSettings, SettingsConfigDict

from vexproof import __version__


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_file=".env", env_file_encoding="utf-8", extra="ignore", frozen=True
    )

    cache_dir: Path = Field(default=Path(".vexproof-cache"), alias="VEXPROOF_CACHE_DIR")
    http_timeout_s: float = Field(default=20.0, gt=0, alias="VEXPROOF_HTTP_TIMEOUT_S")
    osv_url: str = Field(default="https://api.osv.dev", alias="VEXPROOF_OSV_URL")
    kev_url: str = Field(
        default=(
            "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
        ),
        alias="VEXPROOF_KEV_URL",
    )
    epss_url: str = Field(default="https://api.first.org/data/v1/epss", alias="VEXPROOF_EPSS_URL")
    pypi_url: str = Field(default="https://pypi.org", alias="VEXPROOF_PYPI_URL")
    max_download_mb: int = Field(default=150, gt=0, alias="VEXPROOF_MAX_DOWNLOAD_MB")
    workers: int = Field(default=8, ge=1, le=32, alias="VEXPROOF_WORKERS")
    # Secrets are optional here; each stage that needs one checks and fails with a clear message.
    model_api_key: SecretStr | None = Field(default=None, alias="MODEL_API_KEY")
    model_base_url: str = Field(default="https://api.meta.ai/v1", alias="VEXPROOF_MODEL_BASE_URL")
    model: str = Field(default="muse-spark-1.1", alias="VEXPROOF_MODEL")
    model_api: Literal["responses", "chat"] = Field(default="responses", alias="VEXPROOF_MODEL_API")
    model_mode: Literal["cache", "replay", "live"] = Field(
        default="cache", alias="VEXPROOF_MODEL_MODE"
    )
    model_max_tokens: int = Field(default=1_000_000, gt=0, alias="VEXPROOF_MODEL_MAX_TOKENS")
    model_timeout_s: float = Field(default=120.0, gt=0, alias="VEXPROOF_MODEL_TIMEOUT_S")
    model_workers: int = Field(default=4, ge=1, le=32, alias="VEXPROOF_MODEL_WORKERS")
    localhost_alias: str | None = Field(
        default=None,
        alias="VEXPROOF_LOCALHOST_ALIAS",
        description="Inside a container, the name of the host computer (host.docker.internal), so "
        "a model server configured at localhost, such as Ollama, is still found",
    )
    price_input_per_m: float | None = Field(default=None, ge=0, alias="VEXPROOF_PRICE_INPUT_PER_M")
    price_output_per_m: float | None = Field(
        default=None, ge=0, alias="VEXPROOF_PRICE_OUTPUT_PER_M"
    )

    @property
    def user_agent(self) -> str:
        return f"vexproof/{__version__} (+https://github.com/henrymbuguak/vexproof)"
