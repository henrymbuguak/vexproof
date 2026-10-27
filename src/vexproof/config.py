"""Runtime settings, read from environment variables and an optional .env file."""

from __future__ import annotations

from pathlib import Path

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
    # Secrets are optional here; each stage that needs one checks and fails with a clear message.
    model_api_key: SecretStr | None = Field(default=None, alias="MODEL_API_KEY")
    github_token: SecretStr | None = Field(default=None, alias="GITHUB_TOKEN")

    @property
    def user_agent(self) -> str:
        return f"vexproof/{__version__} (+https://github.com/henrymbuguak/vexproof)"
