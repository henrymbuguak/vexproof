"""Frozen Pydantic models exchanged between pipeline stages.

Rules: models are immutable (frozen), reject unknown fields (extra="forbid"),
and use tuples rather than lists so instances are hashable and cannot be mutated.
"""

from __future__ import annotations

from enum import StrEnum
from typing import Literal

from packaging.utils import canonicalize_name
from pydantic import BaseModel, ConfigDict, Field, field_validator


class Frozen(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")


class Verdict(StrEnum):
    """Values match OpenVEX statuses so export is a direct mapping."""

    AFFECTED = "affected"
    NOT_AFFECTED = "not_affected"
    NEEDS_REVIEW = "under_investigation"


class Level(StrEnum):
    """Degradation ladder: the highest level of evidence available for an alert."""

    L0_NOT_IMPORTED = "L0"
    L1_SYMBOL = "L1"
    L2_MODULE = "L2"
    L3_NONE = "L3"


class Package(Frozen):
    name: str = Field(min_length=1, description="PEP 503 canonical distribution name")
    version: str = Field(min_length=1)
    direct: bool = False
    purl: str | None = None

    @field_validator("name")
    @classmethod
    def _canonical(cls, value: str) -> str:
        return str(canonicalize_name(value))


class Reference(Frozen):
    type: str
    url: str


class Advisory(Frozen):
    id: str = Field(min_length=1, description="OSV id, e.g. GHSA-... or PYSEC-...")
    aliases: tuple[str, ...] = ()
    summary: str = ""
    details: str = ""
    fixed_in: str | None = None
    references: tuple[Reference, ...] = ()
    cvss_vector: str | None = None
    severity_label: str | None = None
    disputed_by: str | None = Field(
        default=None,
        description="A reviewed GHSA alias whose ranges exclude the installed version",
    )
    source: Literal["osv.dev"] = "osv.dev"

    @property
    def cve_ids(self) -> tuple[str, ...]:
        ids = [a for a in (self.id, *self.aliases) if a.startswith("CVE-")]
        return tuple(dict.fromkeys(ids))


class Signals(Frozen):
    cvss: float | None = Field(default=None, ge=0.0, le=10.0)
    epss: float | None = Field(default=None, ge=0.0, le=1.0)
    epss_percentile: float | None = Field(default=None, ge=0.0, le=1.0)
    in_kev: bool = False


class Hop(Frozen):
    file: str = Field(min_length=1)
    line: int = Field(ge=1)
    symbol: str = Field(min_length=1)


class Evidence(Frozen):
    """Filled by later chapters (symbols, evidence engine). Defined now so the schema is stable."""

    level: Level
    vulnerable_symbols: tuple[str, ...] = ()
    symbol_quote: str | None = None
    call_chain: tuple[Hop, ...] = ()
    checks_passed: tuple[str, ...] = ()


class Finding(Frozen):
    """One alert: a package version matched by one advisory."""

    id: str
    package: Package
    advisory: Advisory
    signals: Signals = Signals()
    verdict: Verdict | None = None
    evidence: Evidence | None = None


class ServiceProfile(Frozen):
    """Business context stated by the user. It only affects priority, never reachability."""

    service: str = Field(min_length=1)
    internet_facing: bool
    handles_personal_data: bool
    criticality: Literal["low", "medium", "high"]
    entrypoints: tuple[str, ...] = ()
