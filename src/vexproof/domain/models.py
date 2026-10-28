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


class FixCommit(Frozen):
    """A commit on GitHub that fixed the vulnerability, as named by the advisory."""

    owner: str = Field(min_length=1)
    repo: str = Field(min_length=1)
    sha: str = Field(pattern=r"^[0-9a-f]{7,40}$")

    @property
    def url(self) -> str:
        return f"https://github.com/{self.owner}/{self.repo}/commit/{self.sha}"


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
    fix_commits: tuple[FixCommit, ...] = ()
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


class Candidate(Frozen):
    """A function changed by a fix commit: a possible vulnerable symbol, verified to exist."""

    qualname: str = Field(
        min_length=1, description="module.Class.function as in the installed code"
    )
    module: str = Field(min_length=1)
    file: str = Field(min_length=1, description="path inside the installed package")
    changed_lines: int = Field(ge=0, description="lines of this function the fix touched")
    commits: tuple[str, ...] = ()
    diff: str = Field(default="", description="the fix's change to this function (-U0 hunks)")


class Evidence(Frozen):
    """Everything vexproof knows about one alert. Later chapters add symbols and call chains."""

    level: Level
    candidates: tuple[Candidate, ...] = ()
    changed_modules: tuple[str, ...] = ()
    fix_commits: tuple[str, ...] = ()
    vulnerable_symbols: tuple[str, ...] = ()
    symbol_quote: str | None = None
    symbol_model: str | None = Field(default=None, description="model and prompt that chose them")
    call_chain: tuple[Hop, ...] = ()
    checks_passed: tuple[str, ...] = ()
    notes: tuple[str, ...] = ()


class Finding(Frozen):
    """One alert: a package version matched by one advisory."""

    id: str
    package: Package
    advisory: Advisory
    signals: Signals = Signals()
    verdict: Verdict | None = None
    justification: str | None = Field(
        default=None, description="OpenVEX justification when verdict is not_affected"
    )
    evidence: Evidence | None = None


class ServiceProfile(Frozen):
    """Business context stated by the user. It only affects priority, never reachability."""

    service: str = Field(min_length=1)
    internet_facing: bool
    handles_personal_data: bool
    criticality: Literal["low", "medium", "high"]
    entrypoints: tuple[str, ...] = ()
