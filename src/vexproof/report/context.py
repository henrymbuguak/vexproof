"""What every report needs to know about the scan, and how to name the scanned project."""

from __future__ import annotations

import re
from dataclasses import dataclass
from datetime import datetime
from pathlib import PurePath
from urllib.parse import quote

from vexproof.domain import Finding, ServiceProfile

_GITHUB = re.compile(r"^https://github\.com/([A-Za-z0-9_.-]+)/([A-Za-z0-9_.-]+?)(?:\.git)?/?$")


@dataclass(frozen=True)
class ReportContext:
    source: str
    commit: str | None
    findings: tuple[Finding, ...]
    generated_at: datetime
    tooling: str
    profile: ServiceProfile | None = None

    @property
    def product(self) -> str:
        """Package URL of the scanned project: pkg:github/<owner>/<repo>@<commit> when known."""
        return product_purl(self.source, self.commit)


def product_purl(source: str, commit: str | None) -> str:
    version = f"@{quote(commit, safe='')}" if commit else ""
    match = _GITHUB.match(source)
    if match:
        owner, repo = (quote(part.lower(), safe=".-_") for part in match.groups())
        return f"pkg:github/{owner}/{repo}{version}"
    name = PurePath(source.rstrip("/\\")).name or "project"
    return f"pkg:generic/{quote(name.lower(), safe='.-_')}{version}"


def package_purl(finding: Finding) -> str:
    package = finding.package
    if package.purl:
        return package.purl
    return f"pkg:pypi/{quote(package.name, safe='.-_')}@{quote(package.version, safe='.+!')}"


def short_symbol(qualname: str) -> str:
    """The last two parts of a dotted name: `IcoFile.frame`, `numberformat.format`."""
    return ".".join(qualname.split(".")[-2:])
