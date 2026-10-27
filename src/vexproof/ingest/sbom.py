"""Extract PyPI packages from CycloneDX or SPDX JSON documents.

Only what the pipeline needs is read: name, version, purl. Everything else is ignored.
"""

from __future__ import annotations

import json
from collections.abc import Iterable, Mapping
from pathlib import Path
from typing import Any
from urllib.parse import unquote

from vexproof.domain import Package
from vexproof.errors import IngestError

_PYPI_PURL_PREFIX = "pkg:pypi/"


def _purl_name_version(purl: str) -> tuple[str, str] | None:
    """Parse `pkg:pypi/<name>@<version>[?qualifiers][#subpath]`."""
    if not purl.startswith(_PYPI_PURL_PREFIX):
        return None
    body = purl.removeprefix(_PYPI_PURL_PREFIX).split("?", 1)[0].split("#", 1)[0]
    name, sep, version = body.partition("@")
    if not sep or not name or not version:
        return None
    return unquote(name), unquote(version)


def _cyclonedx_purls(doc: Mapping[str, Any]) -> Iterable[str]:
    stack: list[Any] = list(doc.get("components") or [])
    while stack:
        component = stack.pop()
        if not isinstance(component, dict):
            continue
        purl = component.get("purl")
        if isinstance(purl, str):
            yield purl
        stack.extend(component.get("components") or [])


def _spdx_purls(doc: Mapping[str, Any]) -> Iterable[str]:
    for package in doc.get("packages") or []:
        if not isinstance(package, dict):
            continue
        for ref in package.get("externalRefs") or []:
            if isinstance(ref, dict) and ref.get("referenceType") == "purl":
                locator = ref.get("referenceLocator")
                if isinstance(locator, str):
                    yield locator


def packages_from_sbom(
    doc: Mapping[str, Any], direct_names: frozenset[str] = frozenset()
) -> tuple[Package, ...]:
    """Return unique PyPI packages, sorted by name, marking direct dependencies."""
    if doc.get("bomFormat") == "CycloneDX":
        purls = _cyclonedx_purls(doc)
    elif "spdxVersion" in doc:
        purls = _spdx_purls(doc)
    else:
        raise IngestError("unsupported SBOM: expected CycloneDX JSON or SPDX JSON")

    found: dict[tuple[str, str], Package] = {}
    for purl in purls:
        parsed = _purl_name_version(purl)
        if parsed is None:
            continue
        name, version = parsed
        package = Package(name=name, version=version, purl=purl)
        package = package.model_copy(update={"direct": package.name in direct_names})
        found.setdefault((package.name, package.version), package)
    return tuple(sorted(found.values(), key=lambda p: (p.name, p.version)))


def load_sbom(path: Path) -> dict[str, Any]:
    try:
        doc = json.loads(path.read_text(encoding="utf-8"))
    except OSError as exc:
        raise IngestError(f"cannot read SBOM {path}: {exc}") from exc
    except json.JSONDecodeError as exc:
        raise IngestError(f"SBOM {path} is not valid JSON: {exc}") from exc
    if not isinstance(doc, dict):
        raise IngestError(f"SBOM {path} must be a JSON object")
    return doc
