"""Choose the version that fixes an advisory for the version actually installed."""

from __future__ import annotations

from collections.abc import Iterator, Mapping
from typing import Any

from packaging.utils import canonicalize_name
from packaging.version import InvalidVersion, Version

_ORDER = {"introduced": 0, "fixed": 1, "last_affected": 1, "limit": 1}


def _version(text: str) -> Version | None:
    try:
        return Version(text)
    except InvalidVersion:
        return None


def _ecosystem_ranges(
    record: Mapping[str, Any], package: str
) -> Iterator[list[tuple[Version, str]]]:
    """Yield each PyPI ECOSYSTEM range for `package` as sorted (version, event-kind) pairs."""
    wanted = canonicalize_name(package)
    for affected in record.get("affected") or []:
        pkg = affected.get("package") or {}
        if pkg.get("ecosystem") != "PyPI" or canonicalize_name(str(pkg.get("name", ""))) != wanted:
            continue
        for rng in affected.get("ranges") or []:
            if rng.get("type") != "ECOSYSTEM":
                continue
            events = [
                (parsed, kind)
                for event in rng.get("events") or []
                for kind, value in event.items()
                if kind in _ORDER and (parsed := _version(str(value))) is not None
            ]
            yield sorted(events, key=lambda e: (e[0], _ORDER[e[1]]))


def _fix_for(
    events: list[tuple[Version, str]], current: Version
) -> tuple[Version | None, list[Version]]:
    """Return (fix of the interval containing `current`, every fixed bound seen)."""
    fixes: list[Version] = []
    start: Version | None = None
    for version, kind in events:
        if kind == "introduced":
            start = version
            continue
        if kind == "fixed":
            if start is not None and start <= current < version:
                return version, fixes
            fixes.append(version)
        start = None
    return None, fixes


def fixed_version(record: Mapping[str, Any], package: str, installed: str) -> str | None:
    """Return the `fixed` bound of the ECOSYSTEM range containing `installed`.

    Falls back to the lowest fixed version above `installed` when no range contains it.
    """
    current = _version(installed)
    if current is None:
        return None
    every_fix: list[Version] = []
    for events in _ecosystem_ranges(record, package):
        containing, fixes = _fix_for(events, current)
        if containing is not None:
            return str(containing)
        every_fix.extend(fixes)
    above = sorted(v for v in every_fix if v > current)
    return str(above[0]) if above else None
