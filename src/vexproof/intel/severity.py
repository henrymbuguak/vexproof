"""Turn OSV severity entries into a numeric CVSS base score and a label."""

from __future__ import annotations

from collections.abc import Mapping
from typing import Any

from cvss import CVSS3, CVSS4
from cvss.exceptions import CVSSError

_PREFERENCE = ("CVSS_V4", "CVSS_V3")


def cvss_vector(record: Mapping[str, Any]) -> str | None:
    """Pick the newest CVSS vector from the record or its affected entries."""
    entries: list[Mapping[str, Any]] = list(record.get("severity") or [])
    for affected in record.get("affected") or []:
        entries.extend(affected.get("severity") or [])
    for wanted in _PREFERENCE:
        for entry in entries:
            if entry.get("type") == wanted and isinstance(entry.get("score"), str):
                return str(entry["score"])
    return None


def base_score(vector: str | None) -> float | None:
    if not vector:
        return None
    try:
        if vector.startswith("CVSS:4"):
            return float(CVSS4(vector).base_score)
        if vector.startswith("CVSS:3"):
            return float(CVSS3(vector).base_score)
    except CVSSError:
        return None
    return None


def severity_label(record: Mapping[str, Any]) -> str | None:
    """GHSA records carry a label such as HIGH or MODERATE in database_specific."""
    specific = record.get("database_specific") or {}
    label = specific.get("severity") if isinstance(specific, Mapping) else None
    return str(label).upper() if isinstance(label, str) else None
