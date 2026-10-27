"""Detect alerts whose own reviewed GHSA alias says the installed version is not affected.

Advisory databases sometimes disagree. A PYSEC record may mark every version as affected while
the GitHub-reviewed record for the same CVE starts at a later version. Such alerts stay in the raw
scanner count (scanners report them) but carry the disagreement as evidence.
"""

from __future__ import annotations

from collections.abc import Callable, Mapping, Sequence
from typing import Any

from vexproof.domain import Package
from vexproof.errors import IntelError
from vexproof.intel.fixed import is_affected

FetchRecord = Callable[[str], Mapping[str, Any]]


def find_disputes(
    package: Package, records: Sequence[Mapping[str, Any]], fetch: FetchRecord
) -> dict[str, str]:
    """Map advisory id -> GHSA id that disputes it, for one package's matched records."""
    returned = {str(r["id"]) for r in records}
    disputes: dict[str, str] = {}
    for record in records:
        record_id = str(record["id"])
        if record_id.startswith("GHSA-"):
            continue
        for alias in record.get("aliases") or []:
            if not str(alias).startswith("GHSA-") or alias in returned:
                continue
            try:
                reviewed = fetch(str(alias))
            except IntelError:
                continue  # an unreachable alias only means no dispute is recorded
            if reviewed.get("withdrawn"):
                continue
            if not is_affected(reviewed, package.name, package.version):
                disputes[record_id] = str(alias)
                break
    return disputes
