from __future__ import annotations

from collections.abc import Mapping
from typing import Any

from vexproof.domain import Package
from vexproof.errors import IntelError
from vexproof.intel.disputes import find_disputes

PILLOW = Package(name="pillow", version="4.3.0")


def _ghsa(gid: str, introduced: str, fixed: str, **extra: object) -> dict[str, Any]:
    return {
        "id": gid,
        "affected": [
            {
                "package": {"ecosystem": "PyPI", "name": "pillow"},
                "ranges": [
                    {"type": "ECOSYSTEM", "events": [{"introduced": introduced}, {"fixed": fixed}]}
                ],
            }
        ],
        **extra,
    }


def _fetcher(store: Mapping[str, Mapping[str, Any]]):  # type: ignore[no-untyped-def]
    def fetch(advisory_id: str) -> Mapping[str, Any]:
        if advisory_id not in store:
            raise IntelError(f"no {advisory_id}")
        return store[advisory_id]

    return fetch


def test_pysec_disputed_when_reviewed_range_excludes_installed_version() -> None:
    # Mirrors PYSEC-2021-317 -> GHSA-98vv-pw6r-q6q4 (introduced 5.2.0) for Pillow 4.3.0.
    records = [{"id": "PYSEC-1", "aliases": ["CVE-1", "GHSA-x"]}]
    disputes = find_disputes(
        PILLOW, records, _fetcher({"GHSA-x": _ghsa("GHSA-x", "5.2.0", "8.3.2")})
    )
    assert disputes == {"PYSEC-1": "GHSA-x"}


def test_no_dispute_when_reviewed_range_covers_version() -> None:
    records = [{"id": "PYSEC-1", "aliases": ["GHSA-x"]}]
    assert find_disputes(PILLOW, records, _fetcher({"GHSA-x": _ghsa("GHSA-x", "0", "8.3.2")})) == {}


def test_skips_returned_withdrawn_unreachable_and_ghsa_records() -> None:
    records = [
        {"id": "PYSEC-1", "aliases": ["GHSA-returned"]},
        {"id": "GHSA-returned", "aliases": ["PYSEC-1"]},
        {"id": "PYSEC-2", "aliases": ["GHSA-withdrawn"]},
        {"id": "PYSEC-3", "aliases": ["GHSA-missing"]},
        {"id": "GHSA-own", "aliases": ["GHSA-other"]},
    ]
    store = {
        "GHSA-withdrawn": _ghsa("GHSA-withdrawn", "9.0", "9.1", withdrawn="2024-01-01T00:00:00Z"),
        "GHSA-other": _ghsa("GHSA-other", "9.0", "9.1"),
    }
    assert find_disputes(PILLOW, records, _fetcher(store)) == {}
