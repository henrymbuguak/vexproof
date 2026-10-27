from __future__ import annotations

from typing import Any

import pytest

from tests.helpers import fixture_json
from vexproof.intel.fixed import fixed_version, is_affected
from vexproof.intel.severity import base_score, cvss_vector, severity_label


def test_cvss_v3_vector_scored() -> None:
    record = fixture_json("osv/GHSA-aaaa-bbbb-cccc.json")
    assert base_score(cvss_vector(record)) == 9.8


def test_prefers_v4_and_reads_affected_level_severity() -> None:
    record = {
        "severity": [{"type": "CVSS_V3", "score": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"}],
        "affected": [
            {
                "severity": [
                    {
                        "type": "CVSS_V4",
                        "score": "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N",
                    }
                ]
            }
        ],
    }
    vector = cvss_vector(record)
    assert vector is not None
    assert vector.startswith("CVSS:4.0")
    assert base_score(vector) == 9.3


@pytest.mark.parametrize("vector", [None, "", "CVSS:3.1/garbage", "CVSS:2.0/AV:N"])
def test_unscoreable_vectors_return_none(vector: str | None) -> None:
    assert base_score(vector) is None


def test_label_uppercased() -> None:
    assert severity_label({"database_specific": {"severity": "moderate"}}) == "MODERATE"
    assert severity_label({}) is None


def _record(events: list[dict[str, str]], name: str = "lib") -> dict[str, Any]:
    return {
        "affected": [
            {
                "package": {"ecosystem": "PyPI", "name": name},
                "ranges": [{"type": "ECOSYSTEM", "events": events}],
            }
        ]
    }


@pytest.mark.parametrize(
    ("installed", "expected"),
    [
        ("1.0", "1.5"),  # inside first range
        ("2.1", "2.3"),  # inside second range
        ("1.7", "2.3"),  # between ranges: falls back to lowest fixed above
        ("3.0", None),  # newer than every fix
        ("not-a-version", None),
    ],
)
def test_fixed_version_for_installed(installed: str, expected: str | None) -> None:
    events = [{"introduced": "2.0"}, {"fixed": "2.3"}, {"introduced": "0"}, {"fixed": "1.5"}]
    assert fixed_version(_record(events), "lib", installed) == expected


def test_fixed_version_matches_canonical_name_and_ecosystem() -> None:
    record = _record([{"introduced": "0"}, {"fixed": "1.1"}], name="Other_Lib")
    assert fixed_version(record, "other-lib", "1.0") == "1.1"
    record["affected"][0]["package"]["ecosystem"] = "npm"
    assert fixed_version(record, "other-lib", "1.0") is None


def test_last_affected_closes_range_without_fix() -> None:
    assert (
        fixed_version(_record([{"introduced": "0"}, {"last_affected": "1.9"}]), "lib", "1.0")
        is None
    )


@pytest.mark.parametrize(
    ("installed", "expected"),
    [
        ("4.3.0", False),  # below the reviewed range: the real Pillow case
        ("5.2.0", True),  # introduced bound is inclusive
        ("8.3.1", True),
        ("8.3.2", False),  # fixed bound is exclusive
        ("not-a-version", False),
    ],
)
def test_is_affected_ranges(installed: str, expected: bool) -> None:
    record = _record([{"introduced": "5.2.0"}, {"fixed": "8.3.2"}])
    assert is_affected(record, "lib", installed) is expected


def test_is_affected_last_affected_open_range_and_explicit_versions() -> None:
    assert is_affected(_record([{"introduced": "1.0"}, {"last_affected": "1.4"}]), "lib", "1.4")
    assert not is_affected(_record([{"introduced": "1.0"}, {"last_affected": "1.4"}]), "lib", "1.5")
    assert is_affected(_record([{"introduced": "2.0"}]), "lib", "9.9")
    explicit = {
        "affected": [{"package": {"ecosystem": "PyPI", "name": "lib"}, "versions": ["0.1"]}]
    }
    assert is_affected(explicit, "lib", "0.1")
    assert not is_affected(explicit, "other", "0.1")
