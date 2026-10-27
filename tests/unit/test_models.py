from __future__ import annotations

import pytest
from hypothesis import given
from hypothesis import strategies as st
from pydantic import ValidationError

from vexproof.domain import Advisory, Evidence, Finding, Hop, Level, Package, Signals

names = st.from_regex(r"[A-Za-z][A-Za-z0-9._-]{0,20}", fullmatch=True)
versions = st.from_regex(r"[0-9]{1,3}(\.[0-9]{1,3}){0,2}", fullmatch=True)


def test_package_name_is_canonicalized() -> None:
    assert Package(name="Other_Lib", version="1.0").name == "other-lib"


def test_models_are_frozen_and_reject_unknown_fields() -> None:
    package = Package(name="x", version="1")
    with pytest.raises(ValidationError):
        package.version = "2"  # type: ignore[misc]
    with pytest.raises(ValidationError):
        Package.model_validate({"name": "x", "version": "1", "surprise": True})


def test_signals_bounds() -> None:
    with pytest.raises(ValidationError):
        Signals(cvss=11.0)
    with pytest.raises(ValidationError):
        Signals(epss=1.5)


def test_hop_line_must_be_positive() -> None:
    with pytest.raises(ValidationError):
        Hop(file="a.py", line=0, symbol="f")


def test_cve_ids_deduplicated_from_id_and_aliases() -> None:
    advisory = Advisory(id="CVE-1", aliases=("GHSA-x", "CVE-1", "CVE-2"))
    assert advisory.cve_ids == ("CVE-1", "CVE-2")


@given(name=names, version=versions, direct=st.booleans(), cvss=st.none() | st.floats(0, 10))
def test_finding_json_round_trip(name: str, version: str, direct: bool, cvss: float | None) -> None:
    finding = Finding(
        id="GHSA-1:x@1",
        package=Package(name=name, version=version, direct=direct),
        advisory=Advisory(id="GHSA-1"),
        signals=Signals(cvss=cvss),
        evidence=Evidence(
            level=Level.L1_SYMBOL, call_chain=(Hop(file="a.py", line=3, symbol="f"),)
        ),
    )
    assert Finding.model_validate_json(finding.model_dump_json()) == finding
