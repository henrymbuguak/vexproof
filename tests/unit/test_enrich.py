from __future__ import annotations

from tests.helpers import fixture_json
from vexproof.domain import Package
from vexproof.intel.enrich import build_findings, dedupe_records


def test_dedupe_prefers_ghsa_and_drops_withdrawn() -> None:
    records = [
        fixture_json("osv/PYSEC-2026-1.json"),
        fixture_json("osv/GHSA-aaaa-bbbb-cccc.json"),
        fixture_json("osv/GHSA-wwww-xxxx-yyyy.json"),
        fixture_json("osv/GHSA-dddd-eeee-ffff.json"),
    ]
    assert [r["id"] for r in dedupe_records(records)] == [
        "GHSA-aaaa-bbbb-cccc",
        "GHSA-dddd-eeee-ffff",
    ]


def test_build_findings_attaches_signals() -> None:
    package = Package(name="examplelib", version="1.4.2", direct=True)
    findings = build_findings(
        {
            package: [
                fixture_json("osv/GHSA-aaaa-bbbb-cccc.json"),
                fixture_json("osv/GHSA-dddd-eeee-ffff.json"),
            ]
        },
        kev=frozenset({"CVE-2026-0001"}),
        epss={"CVE-2026-0001": (0.9, 0.99)},
    )
    first, second = findings
    assert first.id == "GHSA-aaaa-bbbb-cccc:examplelib@1.4.2"
    assert first.signals.in_kev
    assert first.signals.cvss == 9.8
    assert first.signals.epss == 0.9
    assert second.signals.in_kev is False
    assert second.signals.epss is None
    assert second.signals.cvss is None
    assert second.advisory.fixed_in == "1.5.0"
