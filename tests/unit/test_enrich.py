from __future__ import annotations

from tests.helpers import fixture_json
from vexproof.domain import Advisory, Package
from vexproof.intel.enrich import build_findings, dedupe_records, merge_unlinked_duplicates


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


def _adv(
    aid: str, *, aliases: tuple[str, ...] = (), fixed: str | None = "2.0", text: str = ""
) -> Advisory:
    return Advisory(id=aid, aliases=aliases, details=text, fixed_in=fixed)


def test_alias_less_duplicate_merged_into_matching_advisory() -> None:
    # Mirrors PYSEC-2023-175 (no aliases, prose names CVE-2023-4863) vs the libwebp GHSA.
    # As in the real GHSA-j7hp-h8jx-5ppr record, the GHSA carries both CVE ids.
    kept = _adv("GHSA-1", aliases=("CVE-2023-4863", "CVE-2023-5129"), fixed="10.0.1")
    dup = _adv(
        "PYSEC-9", fixed="10.0.1", text="vulnerable to CVE-2023-5129 (previously CVE-2023-4863)"
    )
    merged = merge_unlinked_duplicates([kept, dup])
    assert [a.id for a in merged] == ["GHSA-1"]
    assert merged[0].aliases == ("CVE-2023-4863", "CVE-2023-5129", "PYSEC-9")


def test_not_merged_without_matching_fix_or_with_own_aliases() -> None:
    kept = _adv("GHSA-1", aliases=("CVE-1",), fixed="2.0")
    different_fix = _adv("PYSEC-1", fixed="3.0", text="related to CVE-1")
    has_aliases = _adv("PYSEC-2", aliases=("CVE-2",), fixed="2.0", text="unlike CVE-1")
    no_mention = _adv("PYSEC-3", fixed="2.0", text="a different bug")
    merged = merge_unlinked_duplicates([kept, different_fix, has_aliases, no_mention])
    assert [a.id for a in merged] == ["GHSA-1", "PYSEC-1", "PYSEC-2", "PYSEC-3"]


def test_umbrella_merged_into_every_covered_advisory() -> None:
    # Mirrors GHSA-jgpv-4h4c-xhw3: one alias-less advisory for the Pillow 8.1.2 release whose
    # text names CVEs that are each also published as their own advisory.
    blp = _adv("GHSA-blp", aliases=("CVE-2021-27921",), fixed="8.1.2")
    icns = _adv("GHSA-icns", aliases=("CVE-2021-27922",), fixed="8.1.2")
    ico = _adv("GHSA-ico", aliases=("CVE-2021-27923",), fixed="8.1.2")
    umbrella = _adv(
        "GHSA-umbrella",
        fixed="8.1.2",
        text="Fixes CVE-2021-27921, CVE-2021-27922 and CVE-2021-27923.",
    )
    merged = merge_unlinked_duplicates([blp, umbrella, icns, ico])
    assert [a.id for a in merged] == ["GHSA-blp", "GHSA-icns", "GHSA-ico"]
    assert all("GHSA-umbrella" in a.aliases for a in merged)


def test_umbrella_kept_when_it_names_an_uncovered_cve() -> None:
    blp = _adv("GHSA-blp", aliases=("CVE-2021-27921",), fixed="8.1.2")
    umbrella = _adv("GHSA-umbrella", fixed="8.1.2", text="Fixes CVE-2021-27921 and CVE-2021-99999.")
    merged = merge_unlinked_duplicates([blp, umbrella])
    assert [a.id for a in merged] == ["GHSA-blp", "GHSA-umbrella"]
    assert merged[0].aliases == ("CVE-2021-27921",)


def test_alias_less_without_any_cve_is_kept() -> None:
    plain = _adv("GHSA-plain", fixed="8.1.2", text="Uncontrolled resource consumption")
    other = _adv("GHSA-blp", aliases=("CVE-2021-27921",), fixed="8.1.2")
    assert [a.id for a in merge_unlinked_duplicates([other, plain])] == ["GHSA-blp", "GHSA-plain"]
