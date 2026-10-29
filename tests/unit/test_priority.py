from __future__ import annotations

from dataclasses import replace

import pytest

from tests.report_fixtures import DJANGO, INTERNAL, PUBLIC, finding, mixed
from vexproof.domain import Level, ServiceProfile, Verdict
from vexproof.report.context import package_purl, product_purl, short_symbol
from vexproof.report.priority import (
    Outcome,
    Tier,
    outcome_counts,
    rank,
    score,
    severity,
    upgrade_plan,
)

AFFECTED = Verdict.AFFECTED


def _tier(f: object, profile: ServiceProfile | None = None) -> Tier:
    return rank([f], profile)[0].tier  # type: ignore[list-item]


def test_names() -> None:
    assert product_purl("https://github.com/Acme/Shop.git", "abc") == "pkg:github/acme/shop@abc"
    assert product_purl("https://github.com/acme/shop/", None) == "pkg:github/acme/shop"
    assert product_purl("/home/me/My App/", "abc") == "pkg:generic/my%20app@abc"
    assert product_purl("", None) == "pkg:generic/project"
    assert package_purl(finding("A")) == "pkg:pypi/pillow@4.3.0"
    assert package_purl(finding("A", package=DJANGO)) == "pkg:pypi/django@2.0"
    assert short_symbol("PIL.IcoImagePlugin.IcoFile.frame") == "IcoFile.frame"
    assert short_symbol("frame") == "frame"


@pytest.mark.parametrize(
    ("kwargs", "profile", "tier", "why"),
    [
        ({"kev": True}, None, Tier.FIX_NOW, "known exploited in the wild (CISA KEV)"),
        ({"epss": 0.25}, None, Tier.FIX_NOW, "EPSS 25%: likely to see exploitation"),
        ({"cvss": 9.8}, None, Tier.FIX_NOW, "critical severity"),
        ({"cvss": 8.7}, PUBLIC, Tier.FIX_NOW, "high severity in shop, an internet-facing"),
        ({"cvss": 8.7}, None, Tier.FIX_SOON, "CVSS 8.7, EPSS 1.0%, not in CISA KEV"),
        ({"cvss": 8.7}, INTERNAL, Tier.FIX_SOON, "CVSS 8.7"),
        (
            {"cvss": 8.7},
            PUBLIC.model_copy(update={"criticality": "low"}),
            Tier.FIX_SOON,
            "CVSS 8.7",
        ),
        ({"cvss": 6.1}, PUBLIC, Tier.FIX_SOON, "CVSS 6.1"),
        ({"cvss": None, "label": "CRITICAL"}, None, Tier.FIX_NOW, "critical severity"),
    ],
)
def test_reachable_tiers(
    kwargs: dict[str, object], profile: ServiceProfile | None, tier: Tier, why: str
) -> None:
    ranked = rank([finding("GHSA-x", verdict=AFFECTED, **kwargs)], profile)[0]  # type: ignore[arg-type]
    assert ranked.tier is tier
    assert any(why in reason for reason in ranked.reasons), ranked.reasons
    assert ranked.reasons[0].startswith("reachable: shop/admin.py:20 reaches IcoFile.frame")
    assert ranked.brief.startswith("shop/admin.py:20 -> IcoFile.frame (2 hops, all certain)")


def test_profile_changes_priority_never_the_verdict() -> None:
    f = finding("GHSA-x", verdict=AFFECTED, cvss=8.7)
    assert _tier(f) is Tier.FIX_SOON
    assert _tier(f, PUBLIC) is Tier.FIX_NOW
    cleared = finding("GHSA-y", verdict=Verdict.NOT_AFFECTED, cvss=10.0, kev=True)
    opened = finding("GHSA-z", cvss=10.0)
    for profile in (None, PUBLIC, INTERNAL):
        assert _tier(cleared, profile) is Tier.NOT_AFFECTED
        assert _tier(opened, profile) is Tier.REVIEW


def test_reachable_reasons_name_the_path_and_the_fix() -> None:
    certain = rank([finding("A", verdict=AFFECTED, fixed_in=None)])[0]
    assert certain.reasons[0].endswith("in 2 hop(s), every hop certain")
    assert certain.reasons[-1] == "no fixed version of pillow published"
    reviewed = rank([finding("A", verdict=AFFECTED, reviewed=True)])[0]
    assert "1 uncertain hop(s) reviewed by the model" in reviewed.reasons[0]
    assert reviewed.reasons[-1] == "fixed in pillow 8.1.2"
    assert reviewed.outcome is Outcome.PATH_REVIEWED
    assert reviewed.brief == "shop/admin.py:20 -> IcoFile.frame (2 hops, 1 reviewed)"


@pytest.mark.parametrize(
    ("kwargs", "reason"),
    [
        ({"level": Level.L1_SYMBOL, "picks": ("PIL.Image.Image.convert",)}, "Image.convert found"),
        ({"level": Level.L1_SYMBOL, "model": "m"}, "none of the functions the fix changed"),
        ({"level": Level.L1_SYMBOL}, "not traced (no model)"),
        ({"level": Level.L2_MODULE}, "only the changed module is known"),
        ({"level": Level.L3_NONE}, "no Python fix code"),
    ],
)
def test_open_reasons(kwargs: dict[str, object], reason: str) -> None:
    ranked = rank([finding("GHSA-o", **kwargs)])[0]  # type: ignore[arg-type]
    assert ranked.tier is Tier.REVIEW
    assert reason in ranked.reasons[0]
    assert ranked.brief.startswith(ranked.reasons[0])


def test_dispute_is_shown_even_with_a_pick() -> None:
    f = finding("GHSA-d", picks=("PIL.Image.open",), disputed_by="GHSA-rev")
    reasons = rank([f])[0].reasons
    assert "Image.open found" in reasons[0]
    assert "disputed: the reviewed record GHSA-rev says this version is not affected" in reasons


def test_open_kev_is_reviewed_first_and_unanalysed_is_said() -> None:
    kev = finding("GHSA-kev", kev=True, cvss=5.0)
    severe = finding("GHSA-severe", cvss=9.0)
    ranked = rank([severe, kev])
    assert [r.finding.advisory.id for r in ranked] == ["GHSA-kev", "GHSA-severe"]
    assert ranked[0].reasons[0] == "known exploited in the wild (CISA KEV): review first"
    bare = finding("GHSA-bare").model_copy(update={"evidence": None})
    assert rank([bare])[0].reasons[0] == "not analysed (scan ran without analysis)"
    unknown = finding("GHSA-u", cvss=None, epss=None)
    assert "severity unknown, not in CISA KEV" in rank([unknown])[0].reasons


def test_cleared_reasons_and_outcomes() -> None:
    ranked = {r.finding.advisory.id: r for r in rank(mixed())}
    assert ranked["GHSA-gone"].reasons == (
        "vulnerable module never loaded by your code: PIL.GdImageFile (nothing loads it)",
    )
    assert ranked["GHSA-dj0"].reasons == ("package never imported by your code",)
    plain = finding("GHSA-p", verdict=Verdict.NOT_AFFECTED)
    assert rank([plain])[0].reasons == ("vulnerable module never loaded by your code",)
    counts = outcome_counts(mixed())
    assert counts == {
        Outcome.CLEARED_PACKAGE: 1,
        Outcome.CLEARED_MODULE: 1,
        Outcome.PATH_CERTAIN: 1,
        Outcome.PATH_REVIEWED: 1,
        Outcome.OPEN: 2,
    }


def test_order_and_score() -> None:
    order = [r.finding.advisory.id for r in rank(mixed(), PUBLIC)]
    assert order == ["GHSA-kev", "GHSA-high", "GHSA-dj", "GHSA-open", "GHSA-dj0", "GHSA-gone"]
    assert score(finding("A", cvss=10.0, epss=1.0, kev=True)) == 100
    assert score(finding("A", cvss=None, epss=None)) == 25  # unknown severity counts as medium
    assert severity(finding("A", cvss=None, label="moderate")) == 5.5
    assert severity(finding("A", cvss=None, label="weird")) is None


def test_upgrade_plan() -> None:
    plans = upgrade_plan(rank(mixed(), PUBLIC))
    assert [p.package for p in plans] == ["pillow", "django"]
    pillow, django = plans
    assert pillow.target == "10.0.0"  # the open alert needs more than the reachable ones
    assert pillow.reachable_target == "9.0.0"
    assert pillow.resolves == ("GHSA-high", "GHSA-kev", "GHSA-open")
    assert pillow.already_cleared == 1
    assert pillow.tier is Tier.FIX_NOW
    assert pillow.major_jump is True
    assert django.target is None
    assert django.reachable_target is None
    assert django.no_fix == ("GHSA-dj",)
    assert django.major_jump is False
    assert django.tier is Tier.REVIEW


def test_upgrade_plan_edge_cases() -> None:
    only_cleared = rank([finding("A", verdict=Verdict.NOT_AFFECTED)])
    assert upgrade_plan(only_cleared) == []
    odd = upgrade_plan(rank([finding("A", fixed_in="not-a-version"), finding("B")]))[0]
    assert odd.no_fix == ("A",)
    assert odd.target == "8.1.2"
    weird = replace(odd, installed="weird")
    assert weird.major_jump is False
    minor = upgrade_plan(rank([finding("A", fixed_in="4.3.1")]))[0]
    assert minor.major_jump is False
