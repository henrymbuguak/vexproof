"""OpenVEX and HTML outputs: valid, deterministic, and safe with hostile advisory text."""

from __future__ import annotations

import re
from dataclasses import replace
from html.parser import HTMLParser
from typing import Any

import pytest

from tests.report_fixtures import HOSTILE, PUBLIC, context, finding, mixed
from vexproof.domain import Verdict
from vexproof.report.html import render_html
from vexproof.report.openvex import CONTEXT, openvex, problems


def _by_name(document: dict[str, Any]) -> dict[str, dict[str, Any]]:
    return {s["vulnerability"]["name"]: s for s in document["statements"]}


def test_openvex_document_and_statements() -> None:
    document = openvex(context(*mixed(), profile=PUBLIC), author="Acme Security")
    assert problems(document) == []
    assert document["@context"] == CONTEXT
    assert re.fullmatch(r"https://openvex\.dev/docs/public/vex-[0-9a-f]{64}", document["@id"])
    assert document["author"] == "Acme Security"
    assert document["timestamp"] == "2026-10-29T12:00:00Z"
    assert document["tooling"] == "vexproof test"
    statements = _by_name(document)
    assert len(statements) == 6

    kev = statements["GHSA-kev"]
    assert kev["status"] == "affected"
    assert kev["action_statement"] == "Upgrade pillow from 4.3.0 to 9.0.0 or later."
    assert "Priority: fix now" in kev["status_notes"]
    assert "shop.admin (shop/admin.py:20) -> PIL.Image.open" in kev["status_notes"]
    assert kev["products"] == [
        {
            "@id": f"pkg:github/acme/shop@{'1aa90f67f4559a36d8049d8a2d3fe622791ee95c'}",
            "subcomponents": [{"@id": "pkg:pypi/pillow@4.3.0"}],
        }
    ]
    assert kev["vulnerability"] == {
        "@id": "https://osv.dev/vulnerability/GHSA-kev",
        "name": "GHSA-kev",
        "description": "GHSA-kev summary",
        "aliases": ["CVE-GHSA-kev"],
    }
    gone = statements["GHSA-gone"]
    assert gone["status"] == "not_affected"
    assert gone["justification"] == "vulnerable_code_not_in_execute_path"
    assert gone["impact_statement"].startswith("vulnerable module never loaded by your code")
    assert "action_statement" not in gone
    opened = statements["GHSA-dj"]
    assert opened["status"] == "under_investigation"
    assert opened["status_notes"].startswith("no Python fix code to check against")
    assert opened["products"][0]["subcomponents"] == [{"@id": "pkg:pypi/django@2.0"}]


def test_openvex_is_deterministic_and_content_addressed() -> None:
    first, again = openvex(context(*mixed())), openvex(context(*reversed(mixed())))
    assert first == again  # statement order does not depend on input order
    changed = openvex(context(*mixed()[1:]))
    assert changed["@id"] != first["@id"]


def test_openvex_edge_cases() -> None:
    no_fix = finding("GHSA-nf", verdict=Verdict.AFFECTED, fixed_in=None)
    long_note = finding("GHSA-long", notes=(), summary="")
    long_note = long_note.model_copy(
        update={"advisory": long_note.advisory.model_copy(update={"summary": "", "aliases": ()})}
    )
    statements = _by_name(openvex(context(no_fix, long_note)))
    assert statements["GHSA-nf"]["action_statement"].startswith("No fixed version of pillow")
    assert statements["GHSA-long"]["vulnerability"] == {
        "@id": "https://osv.dev/vulnerability/GHSA-long",
        "name": "GHSA-long",
    }
    huge = finding("GHSA-huge", disputed_by="X" * 2000)
    notes = _by_name(openvex(context(huge)))["GHSA-huge"]["status_notes"]
    assert len(notes) == 1000
    assert notes.endswith("...")


@pytest.mark.parametrize(
    ("change", "problem"),
    [
        (lambda d: d.pop("author"), "missing author"),
        (lambda d: _by_name(d)["GHSA-kev"].update(status="maybe"), "unknown status 'maybe'"),
        (lambda d: _by_name(d)["GHSA-kev"].update(justification="x"), "unknown justification"),
        (lambda d: _by_name(d)["GHSA-kev"].update(products=[]), "no products"),
        (lambda d: _by_name(d)["GHSA-kev"].update(vulnerability={}), "vulnerability has no name"),
        (lambda d: _by_name(d)["GHSA-kev"].pop("action_statement"), "affected needs an action"),
        (
            lambda d: [
                _by_name(d)["GHSA-gone"].pop(k) for k in ("justification", "impact_statement")
            ],
            "not_affected needs a justification",
        ),
    ],
)
def test_problems_finds_each_broken_rule(change: Any, problem: str) -> None:
    document = openvex(context(*mixed()))
    change(document)
    assert any(problem in p for p in problems(document)), problems(document)


class _Collect(HTMLParser):
    def __init__(self) -> None:
        super().__init__()
        self.tags: list[str] = []
        self.hrefs: list[str] = []
        self.text: list[str] = []

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        self.tags.append(tag)
        self.hrefs += [v or "" for k, v in attrs if k == "href"]

    def handle_data(self, data: str) -> None:
        self.text.append(data)


def _parse(page: str) -> _Collect:
    parser = _Collect()
    parser.feed(page)
    return parser


def test_html_report_sections_and_evidence() -> None:
    page = render_html(context(*mixed(), profile=PUBLIC))
    text = " ".join(" ".join(_parse(page).text).split())
    assert page.startswith("<!doctype html>")
    assert "Content-Security-Policy" in page
    assert "default-src 'none'" in page
    assert "Fix first (2)" in text
    assert "Needs review (2)" in text
    assert "Not affected (2)" in text
    assert "Upgrade plan (2)" in text
    assert "6 scanner alerts" in text
    assert "2 reachable (1 with every hop certain)" in text
    assert "33.3% alert noise removed" in text
    assert "profile: shop (internet-facing, high criticality, handles personal data)" in text
    assert "known exploited in the wild (CISA KEV)" in text
    assert ">= 9.0.0 >= 10.0.0" in text
    assert "major version change: read the release notes" in text
    assert "1 with no fixed version: GHSA-dj" in text
    assert "1 more already cleared" in text
    assert "(uncertain, reviewed)" in text
    assert "PIL.IcoImagePlugin.IcoFile.frame" in text


def test_html_report_empty_and_without_profile() -> None:
    page = render_html(context())
    text = " ".join(" ".join(_parse(page).text).split())
    for empty in ("Nothing proven reachable.", "Nothing left open.", "Nothing cleared.",
                  "No upgrades needed."):  # fmt: skip
        assert empty in text
    assert "no service profile" in text
    internal = render_html(context(finding("A"), profile=PUBLIC.model_copy(
        update={"internet_facing": False, "handles_personal_data": False})))  # fmt: skip
    assert "(internal, high criticality)" in internal
    local = replace(context(finding("A")), source="./my-app")
    assert 'href="./my-app"' not in render_html(local)  # only https sources become links


def test_html_escapes_hostile_text_and_links() -> None:
    evil = finding(
        "GHSA-evil",
        summary=HOSTILE,
        notes=(HOSTILE, "y" * 900),
        picks=("PIL.Image.open",),
        disputed_by=HOSTILE,
    )
    evil = evil.model_copy(
        update={
            "evidence": evil.evidence.model_copy(  # type: ignore[union-attr]
                update={
                    "fix_commits": ("javascript:alert(1)", 'https://x.test/"onmouseover=1'),
                    "symbol_quote": HOSTILE,
                }
            )
        }
    )
    page = render_html(context(evil))
    parsed = _parse(page)
    assert "script" not in parsed.tags
    assert "<script>" not in page
    assert all(h.startswith("https://") for h in parsed.hrefs), parsed.hrefs
    assert 'href="https://x.test/&quot;onmouseover=1"' in page
    assert HOSTILE in " ".join(parsed.text)  # shown as text, intact
    assert "y" * 597 + "..." in page
