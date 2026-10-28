"""Live checks against real services. Run with `make smoke`; skipped by default and in CI."""

from __future__ import annotations

from pathlib import Path

import httpx
import pytest

from vexproof.config import Settings
from vexproof.domain import Advisory, FixCommit, Level, Package
from vexproof.intel.epss import load_epss
from vexproof.intel.http import JsonHttp
from vexproof.intel.kev import load_kev
from vexproof.intel.osv import OSVClient
from vexproof.sources.git import GitFixFetcher
from vexproof.sources.pypi import PyPIClient
from vexproof.sources.store import SourceStore
from vexproof.static.shortlist import build_shortlist

pytestmark = pytest.mark.network


def test_live_osv_kev_epss() -> None:
    settings = Settings()
    with httpx.Client(timeout=30, headers={"User-Agent": settings.user_agent}) as client:
        http = JsonHttp(client)
        old_jinja = Package(name="jinja2", version="2.10")
        ids = OSVClient(http, settings.osv_url).advisory_ids([old_jinja])[old_jinja]
        assert ids, "jinja2 2.10 has published advisories; OSV returned none"
        assert len(load_kev(http, settings.kev_url)) > 1000
        assert "CVE-2021-44228" in load_epss(http, settings.epss_url, ["CVE-2021-44228"])


def test_live_wheel_and_real_django_fix_commit(tmp_path: Path) -> None:
    """Real PyPI wheel + the real fix for CVE-2019-19844 (Django password-reset hijack)."""
    settings = Settings()
    package = Package(name="django", version="2.0")
    advisory = Advisory(
        id="GHSA-vfq6-hq5r-27r6",
        fix_commits=(
            FixCommit(
                owner="django", repo="django", sha="302a4ff1e8b1c798aab97673909c7a3dfda42c26"
            ),
        ),
    )
    with httpx.Client(
        timeout=120, follow_redirects=True, headers={"User-Agent": settings.user_agent}
    ) as client:
        store = SourceStore(
            tmp_path, PyPIClient(JsonHttp(client), client, settings.pypi_url, 10**8)
        )
        tree = store.get(package)
    assert "django.contrib.auth.forms" in tree.modules
    shortlist = build_shortlist(advisory, tree, GitFixFetcher(tmp_path))
    assert shortlist.level is Level.L1_SYMBOL
    assert "django.contrib.auth.forms.PasswordResetForm.save" in {
        c.qualname for c in shortlist.candidates
    }
