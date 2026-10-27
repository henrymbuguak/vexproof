"""Live checks against real services. Run with `make smoke`; skipped by default and in CI."""

from __future__ import annotations

import httpx
import pytest

from vexproof.config import Settings
from vexproof.domain import Package
from vexproof.intel.epss import load_epss
from vexproof.intel.http import JsonHttp
from vexproof.intel.kev import load_kev
from vexproof.intel.osv import OSVClient

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
