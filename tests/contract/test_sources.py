from __future__ import annotations

import pytest
import respx

from tests.helpers import EPSS, KEV, OSV
from vexproof.domain import Package
from vexproof.errors import IntelError
from vexproof.intel.epss import load_epss
from vexproof.intel.http import JsonHttp
from vexproof.intel.kev import load_kev
from vexproof.intel.osv import OSVClient, to_advisory

PACKAGES = (
    Package(name="examplelib", version="1.4.2"),
    Package(name="nested-lib", version="0.9"),
    Package(name="other-lib", version="2.0.0"),
)


def test_osv_batch_follows_pagination(http: JsonHttp, mocked_services: respx.MockRouter) -> None:
    ids = OSVClient(http, OSV).advisory_ids(PACKAGES)
    assert ids[PACKAGES[0]] == (
        "GHSA-aaaa-bbbb-cccc",
        "PYSEC-2026-1",
        "GHSA-dddd-eeee-ffff",
        "PYSEC-2026-8",
    )
    assert ids[PACKAGES[1]] == ("GHSA-wwww-xxxx-yyyy",)
    assert ids[PACKAGES[2]] == ("PYSEC-2026-7",)
    sent = mocked_services.routes[1].calls.last.request.content
    assert b'"page_token":"page-2"' in sent.replace(b" ", b"")


@respx.mock
def test_osv_batch_shape_mismatch_raises(http: JsonHttp) -> None:
    respx.post(f"{OSV}/v1/querybatch").respond(json={"results": []})
    with pytest.raises(IntelError, match="unexpected shape"):
        OSVClient(http, OSV).advisory_ids(PACKAGES)


def test_record_to_advisory(http: JsonHttp, mocked_services: respx.MockRouter) -> None:
    record = OSVClient(http, OSV).record("GHSA-aaaa-bbbb-cccc")
    advisory = to_advisory(record, PACKAGES[0])
    assert advisory.fixed_in == "1.4.3"
    assert advisory.cve_ids == ("CVE-2026-0001",)
    assert advisory.severity_label == "CRITICAL"
    assert any(r.type == "FIX" and "/commit/" in r.url for r in advisory.references)


@respx.mock
def test_record_id_mismatch_raises(http: JsonHttp) -> None:
    respx.get(f"{OSV}/v1/vulns/GHSA-1").respond(json={"id": "GHSA-2"})
    with pytest.raises(IntelError, match="unexpected record"):
        OSVClient(http, OSV).record("GHSA-1")


def test_kev_and_epss(http: JsonHttp, mocked_services: respx.MockRouter) -> None:
    assert "CVE-2026-0001" in load_kev(http, KEV)
    scores = load_epss(http, EPSS, ["CVE-2026-0002", "CVE-2026-0001", "CVE-2026-0001"])
    assert scores["CVE-2026-0001"] == (0.91234, 0.998)
    assert (
        mocked_services.routes[-1].calls.last.request.url.params["cve"]
        == "CVE-2026-0001,CVE-2026-0002"
    )


@respx.mock
def test_kev_bad_shape_and_epss_bad_rows(http: JsonHttp) -> None:
    respx.get(KEV).respond(json={"nope": []})
    with pytest.raises(IntelError, match="KEV"):
        load_kev(http, KEV)
    respx.get(EPSS).respond(json={"data": [{"cve": "CVE-1", "epss": "n/a", "percentile": "0.1"}]})
    assert load_epss(http, EPSS, ["CVE-1"]) == {}


def test_epss_chunks_large_requests(http: JsonHttp, mocked_services: respx.MockRouter) -> None:
    load_epss(http, EPSS, [f"CVE-2026-{i:04d}" for i in range(250)])
    assert mocked_services.routes[-1].call_count == 3
