"""CISA Known Exploited Vulnerabilities catalog."""

from __future__ import annotations

from vexproof.errors import IntelError
from vexproof.intel.http import DAY, JsonHttp


def load_kev(http: JsonHttp, url: str) -> frozenset[str]:
    data = http.request("GET", url, ttl_s=DAY)
    entries = data.get("vulnerabilities") if isinstance(data, dict) else None
    if not isinstance(entries, list):
        raise IntelError("KEV feed has an unexpected shape")
    return frozenset(str(e["cveID"]) for e in entries if isinstance(e, dict) and "cveID" in e)
