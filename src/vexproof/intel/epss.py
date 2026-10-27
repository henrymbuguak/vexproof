"""FIRST EPSS scores. The API returns numbers as strings; they are parsed here."""

from __future__ import annotations

from collections.abc import Iterable

from vexproof.intel.http import DAY, JsonHttp

_CHUNK = 100  # keeps the query string well under URL length limits


def load_epss(http: JsonHttp, url: str, cves: Iterable[str]) -> dict[str, tuple[float, float]]:
    """Map CVE id to (epss probability, percentile). CVEs without a score are omitted."""
    wanted = sorted(set(cves))
    scores: dict[str, tuple[float, float]] = {}
    for start in range(0, len(wanted), _CHUNK):
        chunk = wanted[start : start + _CHUNK]
        data = http.request("GET", url, params={"cve": ",".join(chunk)}, ttl_s=DAY)
        for row in (data.get("data") if isinstance(data, dict) else None) or []:
            try:
                scores[str(row["cve"])] = (float(row["epss"]), float(row["percentile"]))
            except (KeyError, TypeError, ValueError):
                continue
    return scores
