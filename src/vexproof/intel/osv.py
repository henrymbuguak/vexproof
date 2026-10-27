"""OSV.dev client: find advisories for packages and turn records into Advisory models."""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from typing import Any

from vexproof.domain import Advisory, Package, Reference
from vexproof.errors import IntelError
from vexproof.intel.fixed import fixed_version
from vexproof.intel.http import DAY, JsonHttp
from vexproof.intel.severity import cvss_vector, severity_label

_BATCH = 1000
_MAX_PAGES = 20


class OSVClient:
    def __init__(self, http: JsonHttp, base_url: str) -> None:
        self._http = http
        self._base = base_url.rstrip("/")

    @staticmethod
    def _query(package: Package) -> dict[str, Any]:
        return {"package": {"name": package.name, "ecosystem": "PyPI"}, "version": package.version}

    def advisory_ids(self, packages: Sequence[Package]) -> dict[Package, tuple[str, ...]]:
        """Map each package to the OSV ids that affect its version."""
        result: dict[Package, tuple[str, ...]] = {}
        for start in range(0, len(packages), _BATCH):
            chunk = packages[start : start + _BATCH]
            body = {"queries": [self._query(p) for p in chunk]}
            data = self._http.request("POST", f"{self._base}/v1/querybatch", body=body, ttl_s=DAY)
            results = data.get("results") if isinstance(data, dict) else None
            if not isinstance(results, list) or len(results) != len(chunk):
                raise IntelError("OSV querybatch returned an unexpected shape")
            for package, item in zip(chunk, results, strict=True):
                ids = [v["id"] for v in (item.get("vulns") or [])]
                token = item.get("next_page_token")
                pages = 0
                while token and pages < _MAX_PAGES:
                    page = self._http.request(
                        "POST",
                        f"{self._base}/v1/query",
                        body={**self._query(package), "page_token": token},
                        ttl_s=DAY,
                    )
                    if not isinstance(page, dict):
                        raise IntelError(f"OSV query page for {package.name} is not an object")
                    ids.extend(v["id"] for v in (page.get("vulns") or []))
                    token = page.get("next_page_token")
                    pages += 1
                result[package] = tuple(dict.fromkeys(ids))
        return result

    def record(self, advisory_id: str) -> Mapping[str, Any]:
        data = self._http.request("GET", f"{self._base}/v1/vulns/{advisory_id}", ttl_s=7 * DAY)
        if not isinstance(data, dict) or data.get("id") != advisory_id:
            raise IntelError(f"OSV returned an unexpected record for {advisory_id}")
        return data


def to_advisory(record: Mapping[str, Any], package: Package) -> Advisory:
    references = tuple(
        Reference(type=str(r.get("type", "WEB")), url=str(r["url"]))
        for r in record.get("references") or []
        if isinstance(r, dict) and r.get("url")
    )
    return Advisory(
        id=str(record["id"]),
        aliases=tuple(str(a) for a in record.get("aliases") or []),
        summary=str(record.get("summary") or ""),
        details=str(record.get("details") or ""),
        fixed_in=fixed_version(record, package.name, package.version),
        references=references,
        cvss_vector=cvss_vector(record),
        severity_label=severity_label(record),
    )
