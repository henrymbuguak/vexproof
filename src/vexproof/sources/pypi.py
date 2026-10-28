"""Find and download the distribution file for an exact package version from PyPI.

Integrity: every download is checked against the SHA-256 digest PyPI publishes; a mismatch is an
error. Size: downloads larger than `max_bytes` are refused before and during transfer.
"""

from __future__ import annotations

import hashlib
import os
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import httpx
import stamina

from vexproof.domain import Package
from vexproof.errors import VexproofError
from vexproof.intel.http import DAY, JsonHttp

_PURE_TAGS = ("-py3-none-any.whl", "-py2.py3-none-any.whl", "-py3-none-any.", "-none-any.whl")


class SourceError(VexproofError):
    """A package's source could not be obtained or read."""


@dataclass(frozen=True, slots=True)
class Artifact:
    filename: str
    url: str
    sha256: str
    size: int
    kind: str  # "wheel" or "sdist"


def choose_artifact(files: Sequence[Mapping[str, Any]]) -> Artifact | None:
    """Prefer a pure-Python wheel, then the smallest wheel, then an sdist.

    Every wheel of one version ships the same Python source; the smallest one usually omits
    bundled native libraries, so it downloads fastest without changing what is analysed.
    """
    candidates = [f for f in files if f.get("digests", {}).get("sha256") and f.get("url")]
    wheels = [f for f in candidates if f.get("packagetype") == "bdist_wheel"]
    pure = [w for w in wheels if any(str(w["filename"]).endswith(t) for t in _PURE_TAGS)]
    sdists = [
        f
        for f in candidates
        if f.get("packagetype") == "sdist"
        and str(f["filename"]).endswith((".tar.gz", ".zip", ".tgz"))
    ]
    for group, kind in ((pure, "wheel"), (wheels, "wheel"), (sdists, "sdist")):
        if group:
            best = min(group, key=lambda f: (int(f.get("size") or 0), str(f["filename"])))
            return Artifact(
                filename=str(best["filename"]),
                url=str(best["url"]),
                sha256=str(best["digests"]["sha256"]).lower(),
                size=int(best.get("size") or 0),
                kind=kind,
            )
    return None


class PyPIClient:
    def __init__(self, http: JsonHttp, client: httpx.Client, base_url: str, max_bytes: int) -> None:
        self._http = http
        self._client = client
        self._base = base_url.rstrip("/")
        self._max = max_bytes

    def artifact(self, package: Package) -> Artifact:
        url = f"{self._base}/pypi/{package.name}/{package.version}/json"
        try:
            data = self._http.request("GET", url, ttl_s=30 * DAY)
        except VexproofError as exc:
            raise SourceError(f"{package.name} {package.version} not found on PyPI: {exc}") from exc
        files = data.get("urls") if isinstance(data, dict) else None
        artifact = choose_artifact(files) if isinstance(files, list) else None
        if artifact is None:
            raise SourceError(f"{package.name} {package.version} has no usable file on PyPI")
        if artifact.size > self._max:
            raise SourceError(
                f"{artifact.filename} is {artifact.size // 1_000_000} MB, above the "
                f"{self._max // 1_000_000} MB limit (VEXPROOF_MAX_DOWNLOAD_MB)"
            )
        return artifact

    def download(self, artifact: Artifact, dest: Path) -> Path:
        """Stream `artifact` to `dest`, verifying size and SHA-256; return `dest`."""
        dest.parent.mkdir(parents=True, exist_ok=True)
        partial = dest.with_name(dest.name + f".{os.getpid()}.part")
        try:
            digest = self._stream(artifact, partial)
            if digest != artifact.sha256:
                raise SourceError(
                    f"SHA-256 mismatch for {artifact.filename}: expected {artifact.sha256}, "
                    f"got {digest}"
                )
            partial.replace(dest)
        finally:
            partial.unlink(missing_ok=True)
        return dest

    @stamina.retry(on=httpx.TransportError, attempts=3, timeout=120.0)
    def _stream(self, artifact: Artifact, target: Path) -> str:
        sha = hashlib.sha256()
        received = 0
        with self._client.stream("GET", artifact.url) as response, target.open("wb") as out:
            if response.status_code != httpx.codes.OK:
                raise SourceError(f"download of {artifact.filename} failed: {response.status_code}")
            for chunk in response.iter_bytes():
                received += len(chunk)
                if received > self._max:
                    raise SourceError(f"{artifact.filename} exceeded the download size limit")
                sha.update(chunk)
                out.write(chunk)
        return sha.hexdigest()
