"""Generate a CycloneDX SBOM with a pinned Syft binary."""

from __future__ import annotations

import json
import re
import shutil
import subprocess
from pathlib import Path
from typing import Any

import structlog

from vexproof.errors import IngestError

log = structlog.get_logger(__name__)
_SYFT_TIMEOUT_S = 600
_VERSION = re.compile(r"^Version:\s*v?(?P<v>\S+)", re.MULTILINE)


def pinned_syft_version(versions_file: Path) -> str | None:
    if not versions_file.is_file():
        return None
    for line in versions_file.read_text(encoding="utf-8").splitlines():
        key, _, value = line.partition("=")
        if key.strip() == "SYFT_VERSION" and value.strip():
            return value.strip().removeprefix("v")
    return None


def _run(cmd: list[str]) -> str:
    try:
        result = subprocess.run(  # noqa: S603 - fixed executable resolved via shutil.which
            cmd, capture_output=True, text=True, timeout=_SYFT_TIMEOUT_S, check=True
        )
    except subprocess.TimeoutExpired as exc:
        raise IngestError(f"syft timed out after {_SYFT_TIMEOUT_S}s") from exc
    except subprocess.CalledProcessError as exc:
        raise IngestError(f"syft failed: {exc.stderr.strip()}") from exc
    return result.stdout


def generate_sbom(
    source_dir: Path, versions_file: Path = Path("tools/versions.env")
) -> dict[str, Any]:
    """Run `syft dir:<source_dir> -o cyclonedx-json` and return the parsed document."""
    syft = shutil.which("syft")
    if syft is None:
        raise IngestError(
            "syft is not installed; install the version pinned in tools/versions.env "
            "or pass an existing SBOM with --sbom"
        )
    installed_match = _VERSION.search(_run([syft, "version"]))
    installed = installed_match["v"] if installed_match else "unknown"
    pinned = pinned_syft_version(versions_file)
    if pinned and installed != pinned:
        log.warning("syft_version_mismatch", pinned=pinned, installed=installed)
    output = _run([syft, f"dir:{source_dir}", "-o", "cyclonedx-json", "-q"])
    try:
        document: dict[str, Any] = json.loads(output)
    except json.JSONDecodeError as exc:
        raise IngestError("syft produced output that is not valid JSON") from exc
    return document
