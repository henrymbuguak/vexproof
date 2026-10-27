from __future__ import annotations

from pathlib import Path

import pytest

from tests.helpers import FIXTURES, fixture_json
from vexproof.errors import IngestError
from vexproof.ingest.sbom import load_sbom, packages_from_sbom


def test_cyclonedx_extracts_unique_pypi_packages_including_nested() -> None:
    packages = packages_from_sbom(
        fixture_json("sbom/cyclonedx-mini.json"), frozenset({"examplelib"})
    )
    assert [(p.name, p.version, p.direct) for p in packages] == [
        ("examplelib", "1.4.2", True),
        ("nested-lib", "0.9", False),
        ("other-lib", "2.0.0", False),
    ]


def test_spdx_reads_purl_external_refs() -> None:
    packages = packages_from_sbom(fixture_json("sbom/spdx-mini.json"))
    assert [(p.name, p.version) for p in packages] == [("examplelib", "1.4.2")]


def test_unknown_format_rejected() -> None:
    with pytest.raises(IngestError, match="unsupported SBOM"):
        packages_from_sbom({"hello": "world"})


def test_load_sbom_errors(tmp_path: Path) -> None:
    broken = tmp_path / "bad.json"
    broken.write_text("{not json")
    with pytest.raises(IngestError, match="not valid JSON"):
        load_sbom(broken)
    array = tmp_path / "array.json"
    array.write_text("[]")
    with pytest.raises(IngestError, match="JSON object"):
        load_sbom(array)
    with pytest.raises(IngestError, match="cannot read"):
        load_sbom(tmp_path / "missing.json")
    assert load_sbom(FIXTURES / "sbom/spdx-mini.json")["spdxVersion"] == "SPDX-2.3"
