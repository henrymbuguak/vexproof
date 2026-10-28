from __future__ import annotations

import json
from pathlib import Path

import pytest
import respx
from typer.testing import CliRunner

from tests.helpers import EPSS, FIXTURES, KEV, OSV
from vexproof.cli import app
from vexproof.intel.http import JsonHttp
from vexproof.pipeline import IntelConfig, scan

CONFIG = IntelConfig(osv_url=OSV, kev_url=KEV, epss_url=EPSS)
REPO = FIXTURES / "repos/mini-app"


def test_scan_end_to_end_with_mocked_services(
    http: JsonHttp, mocked_services: respx.MockRouter
) -> None:
    result = scan(REPO, http=http, config=CONFIG, sbom_path=FIXTURES / "sbom/cyclonedx-mini.json")
    assert [p.name for p in result.packages if p.direct] == ["examplelib", "other-lib"]
    assert [f.advisory.id for f in result.findings] == [
        "GHSA-aaaa-bbbb-cccc",
        "GHSA-dddd-eeee-ffff",
        "PYSEC-2026-7",
    ]
    # the alias-less PYSEC-2026-8 duplicates the KEV advisory and is merged into it
    assert "PYSEC-2026-8" in result.findings[0].advisory.aliases
    # PYSEC-2026-7 stays counted but is disputed by its own reviewed GHSA alias
    assert result.findings[2].advisory.disputed_by == "GHSA-gggg-hhhh-iiii"
    assert result.findings[0].advisory.disputed_by is None
    kev_hit = result.findings[0]
    assert kev_hit.signals.in_kev
    assert kev_hit.signals.epss_percentile == 0.998
    assert set(result.timings_s) == {"ingest", "intel"}


def test_scan_uses_sbom_generator_when_no_sbom(
    http: JsonHttp, mocked_services: respx.MockRouter
) -> None:
    seen: list[Path] = []

    def generator(path: Path) -> dict[str, object]:
        seen.append(path)
        document: dict[str, object] = json.loads(
            (FIXTURES / "sbom/cyclonedx-mini.json").read_text()
        )
        return document

    result = scan(REPO, http=http, config=CONFIG, sbom_generator=generator)
    assert seen == [REPO]
    assert len(result.findings) == 3


def test_cli_scan_writes_json(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, mocked_services: respx.MockRouter
) -> None:
    monkeypatch.setenv("VEXPROOF_OSV_URL", OSV)
    monkeypatch.setenv("VEXPROOF_KEV_URL", KEV)
    monkeypatch.setenv("VEXPROOF_EPSS_URL", EPSS)
    monkeypatch.setenv("VEXPROOF_CACHE_DIR", str(tmp_path / "cache"))
    out = tmp_path / "findings.json"
    result = CliRunner().invoke(
        app,
        [
            "scan",
            str(REPO),
            "--sbom",
            str(FIXTURES / "sbom/cyclonedx-mini.json"),
            "--profile",
            str(FIXTURES.parents[1] / "examples/service_profile.yaml"),
            "--json",
            str(out),
            "--no-analysis",
        ],
    )
    assert result.exit_code == 0, result.output
    assert "3 scanner alerts" in result.output
    assert "1 alert(s) disputed" in result.output
    assert "Evidence levels" not in result.output
    payload = json.loads(out.read_text())
    assert payload["summary"] == {
        "alerts": 3,
        "levels": {"L0": 0, "L1": 0, "L2": 0, "L3": 0},
        "cleared": 0,
    }
    assert payload["findings"][0]["signals"]["in_kev"] is True


def test_cli_rejects_bad_inputs(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("VEXPROOF_CACHE_DIR", str(tmp_path / "cache"))
    runner = CliRunner()
    no_commit = runner.invoke(app, ["scan", "https://github.com/a/b"])
    assert no_commit.exit_code != 0
    bad_url = runner.invoke(app, ["scan", "https://gitlab.com/a/b", "--commit", "abc1234"])
    assert bad_url.exit_code == 2
    assert "only https://github.com" in bad_url.output
    missing_dir = runner.invoke(app, ["scan", str(tmp_path / "nope")])
    assert missing_dir.exit_code != 0
    assert runner.invoke(app, ["version"]).exit_code == 0
