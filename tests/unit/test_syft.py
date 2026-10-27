from __future__ import annotations

import json
import shutil
import subprocess
from pathlib import Path

import pytest

from vexproof.errors import IngestError
from vexproof.ingest import syft


def test_pinned_version_parsing(tmp_path: Path) -> None:
    versions = tmp_path / "versions.env"
    versions.write_text("# comment\nSYFT_VERSION=v1.2.3\n")
    assert syft.pinned_syft_version(versions) == "1.2.3"
    versions.write_text("SYFT_VERSION=\n")
    assert syft.pinned_syft_version(versions) is None
    assert syft.pinned_syft_version(tmp_path / "missing") is None


def test_missing_syft_gives_actionable_error(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(shutil, "which", lambda _: None)
    with pytest.raises(IngestError, match="--sbom"):
        syft.generate_sbom(Path())


def test_generate_sbom_runs_cyclonedx_output(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(shutil, "which", lambda _: "/usr/bin/syft")
    seen: list[list[str]] = []

    def fake_run(cmd: list[str], **_: object) -> subprocess.CompletedProcess[str]:
        seen.append(cmd)
        out = "Version: 1.2.3\n" if cmd[1] == "version" else json.dumps({"bomFormat": "CycloneDX"})
        return subprocess.CompletedProcess(cmd, 0, stdout=out, stderr="")

    monkeypatch.setattr(subprocess, "run", fake_run)
    doc = syft.generate_sbom(tmp_path, versions_file=tmp_path / "none")
    assert doc == {"bomFormat": "CycloneDX"}
    assert seen[1][1:4] == [f"dir:{tmp_path}", "-o", "cyclonedx-json"]


def test_syft_bad_output(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(shutil, "which", lambda _: "/usr/bin/syft")
    monkeypatch.setattr(
        subprocess,
        "run",
        lambda cmd, **_: subprocess.CompletedProcess(cmd, 0, stdout="oops", stderr=""),
    )
    with pytest.raises(IngestError, match="not valid JSON"):
        syft.generate_sbom(tmp_path)
