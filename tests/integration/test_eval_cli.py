"""`vexproof eval`: the terminal summary, the Markdown file and the exit code as a gate."""

from __future__ import annotations

import json
from pathlib import Path

import pytest
from typer.testing import CliRunner

from tests.unit.test_evaluate import _findings
from vexproof import cli

GOLD = Path(__file__).parents[2] / "eval" / "gold" / "symbols.yaml"


def _files(tmp_path: Path, loaded: list[str]) -> tuple[Path, Path]:
    findings = tmp_path / "findings.json"
    findings.write_text(
        json.dumps(
            {
                "source": "shop",
                "findings": [f.model_dump(mode="json") for f in _findings()[:1]],
                "closure": {"reached": ["PIL"], "unreached": ["PIL.ImageMath"]},
            }
        )
    )
    observed = tmp_path / "observed.json"
    observed.write_text(
        json.dumps(
            {
                "workload": "shop.py",
                "python": "3.8.20",
                "loaded_modules": loaded,
                "executed_functions": [],
            }
        )
    )
    return findings, observed


def test_eval_sound(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(cli.console, "width", 200)
    findings, observed = _files(tmp_path, ["PIL"])
    out = tmp_path / "eval.md"
    result = CliRunner().invoke(
        cli.app,
        [
            "eval",
            str(findings),
            "--observed",
            str(observed),
            "--gold",
            str(GOLD),
            "--markdown",
            str(out),
        ],
        terminal_width=200,
    )
    assert result.exit_code == 0, result.output
    assert "verdict: sound" in result.output
    assert "Clears contradicted by the run (module loaded)" in result.output
    assert out.read_text().startswith("# Evaluation: shop")


def test_eval_unsound_fails_the_gate(tmp_path: Path) -> None:
    findings, observed = _files(tmp_path, ["PIL", "PIL.ImageMath"])
    result = CliRunner().invoke(
        cli.app, ["eval", str(findings), "--observed", str(observed)], terminal_width=200
    )
    assert result.exit_code == 1
    text = " ".join(result.output.split())
    assert "wrong clear GHSA-ok: PIL.ImageMath" in text
    assert "missing from the closure PIL.ImageMath" in text
    assert "verdict: UNSOUND" in text


def test_eval_bad_inputs(tmp_path: Path) -> None:
    findings, observed = _files(tmp_path, [])
    runner = CliRunner()
    missing = runner.invoke(cli.app, ["eval", str(tmp_path / "x"), "--observed", str(observed)])
    assert missing.exit_code == 2
    assert "cannot read input" in missing.output
    observed.write_text("{}")
    broken = runner.invoke(cli.app, ["eval", str(findings), "--observed", str(observed)])
    assert broken.exit_code == 2
    assert "not an observation file" in " ".join(broken.output.split())
