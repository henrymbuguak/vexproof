"""The select stage and the model commands, with a scripted model in place of the Model API."""

from __future__ import annotations

import json
from collections.abc import Sequence
from pathlib import Path

import pytest
import respx
from typer.testing import CliRunner

from tests.helpers import EPSS, FIXTURES, KEV, OSV
from tests.llm_fakes import Reply, ScriptedTransport, pick, scripted_stack
from tests.symbol_fixtures import ICO, QUOTE, ico_finding
from vexproof import cli
from vexproof.config import Settings
from vexproof.domain import Finding, Level, Package
from vexproof.intel.http import JsonHttp
from vexproof.llm import factory
from vexproof.llm.factory import ModelConfig, ModelStack
from vexproof.llm.types import ModelError, ModelRequest, Transport
from vexproof.modelcheck import PingResult
from vexproof.pipeline import (
    Analyzers,
    IntelConfig,
    ScanResult,
    needs_selection,
    scan,
    select_symbols,
    selection_counts,
)
from vexproof.service import payload
from vexproof.static.modules import ModuleReach

runner = CliRunner()


def _flat(output: str) -> str:
    """Rich wraps long lines at the terminal width; compare text with whitespace collapsed."""
    return " ".join(output.split())


REPO = FIXTURES / "repos/mini-app"
SBOM = FIXTURES / "sbom/cyclonedx-mini.json"


def _variant(advisory_id: str) -> Finding:
    finding = ico_finding()
    return finding.model_copy(
        update={
            "id": advisory_id,
            "advisory": finding.advisory.model_copy(update={"id": advisory_id}),
        }
    )


def _no_prove(
    repo: Path,
    packages: Sequence[Package],
    findings: Sequence[Finding],
    analyzers: Analyzers,
    model: ModelStack | None = None,
    *,
    trace: bool = True,
    reach: ModuleReach | None = None,
) -> tuple[Finding, ...]:
    """The prove stage has its own tests; here it would need real package sources."""
    return tuple(findings)


def _skip_prove(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr("vexproof.pipeline.prove", _no_prove)
    monkeypatch.setattr("vexproof.pipeline.module_closure", lambda *_: ModuleReach())


def _answers(request: ModelRequest) -> Reply:
    if "GHSA-pick" in request.user:
        return pick([ICO], QUOTE)
    if "GHSA-none" in request.user:
        return pick([], QUOTE, none_match=True)
    if "GHSA-invent" in request.user:
        return pick(["PIL.Image.open"], QUOTE)
    if "GHSA-fail" in request.user:
        return ModelError("server said no")
    return {"ok": True, "word": "vexproof"}


def test_select_symbols_handles_every_outcome(tmp_path: Path) -> None:
    stack, live = scripted_stack(_answers, tmp_path)
    l2 = ico_finding(level=Level.L2_MODULE)
    findings = [_variant(i) for i in ("GHSA-pick", "GHSA-none", "GHSA-invent", "GHSA-fail")]
    result = select_symbols([*findings, l2], stack, workers=4)
    assert [needs_selection(f) for f in [*findings, l2]] == [True] * 4 + [False]
    assert result[-1] is l2  # untouched, and never sent to the model
    assert len(live.requests) == 4
    assert result[0].evidence.vulnerable_symbols == (ICO,)  # type: ignore[union-attr]
    assert result[0].evidence.symbol_model == "fake-model / symbol_pick.v1"  # type: ignore[union-attr]
    assert "symbol selection failed: server said no" in result[3].evidence.notes  # type: ignore[union-attr]
    assert selection_counts(result) == {"picked": 1, "none_match": 1, "rejected": 1, "failed": 1}


def test_select_symbols_stops_spending_when_the_budget_is_gone(tmp_path: Path) -> None:
    stack, live = scripted_stack(_answers, tmp_path, max_tokens=1)
    result = select_symbols([_variant("GHSA-pick"), _variant("GHSA-pick-2")], stack, workers=1)
    assert len(live.requests) == 1
    assert "symbol selection skipped: token budget" in result[1].evidence.notes[-1]  # type: ignore[union-attr]


def test_scan_runs_the_select_stage(
    http: JsonHttp,
    mocked_services: respx.MockRouter,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def fake_analyze(
        repo: Path, packages: Sequence[Package], findings: Sequence[Finding], a: Analyzers
    ) -> tuple[Finding, ...]:
        return (_variant("GHSA-pick"),)

    monkeypatch.setattr("vexproof.pipeline.analyze", fake_analyze)
    _skip_prove(monkeypatch)
    stack, _ = scripted_stack(_answers, tmp_path)
    result = scan(
        REPO,
        http=http,
        config=IntelConfig(osv_url=OSV, kev_url=KEV, epss_url=EPSS),
        analyzers=object(),  # type: ignore[arg-type]
        model=stack,
        sbom_path=SBOM,
    )
    assert result.findings[0].evidence.vulnerable_symbols == (ICO,)  # type: ignore[union-attr]
    assert set(result.timings_s) == {"ingest", "intel", "analyze", "select", "prove"}


# -- CLI ---------------------------------------------------------------------------------------


@pytest.fixture
def fake_api(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> list[ModelConfig]:
    """Route the CLI's model stack to a scripted transport; record each config it asks for."""
    monkeypatch.setenv("MODEL_API_KEY", "test-key")
    monkeypatch.setenv("VEXPROOF_CACHE_DIR", str(tmp_path / "cache"))
    configs: list[ModelConfig] = []
    real = factory.build_stack

    def build(config: ModelConfig, live: Transport | None = None) -> ModelStack:
        configs.append(config)
        return real(config, live=ScriptedTransport(_answers))

    monkeypatch.setattr(cli, "build_stack", build)
    monkeypatch.setattr("vexproof.service.build_stack", build)
    monkeypatch.setattr(cli, "list_models", lambda key, url: ["muse-spark-1.1", "muse-spark-1.2"])
    return configs


def test_cli_scan_with_model(
    fake_api: list[ModelConfig],
    mocked_services: respx.MockRouter,
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    monkeypatch.setenv("VEXPROOF_OSV_URL", OSV)
    monkeypatch.setenv("VEXPROOF_KEV_URL", KEV)
    monkeypatch.setenv("VEXPROOF_EPSS_URL", EPSS)
    monkeypatch.setenv("VEXPROOF_PRICE_INPUT_PER_M", "1")
    monkeypatch.setenv("VEXPROOF_PRICE_OUTPUT_PER_M", "2")
    monkeypatch.setattr("vexproof.pipeline.analyze", lambda *a: (_variant("GHSA-pick"),))
    _skip_prove(monkeypatch)
    out = tmp_path / "findings.json"
    result = runner.invoke(
        cli.app, ["scan", str(REPO), "--sbom", str(SBOM), "--json", str(out)], terminal_width=200
    )
    assert result.exit_code == 0, result.output
    text = _flat(result.output)
    assert "1 verified picks" in text
    assert "Model fake-model: 1 call(s), 0 replayed" in text
    assert "about $0.0001" in text
    assert fake_api[0].recordings_dir == tmp_path / "cache/model"
    assert json.loads(out.read_text())["summary"]["selection"]["picked"] == 1
    shown = runner.invoke(cli.app, ["show", str(out), "GHSA-pick"], terminal_width=200)
    assert f"picked: {ICO}" in shown.output
    assert f'advisory says: "{QUOTE}"' in shown.output


def test_cli_scan_model_needs_a_key(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("VEXPROOF_CACHE_DIR", str(tmp_path / "cache"))
    result = runner.invoke(cli.app, ["scan", str(REPO), "--model"])
    assert result.exit_code == 2
    assert "MODEL_API_KEY is not set" in _flat(result.output)


def _findings_file(tmp_path: Path, findings: Sequence[Finding]) -> Path:
    path = tmp_path / "findings.json"
    result = ScanResult(source="s", commit=None, packages=(), findings=tuple(findings))
    path.write_text(json.dumps(payload(result)))
    return path


def _gold(tmp_path: Path, *advisories: str) -> Path:
    path = tmp_path / "gold.yaml"
    lines = ["cases:"]
    for advisory in advisories:
        lines += [
            f"  - advisory: {advisory}",
            "    package: pillow",
            f"    expected: [{ICO}]",
            "    why: w",
        ]
    path.write_text("\n".join(lines) + "\n")
    return path


def test_check_model_connection_only(fake_api: list[ModelConfig]) -> None:
    result = runner.invoke(cli.app, ["check-model"], terminal_width=200)
    assert result.exit_code == 0, result.output
    assert "models available: muse-spark-1.1, muse-spark-1.2" in _flat(result.output)
    assert "structured output: ok on the responses API" in _flat(result.output)
    assert "connection: GO" in _flat(result.output)
    assert fake_api[0].mode == "live"  # the ping is never answered from a recording


def test_check_model_gold_go(fake_api: list[ModelConfig], tmp_path: Path) -> None:
    findings = _findings_file(tmp_path, [_variant("GHSA-pick")])
    gold = _gold(tmp_path, "GHSA-pick", "GHSA-absent")
    result = runner.invoke(
        cli.app, ["check-model", str(findings), "--gold", str(gold)], terminal_width=200
    )
    assert result.exit_code == 0, result.output
    assert "1/1 correct (100%, need 75%), 0 invented name(s)" in _flat(result.output)
    assert "1 gold case(s) not in this findings file" in _flat(result.output)
    assert "verdict: GO" in _flat(result.output)
    assert fake_api[-1].mode == "cache"  # gold answers are recorded for replay


def test_check_model_gold_no_go(fake_api: list[ModelConfig], tmp_path: Path) -> None:
    findings = _findings_file(tmp_path, [_variant("GHSA-invent")])
    gold = _gold(tmp_path, "GHSA-invent")
    result = runner.invoke(
        cli.app, ["check-model", str(findings), "--gold", str(gold)], terminal_width=200
    )
    assert result.exit_code == 1
    assert "1 invented name(s)" in _flat(result.output)
    assert "verdict: NO-GO" in _flat(result.output)


def test_check_model_failures(
    fake_api: list[ModelConfig], tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    bad = tmp_path / "bad.json"
    bad.write_text("{}")
    assert runner.invoke(cli.app, ["check-model", str(bad)]).exit_code == 2
    findings = _findings_file(tmp_path, [_variant("GHSA-pick")])
    missing_gold = runner.invoke(
        cli.app, ["check-model", str(findings), "--gold", str(tmp_path / "nope.yaml")]
    )
    assert missing_gold.exit_code == 2
    assert "cannot read gold file" in _flat(missing_gold.output)

    def unlisted(key: str, url: str) -> list[str]:
        raise ModelError("could not list models: 404")

    monkeypatch.setattr(cli, "list_models", unlisted)
    monkeypatch.setenv("VEXPROOF_MODEL", "muse-spark-9")
    monkeypatch.setattr(
        cli, "ping", lambda stack_for, prefer: PingResult(api=None, errors={"responses": "x"})
    )
    result = runner.invoke(cli.app, ["check-model"], terminal_width=200)
    assert result.exit_code == 1
    assert "warning: could not list models" in _flat(result.output)
    assert "NO-GO: structured output works on neither API" in _flat(result.output)


def test_local_server_works_without_a_key(
    fake_api: list[ModelConfig],
    monkeypatch: pytest.MonkeyPatch,
    mocked_services: respx.MockRouter,
    tmp_path: Path,
) -> None:
    monkeypatch.setenv("MODEL_API_KEY", "")
    monkeypatch.setenv("VEXPROOF_MODEL_BASE_URL", "http://localhost:11434/v1")
    monkeypatch.setenv("VEXPROOF_MODEL", "llama3.1")
    monkeypatch.setenv("VEXPROOF_MODEL_API", "chat")
    monkeypatch.setenv("VEXPROOF_MODEL_TIMEOUT_S", "600")
    monkeypatch.setenv("VEXPROOF_MODEL_WORKERS", "1")
    monkeypatch.setattr(cli, "list_models", lambda key, url: ["llama3.1:latest"])
    checked = runner.invoke(cli.app, ["check-model"], terminal_width=200)
    assert checked.exit_code == 0, checked.output
    text = _flat(checked.output)
    assert "local model server: no API key needed" in text
    assert "is not in that list" not in text  # "llama3.1" is "llama3.1:latest"
    assert "ok on the chat API" in text
    assert (fake_api[-1].timeout_s, fake_api[-1].workers) == (600.0, 1)

    # with a local server configured, scan turns the model on by itself
    monkeypatch.setenv("VEXPROOF_OSV_URL", OSV)
    monkeypatch.setenv("VEXPROOF_KEV_URL", KEV)
    monkeypatch.setenv("VEXPROOF_EPSS_URL", EPSS)
    monkeypatch.setattr("vexproof.pipeline.analyze", lambda *a: (_variant("GHSA-pick"),))
    _skip_prove(monkeypatch)
    out = tmp_path / "findings.json"
    scanned = runner.invoke(
        cli.app, ["scan", str(REPO), "--sbom", str(SBOM), "--json", str(out)], terminal_width=200
    )
    assert scanned.exit_code == 0, scanned.output
    assert "1 verified picks" in _flat(scanned.output)
    payload = json.loads(out.read_text())
    assert payload["model"]["calls"] == 1  # recorded so evaluation can report cost per alert
    assert payload["model"]["by_purpose"] == {"symbol_pick": 1}
    assert payload["model"]["recorded_input_tokens"] == 0  # nothing was replayed
    assert payload["closure"] == {"reached": [], "unreached": [], "blockers": []}
    assert set(payload["timings_s"]) >= {"ingest", "intel", "select", "prove"}


def test_check_model_without_key() -> None:
    result = runner.invoke(cli.app, ["check-model"])
    assert result.exit_code == 1
    assert "MODEL_API_KEY is not set" in _flat(result.output)


HOSTILE = "[/b] :cloud: [link=https://evil.example]click me[/link] [red]"


def test_untrusted_text_is_printed_literally(tmp_path: Path) -> None:
    """Advisory text, model output and model names must never be read as Rich markup or emoji."""
    finding = _variant("GHSA-pick")
    advisory = finding.advisory.model_copy(update={"summary": HOSTILE})
    evidence = finding.evidence.model_copy(  # type: ignore[union-attr]
        update={"notes": (f"model assessment (high confidence): {HOSTILE}",)}
    )
    hostile = finding.model_copy(update={"advisory": advisory, "evidence": evidence})
    out = _findings_file(tmp_path, [hostile])
    shown = runner.invoke(cli.app, ["show", str(out), "GHSA-pick"], terminal_width=200)
    assert shown.exit_code == 0, shown.output  # a stray "[/b]" used to raise MarkupError
    assert HOSTILE in shown.output
    assert "\x1b]8;" not in shown.output  # no hidden terminal hyperlink

    with cli.console.capture() as captured:
        cloud = factory.build_stack(
            ModelConfig(
                api_key=None,
                base_url="http://localhost:11434/v1",
                model="muse-spark-open:cloud",
                recordings_dir=tmp_path / "rec",
            ),
            live=ScriptedTransport([pick([ICO], QUOTE)], model="muse-spark-open:cloud"),
        )
        select_symbols([_variant("GHSA-pick")], cloud)
        cli._render_usage(cloud, Settings())
    assert "Model muse-spark-open:cloud: 1 call(s)" in captured.get()
