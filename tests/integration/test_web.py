"""The web app end to end, with a scripted scan runner instead of the network."""

from __future__ import annotations

import json
import threading
import time
from collections.abc import Callable, Iterator
from pathlib import Path
from typing import Any

import pytest
from fastapi.testclient import TestClient

from tests.report_fixtures import HOSTILE, SOURCE, finding, mixed
from vexproof.config import Settings
from vexproof.domain import Verdict
from vexproof.report.openvex import problems
from vexproof.web.app import WebConfig, create_app
from vexproof.web.jobs import Job

REPO = "https://github.com/acme/shop"
COMMIT = "1aa90f67f4559a36d8049d8a2d3fe622791ee95c"


def _document(*findings: Any) -> dict[str, Any]:
    return {
        "source": SOURCE,
        "commit": COMMIT,
        "findings": [f.model_dump(mode="json") for f in (findings or mixed())],
        "closure": {"reached": ["PIL", "PIL.Image"], "unreached": ["PIL.GdImageFile"]},
        "model": {"label": "muse-spark-open:cloud", "fresh_cost_usd": 0.95},
        "timings_s": {"prove": 3.0},
    }


def _settings(tmp_path: Path) -> Settings:
    return Settings.model_validate({"VEXPROOF_CACHE_DIR": tmp_path / "cache", "MODEL_API_KEY": ""})


def _config(tmp_path: Path, demo: bool = True, limit: int = 3) -> WebConfig:
    findings = tmp_path / "demo.json"
    if demo:
        findings.write_text(json.dumps(_document()))
    observed = tmp_path / "observed.json"
    observed.write_text(
        json.dumps(
            {
                "workload": "shop.py",
                "python": "3.8.20",
                "steps": [{"step": "home", "status": 200}, {"step": "admin upload ico"}],
                "loaded_modules": ["PIL", "PIL.Image"],
                "executed_functions": ["PIL.IcoImagePlugin.IcoFile.frame"],
            }
        )
    )
    return WebConfig(
        demo_findings=findings,
        demo_profile=Path("examples/shop_profile.yaml"),
        demo_observed=observed,
        demo_gold=Path("eval/gold/symbols.yaml"),
        queue_limit=limit,
        results_dir=tmp_path / "results",
    )


Runner = Callable[[Job, Callable[[str], None]], dict[str, Any]]


def _runner(document: dict[str, Any] | None = None) -> Runner:
    def run(job: Job, progress: Callable[[str], None]) -> dict[str, Any]:
        for stage in ("checkout", "ingest", "intel", "prove"):
            progress(stage)
        if "broken" in job.target:
            raise RuntimeError("git fetch failed: repository not found")
        return document or _document()

    return run


@pytest.fixture
def client(tmp_path: Path) -> Iterator[TestClient]:
    app = create_app(_settings(tmp_path), _runner(), _config(tmp_path))
    with TestClient(app) as test_client:
        yield test_client


def _wait(client: TestClient, job_id: str) -> dict[str, Any]:
    for _ in range(200):
        status: dict[str, Any] = client.get(f"/scans/{job_id}/status").json()
        if status["state"] in {"done", "failed"}:
            return status
        time.sleep(0.01)
    raise AssertionError("scan did not finish")


def _start(client: TestClient, repo: str = REPO, **extra: str) -> str:
    response = client.post(
        "/scans",
        data={"repo": repo, "commit": COMMIT[:7].upper(), "criticality": "high", **extra},
        follow_redirects=False,
    )
    assert response.status_code == 303, response.text
    return str(response.headers["location"]).rsplit("/", 1)[-1]


def test_home_page_has_the_form_the_demo_and_safe_headers(client: TestClient) -> None:
    response = client.get("/")
    assert response.status_code == 200
    html = response.text
    assert '<html lang="en">' in html
    assert 'href="#main"' in html  # skip link
    assert '<label for="repo">GitHub repository</label>' in html
    assert 'href="/scans/demo"' in html
    assert 'class="hero-trace"' in html  # a certain, short path from the demo
    assert "default-src 'self'" in response.headers["content-security-policy"]
    assert "script-src 'self'" in response.headers["content-security-policy"]
    assert response.headers["x-frame-options"] == "DENY"
    assert client.get("/healthz").json()["status"] == "ok"
    assert client.get("/static/app.css").status_code == 200


def test_no_demo_means_no_demo_link(tmp_path: Path) -> None:
    app = create_app(_settings(tmp_path), _runner(), _config(tmp_path, demo=False))
    with TestClient(app) as test_client:
        assert 'href="/scans/demo"' not in test_client.get("/").text
        assert test_client.get("/scans/demo").status_code == 404


def test_form_errors_are_listed_linked_and_marked(client: TestClient) -> None:
    response = client.post(
        "/scans", data={"repo": "https://gitlab.com/a/b", "commit": "xyz", "criticality": "max"}
    )
    assert response.status_code == 422
    html = response.text
    assert "<title>Error: " in html
    assert 'class="error-summary" role="alert"' in html
    assert '<a href="#repo">Use a public GitHub repository address' in html
    assert '<a href="#commit">A commit is 7 to 40 characters' in html
    assert "Choose low, medium or high." in html
    assert 'aria-invalid="true"' in html
    assert 'value="https://gitlab.com/a/b"' in html  # what was typed is kept
    empty = client.post("/scans", data={})
    assert "Enter the repository" in empty.text
    assert "Enter the commit" in empty.text


def test_cross_site_and_oversized_forms_are_refused(client: TestClient) -> None:
    form = {"repo": REPO, "commit": COMMIT}
    cross = client.post("/scans", data=form, headers={"sec-fetch-site": "cross-site"})
    assert cross.status_code == 403
    other = client.post("/scans", data=form, headers={"origin": "https://evil.example"})
    assert other.status_code == 403
    same = client.post(
        "/scans", data=form, headers={"origin": "http://testserver"}, follow_redirects=False
    )
    assert same.status_code == 303
    huge = client.post("/scans", data={"repo": "x" * 5000, "commit": COMMIT})
    assert huge.status_code == 413


def test_a_scan_from_start_to_result(client: TestClient) -> None:
    job_id = _start(client, internet_facing="on", personal_data="on")
    status = _wait(client, job_id)
    assert status["state"] == "done"
    assert [s["status"] for s in status["stages"]] == [
        "done", "done", "done", "skipped", "skipped", "done"
    ]  # fmt: skip
    html = client.get(f"/scans/{job_id}").text
    assert "<h1>Acme/Shop</h1>" in html  # named by the scanned source
    assert "<code>1aa90f67f455</code>" in html
    assert "internet-facing, high criticality, personal data" in html
    assert "muse-spark-open:cloud" in html
    assert "6 alerts, 4 settled with evidence" in html
    assert 'id="fix-first"' in html
    assert 'href="#upgrades"' in html
    assert "How this was checked" not in html  # only the demo has an observation
    assert client.get(f"/scans/{job_id}/evaluation").status_code == 404

    alert = client.get(f"/scans/{job_id}/alerts/GHSA-kev--pillow")
    assert alert.status_code == 200
    assert "Reachable: a verified call path runs from your code" in alert.text
    assert "Known exploited in the wild (CISA KEV)" in alert.text
    assert 'class="trace"' in alert.text
    assert "&#34;status&#34;: &#34;affected&#34;" in alert.text  # its OpenVEX statement
    assert client.get(f"/scans/{job_id}/alerts/nope").status_code == 404

    vex = client.get(f"/scans/{job_id}/download/openvex.json")
    assert vex.headers["content-disposition"] == 'attachment; filename="Acme-Shop-openvex.json"'
    assert problems(vex.json()) == []
    report = client.get(f"/scans/{job_id}/download/report.html")
    assert report.text.startswith("<!doctype html>")
    findings = client.get(f"/scans/{job_id}/download/findings.json").json()
    assert len(findings["findings"]) == 6
    assert client.get(f"/scans/{job_id}/download/other").status_code == 404


def test_progress_page_before_the_scan_finishes(tmp_path: Path) -> None:
    release = threading.Event()

    def slow(job: Job, progress: Callable[[str], None]) -> dict[str, Any]:
        progress("checkout")
        release.wait(5)
        return _document()

    app = create_app(_settings(tmp_path), slow, _config(tmp_path, limit=1))
    with TestClient(app) as test_client:
        job_id = _start(test_client)
        time.sleep(0.05)
        page = test_client.get(f"/scans/{job_id}").text
        assert f'data-job="{job_id}"' in page
        assert 'role="status" aria-live="polite"' in page
        assert "Fetch the repository at that commit." in page
        assert "<noscript>" in page
        full = test_client.post("/scans", data={"repo": REPO, "commit": COMMIT})
        assert full.status_code == 503
        assert "already waiting" in full.text
        release.set()
        assert _wait(test_client, job_id)["state"] == "done"


def test_a_failed_scan_says_what_went_wrong(client: TestClient) -> None:
    job_id = _start(client, repo="https://github.com/acme/broken")
    assert _wait(client, job_id)["state"] == "failed"
    html = client.get(f"/scans/{job_id}").text
    assert "The scan of acme/broken stopped" in html
    assert "git fetch failed: repository not found" in html
    assert "stage-failed" in html
    assert client.get(f"/scans/{job_id}/download/openvex.json").status_code == 404


def test_unknown_scans(client: TestClient) -> None:
    assert client.get("/scans/abc").status_code == 404
    assert client.get("/scans/abc/status").status_code == 404
    assert "There is no scan with that link" in client.get("/scans/abc").text


def test_demo_result_alert_and_evaluation(client: TestClient) -> None:
    html = client.get("/scans/demo").text
    assert "Demo result" in html
    assert 'href="/scans/demo/evaluation"' in html
    evaluation = client.get("/scans/demo/evaluation").text
    assert "Python 3.8.20" in evaluation
    assert "including image uploads in 1 formats" in evaluation
    assert "Sound: no clear was contradicted" in evaluation
    alert = client.get("/scans/demo/alerts/GHSA-high--pillow").text
    assert "uncertain step, judged plausible by the model" in alert.lower()


def test_untrusted_text_is_escaped(tmp_path: Path) -> None:
    evil = finding("GHSA-evil", verdict=Verdict.AFFECTED, summary=HOSTILE, notes=(HOSTILE,))
    app = create_app(_settings(tmp_path), _runner(_document(evil)), _config(tmp_path))
    with TestClient(app) as test_client:
        job_id = _start(test_client)
        _wait(test_client, job_id)
        for path in (f"/scans/{job_id}", f"/scans/{job_id}/alerts/GHSA-evil--pillow"):
            html = test_client.get(path).text
            assert "<script>alert(1)</script>" not in html
            assert "&lt;script&gt;alert(1)&lt;/script&gt;" in html


def test_serve_command_starts_uvicorn(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    import uvicorn
    from typer.testing import CliRunner

    from vexproof import cli

    calls: list[dict[str, Any]] = []
    monkeypatch.setattr(uvicorn, "run", lambda app, **kw: calls.append(kw))
    monkeypatch.setenv("VEXPROOF_CACHE_DIR", str(tmp_path))
    local = CliRunner().invoke(cli.app, ["serve", "--port", "8123"])
    assert local.exit_code == 0, local.output
    assert calls[-1] == {"host": "127.0.0.1", "port": 8123, "log_level": "warning"}
    assert "listening beyond this computer" not in local.output
    wide = CliRunner().invoke(cli.app, ["serve", "--host", "0.0.0.0"], terminal_width=200)  # noqa: S104
    assert "listening beyond this computer" in " ".join(wide.output.split())
