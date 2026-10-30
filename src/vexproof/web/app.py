"""Routes. Every page is server-rendered and complete without JavaScript."""

from __future__ import annotations

import json
import re
from collections.abc import AsyncIterator, Awaitable, Callable
from contextlib import asynccontextmanager
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any
from urllib.parse import parse_qs, quote, urlsplit

import yaml
from fastapi import FastAPI, Request
from fastapi.responses import HTMLResponse, JSONResponse, RedirectResponse, Response
from fastapi.staticfiles import StaticFiles
from jinja2 import Environment, FileSystemLoader, select_autoescape

from vexproof import __version__
from vexproof.config import Settings
from vexproof.domain import ServiceProfile
from vexproof.domain.profile import load_service_profile
from vexproof.errors import VexproofError
from vexproof.report.html import render_html
from vexproof.report.openvex import openvex
from vexproof.report.priority import Tier
from vexproof.service import ScanRequest, model_config, payload, run_scan
from vexproof.symbols.gold import GoldCase, load_gold
from vexproof.web.jobs import STAGE_LABELS, Job, JobStore, Runner
from vexproof.web.views import (
    SHOWN_OPEN,
    TIER_CLASS,
    ResultView,
    finding_key,
    repo_name,
    result_view,
    trace,
    verdict_sentence,
)

HERE = Path(__file__).parent
GITHUB_URL = re.compile(r"^https://github\.com/[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+?(\.git)?/?$")
COMMIT = re.compile(r"^[0-9a-f]{7,40}$")
MAX_FORM_BYTES = 4096
DEMO = "demo"
CSP = (
    "default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data:; "
    "font-src 'self'; connect-src 'self'; frame-ancestors 'none'; form-action 'self'; "
    "base-uri 'none'; object-src 'none'"
)


@dataclass(frozen=True)
class WebConfig:
    """Where the bundled demo lives; any file that is missing just switches that part off."""

    demo_findings: Path = Path("examples/demo/findings.json")
    demo_profile: Path = Path("examples/shop_profile.yaml")
    demo_observed: Path = Path("eval/observed/shop-1aa90f6.json")
    demo_gold: Path = Path("eval/gold/symbols.yaml")
    queue_limit: int = 3
    results_dir: Path | None = None  # default: <cache>/web


@dataclass
class _Demo:
    view: ResultView | None = None
    loaded: bool = False
    extras: dict[str, Any] = field(default_factory=dict)


def default_runner(settings: Settings) -> Runner:
    def run(job: Job, progress: Callable[[str], None]) -> dict[str, Any]:
        request = ScanRequest(
            target=job.target, commit=job.commit, workspace=settings.cache_dir / "repos"
        )
        outcome = run_scan(settings, request, progress)
        return payload(outcome.result, outcome.usage)

    return run


def create_app(  # noqa: PLR0915 - one function holds the routes so they share state plainly
    settings: Settings | None = None,
    runner: Runner | None = None,
    config: WebConfig | None = None,
) -> FastAPI:
    settings = settings or Settings()
    config = config or WebConfig()
    store = JobStore(
        config.results_dir or settings.cache_dir / "web",
        runner or default_runner(settings),
        config.queue_limit,
    )
    model = model_config(settings)
    templates = Environment(
        loader=FileSystemLoader(HERE / "templates"),
        autoescape=select_autoescape(["html"]),
        trim_blocks=True,
        lstrip_blocks=True,
    )
    templates.globals.update(
        version=__version__,
        tier_class=TIER_CLASS,
        finding_key=finding_key,
        model_label=model.model if model.ready else None,
    )
    templates.filters["quote"] = lambda s: quote(str(s), safe="")
    templates.filters["sentence"] = lambda s: str(s)[:1].upper() + str(s)[1:]
    demo = _Demo()

    @asynccontextmanager
    async def lifespan(_: FastAPI) -> AsyncIterator[None]:
        yield
        store.shutdown()

    app = FastAPI(
        title="vexproof", docs_url=None, redoc_url=None, openapi_url=None, lifespan=lifespan
    )
    app.mount("/static", StaticFiles(directory=HERE / "static"), name="static")
    app.state.jobs = store

    @app.middleware("http")
    async def security_headers(
        request: Request, call_next: Callable[[Request], Awaitable[Response]]
    ) -> Response:
        response = await call_next(request)
        response.headers["Content-Security-Policy"] = CSP
        response.headers["X-Content-Type-Options"] = "nosniff"
        # same-origin, not no-referrer: browsers then send a real Origin with this app's forms
        response.headers["Referrer-Policy"] = "same-origin"
        response.headers["X-Frame-Options"] = "DENY"
        return response

    def page(template: str, status: int = 200, **values: object) -> HTMLResponse:
        html = templates.get_template(template).render(**values)
        return HTMLResponse(html, status_code=status)

    def demo_view() -> ResultView | None:
        if demo.loaded:
            return demo.view
        demo.loaded = True
        try:
            document = json.loads(config.demo_findings.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            return None
        profile = _profile_or_none(config.demo_profile)
        observed = _json_or_none(config.demo_observed)
        gold = _gold_or_empty(config.demo_gold)
        try:
            demo.view = result_view(document, profile, observed, gold)
        except VexproofError:
            demo.view = None
        return demo.view

    def view_for(job_id: str) -> ResultView | None:
        if job_id == DEMO:
            return demo_view()
        job = store.get(job_id)
        if job is None or job.state != "done":
            return None
        document = json.loads(store.path(job_id).read_text(encoding="utf-8"))
        return result_view(document, job.profile)

    def not_found(what: str) -> HTMLResponse:
        return page("not_found.html", status=404, what=what)

    @app.get("/", response_class=HTMLResponse)
    def home() -> HTMLResponse:
        return page("home.html", demo=demo_view(), form={}, errors={})

    @app.post("/scans", response_class=HTMLResponse, response_model=None)
    async def start(request: Request) -> Response:
        if not _same_origin(request):
            return page(
                "not_found.html",
                status=403,
                heading="That form came from another site",
                what="Start the scan from this page instead.",
            )
        body = await request.body()
        if len(body) > MAX_FORM_BYTES:
            return page(
                "not_found.html",
                status=413,
                heading="That form is too large",
                what="Enter a repository address and a commit, then try again.",
            )
        form = {k: v[0].strip() for k, v in parse_qs(body.decode("utf-8", "replace")).items()}
        errors = _validate(form)
        if errors:
            return page("home.html", status=422, demo=demo_view(), form=form, errors=errors)
        url = form["repo"].removesuffix("/").removesuffix(".git")
        profile = ServiceProfile(
            service=repo_name(url),
            internet_facing=form.get("internet_facing") == "on",
            handles_personal_data=form.get("personal_data") == "on",
            criticality=form.get("criticality", "medium"),  # type: ignore[arg-type]
        )
        job = store.submit(url, form["commit"].lower(), profile)
        if job is None:
            errors = {"form": "Three scans are already waiting. Try again when one finishes."}
            return page("home.html", status=503, demo=demo_view(), form=form, errors=errors)
        return RedirectResponse(f"/scans/{job.id}", status_code=303)

    @app.get("/scans/{job_id}", response_class=HTMLResponse)
    def scan_page(job_id: str) -> HTMLResponse:
        if job_id != DEMO:
            job = store.get(job_id)
            if job is None:
                return not_found("There is no scan with that link. Scans are kept until restart.")
            if job.state != "done":
                return page("progress.html", job=job, name=repo_name(job.target))
        view = view_for(job_id)
        if view is None:
            return not_found("The demo result is not available in this installation.")
        return page("results.html", view=view, job_id=job_id)

    @app.get("/scans/{job_id}/status")
    def status(job_id: str) -> JSONResponse:
        job = store.get(job_id)
        if job is None:
            return JSONResponse({"error": "unknown scan"}, status_code=404)
        return JSONResponse(job.status())

    @app.get("/scans/{job_id}/alerts/{key}", response_class=HTMLResponse)
    def alert_page(job_id: str, key: str) -> HTMLResponse:
        view = view_for(job_id)
        item = view.find(key) if view else None
        if view is None or item is None:
            return not_found("There is no alert with that link in this scan.")
        statement = next(
            (
                s
                for s in openvex(view.context(f"vexproof {__version__}"))["statements"]
                if s["vulnerability"]["name"] == item.finding.advisory.id
                and s["products"][0]["subcomponents"][0]["@id"].endswith(
                    f"/{item.finding.package.name}@{item.finding.package.version}"
                )
            ),
            None,
        )
        return page(
            "alert.html",
            view=view,
            job_id=job_id,
            item=item,
            steps=trace(item.finding),
            verdict=verdict_sentence(item),
            statement=json.dumps(statement, indent=2) if statement else None,
        )

    @app.get("/scans/{job_id}/download/{name}", response_model=None)
    def download(job_id: str, name: str) -> Response:
        view = view_for(job_id)
        if view is None:
            return not_found("There is nothing to download for that scan.")
        stem = view.name.replace("/", "-")
        if name == "findings.json":
            body = json.dumps(view.record.model_dump(mode="json"), indent=2)
            kind = "application/json"
        elif name == "openvex.json":
            body = json.dumps(openvex(view.context(f"vexproof {__version__}")), indent=2)
            kind = "application/json"
        elif name == "report.html":
            body = render_html(view.context(f"vexproof {__version__}"))
            kind = "text/html; charset=utf-8"
        else:
            return not_found("That download does not exist.")
        filename = f"{stem}-{name}"
        return Response(
            body,
            media_type=kind,
            headers={"Content-Disposition": f'attachment; filename="{filename}"'},
        )

    @app.get("/scans/{job_id}/evaluation", response_class=HTMLResponse)
    def evaluation_page(job_id: str) -> HTMLResponse:
        view = view_for(job_id)
        if view is None or view.evaluation is None:
            return not_found("This scan has no run-time evaluation.")
        steps = view.evaluation.observation.steps
        uploads = sum(1 for s in steps if "upload" in str(s.get("step")))
        return page(
            "evaluation.html", view=view, job_id=job_id, ev=view.evaluation, uploads=uploads
        )

    @app.get("/healthz")
    def health() -> dict[str, str]:
        return {"status": "ok", "version": __version__}

    templates.globals.update(
        stage_labels=STAGE_LABELS,
        shown_open=SHOWN_OPEN,
        tiers=Tier,
        trace_of=trace,
        has_demo=lambda: demo_view() is not None,
    )
    return app


def _same_origin(request: Request) -> bool:
    """Refuse forms posted from other sites: scans clone code and may spend model tokens."""
    site = request.headers.get("sec-fetch-site")
    if site is not None:
        return site in {"same-origin", "none"}
    origin = request.headers.get("origin")
    return origin is None or urlsplit(origin).netloc == request.url.netloc


def _validate(form: dict[str, str]) -> dict[str, str]:
    errors = {}
    repo = form.get("repo", "")
    if not repo:
        errors["repo"] = "Enter the repository's GitHub address."
    elif not GITHUB_URL.match(repo):
        errors["repo"] = (
            "Use a public GitHub repository address, like https://github.com/owner/project."
        )
    commit = form.get("commit", "").lower()
    if not commit:
        errors["commit"] = "Enter the commit to scan, so the result can be reproduced."
    elif not COMMIT.match(commit):
        errors["commit"] = "A commit is 7 to 40 characters from 0-9 and a-f."
    if form.get("criticality", "medium") not in {"low", "medium", "high"}:
        errors["criticality"] = "Choose low, medium or high."
    return errors


def _json_or_none(path: Path) -> dict[str, Any] | None:
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return None
    return data if isinstance(data, dict) else None


def _profile_or_none(path: Path) -> ServiceProfile | None:
    try:
        return load_service_profile(path)
    except (VexproofError, yaml.YAMLError):
        return None


def _gold_or_empty(path: Path) -> tuple[GoldCase, ...]:
    try:
        return load_gold(path)
    except VexproofError:
        return ()
