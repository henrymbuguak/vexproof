"""Run a scan from settings: the wiring shared by the command line and the web app."""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit, urlunsplit

from vexproof.config import Settings
from vexproof.domain import Verdict
from vexproof.ingest.repo import checkout
from vexproof.intel.cache import Cache
from vexproof.intel.http import JsonHttp, make_client
from vexproof.llm.factory import ModelConfig, ModelStack, build_stack
from vexproof.llm.meta import Api
from vexproof.llm.recording import Mode
from vexproof.pipeline import (
    Analyzers,
    IntelConfig,
    ScanResult,
    level_counts,
    scan,
    selection_counts,
    verdict_counts,
)
from vexproof.sources.git import GitFixFetcher
from vexproof.sources.pypi import PyPIClient
from vexproof.sources.store import SourceStore

Progress = Callable[[str], None]


@dataclass(frozen=True)
class ScanRequest:
    target: str  # a local directory, or https://github.com/<owner>/<repo>
    commit: str | None = None  # required for a GitHub URL
    sbom: Path | None = None
    analysis: bool = True
    model: bool | None = None  # None: on when one is configured
    trace: bool = True
    workspace: Path = Path(".vexproof-cache/repos")


@dataclass(frozen=True)
class ScanOutcome:
    result: ScanResult
    stack: ModelStack | None
    usage: dict[str, object] | None


def model_config(
    settings: Settings, *, api: Api | None = None, mode: Mode | None = None
) -> ModelConfig:
    key = settings.model_api_key.get_secret_value() if settings.model_api_key else None
    return ModelConfig(
        api_key=key or None,
        base_url=_through_alias(settings.model_base_url, settings.localhost_alias),
        model=settings.model,
        api=api or settings.model_api,
        mode=mode or settings.model_mode,
        max_tokens=settings.model_max_tokens,
        recordings_dir=settings.cache_dir / "model",
        timeout_s=settings.model_timeout_s,
        workers=settings.model_workers,
    )


def _through_alias(url: str, alias: str | None) -> str:
    """`http://localhost:11434/v1` -> `http://host.docker.internal:11434/v1` inside a container."""
    parts = urlsplit(url)
    if not alias or parts.hostname not in {"localhost", "127.0.0.1", "::1"}:
        return url
    netloc = alias + (f":{parts.port}" if parts.port else "")
    return urlunsplit(parts._replace(netloc=netloc))


def usage(stack: ModelStack | None, settings: Settings) -> dict[str, object] | None:
    """Model use for the whole scan: what this run cost, and what a run without recordings costs."""
    if stack is None or not stack.budget.report.total.calls:
        return None
    report = stack.budget.report
    total = report.total
    prices = (settings.price_input_per_m, settings.price_output_per_m)
    return {
        "label": stack.label,
        "calls": total.calls,
        "replayed": total.replayed,
        "input_tokens": total.input_tokens,
        "output_tokens": total.output_tokens,
        "recorded_input_tokens": total.recorded_input_tokens,
        "recorded_output_tokens": total.recorded_output_tokens,
        "cost_usd": report.cost_usd(*prices),
        "fresh_cost_usd": report.cost_usd(*prices, fresh=True),
        "by_purpose": {k: v.calls for k, v in sorted(report.by_purpose.items())},
    }


def run_scan(
    settings: Settings, request: ScanRequest, progress: Progress | None = None
) -> ScanOutcome:
    """Check out the target if it is a URL, then run every stage. Raises VexproofError."""
    tell = progress or (lambda _: None)
    resolved_commit = request.commit
    if request.target.startswith("https://"):
        if not request.commit:
            raise ValueError("a commit is required when scanning a GitHub URL")
        tell("checkout")
        repo = checkout(request.target, request.commit, request.workspace)
        repo_path, resolved_commit = repo.path, repo.commit
    else:
        repo_path = Path(request.target).resolve()
        if not repo_path.is_dir():
            raise ValueError(f"{request.target} is not a directory")
    config = model_config(settings)
    use_model = request.model if request.model is not None else config.ready
    stack = build_stack(config) if use_model and request.analysis else None
    cache = Cache(settings.cache_dir / "http.sqlite3")
    try:
        with make_client(settings.user_agent, settings.http_timeout_s) as client:
            http = JsonHttp(client, cache)
            analyzers = (
                Analyzers(
                    store=SourceStore(
                        settings.cache_dir,
                        PyPIClient(
                            http, client, settings.pypi_url, settings.max_download_mb * 10**6
                        ),
                    ),
                    fetcher=GitFixFetcher(settings.cache_dir),
                    workers=settings.workers,
                )
                if request.analysis
                else None
            )
            result = scan(
                repo_path,
                http=http,
                config=IntelConfig(
                    settings.osv_url, settings.kev_url, settings.epss_url, settings.workers
                ),
                analyzers=analyzers,
                model=stack,
                trace=request.trace,
                sbom_path=request.sbom,
                source=request.target,
                commit=resolved_commit,
                progress=progress,
            )
    finally:
        cache.close()
    return ScanOutcome(result=result, stack=stack, usage=usage(stack, settings))


def payload(result: ScanResult, usage: dict[str, object] | None = None) -> dict[str, Any]:
    """The `findings.json` document: everything later commands and the web app read."""
    closure = result.closure
    return {
        "source": result.source,
        "commit": result.commit,
        "timings_s": {k: round(v, 2) for k, v in result.timings_s.items()},
        "model": usage,
        "closure": None
        if closure is None
        else {
            "reached": list(closure.reached),
            "unreached": list(closure.unreached),
            "blockers": list(closure.blockers),
        },
        "summary": {
            "alerts": len(result.findings),
            "levels": level_counts(result.findings),
            "cleared": sum(1 for f in result.findings if f.verdict is Verdict.NOT_AFFECTED),
            "selection": selection_counts(result.findings),
            "verdicts": verdict_counts(result.findings),
        },
        "packages": [p.model_dump(mode="json") for p in result.packages],
        "findings": [f.model_dump(mode="json") for f in result.findings],
    }
