"""Scans started from the browser: queued, run one at a time, results kept on disk."""

from __future__ import annotations

import json
import secrets
import threading
import time
from collections.abc import Callable
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Literal

import structlog

from vexproof.domain import ServiceProfile

log = structlog.get_logger(__name__)

State = Literal["queued", "running", "done", "failed"]
# What the person sees for each stage, in order. A stage with nothing to do is skipped.
STAGE_LABELS = {
    "checkout": "Fetch the repository at that commit",
    "ingest": "List the dependencies",
    "intel": "Look up advisories, KEV and EPSS",
    "analyze": "Read the fixes and the installed code",
    "select": "Muse Spark picks the vulnerable functions",
    "prove": "Clear or prove each alert",
}
# Runs a scan: (job, progress callback) -> findings.json document
Runner = Callable[["Job", Callable[[str], None]], dict[str, Any]]


@dataclass
class Job:
    id: str
    target: str
    commit: str
    profile: ServiceProfile | None = None
    state: State = "queued"
    stage: str | None = None
    started: dict[str, float] = field(default_factory=dict)
    finished_at: float | None = None
    error: str | None = None

    def stage_rows(self) -> list[dict[str, str]]:
        """Each stage with its state ("done", "running", "waiting" or "skipped")."""
        order = list(STAGE_LABELS)
        current = order.index(self.stage) if self.stage in order else -1
        rows = []
        for i, (key, label) in enumerate(STAGE_LABELS.items()):
            if self.state == "done" or i < current:
                status = "done" if key in self.started else "skipped"
            elif i == current:
                status = "failed" if self.state == "failed" else "running"
            else:
                status = "waiting"
            rows.append({"key": key, "label": label, "status": status})
        return rows

    def status(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "state": self.state,
            "stage": self.stage,
            "stages": self.stage_rows(),
            "error": self.error,
        }


class JobStore:
    """At most `limit` scans waiting; one runs at a time, so a laptop stays usable."""

    def __init__(self, root: Path, runner: Runner, limit: int = 3) -> None:
        self._root = root
        self._runner = runner
        self._limit = limit
        self._jobs: dict[str, Job] = {}
        self._lock = threading.Lock()
        self._pool = ThreadPoolExecutor(max_workers=1, thread_name_prefix="vexproof-scan")

    def path(self, job_id: str) -> Path:
        return self._root / job_id / "findings.json"

    def get(self, job_id: str) -> Job | None:
        with self._lock:
            return self._jobs.get(job_id)

    def pending(self) -> int:
        with self._lock:
            return sum(1 for j in self._jobs.values() if j.state in {"queued", "running"})

    def submit(self, target: str, commit: str, profile: ServiceProfile | None) -> Job | None:
        """Queue a scan; None when the queue is full."""
        with self._lock:
            busy = sum(1 for j in self._jobs.values() if j.state in {"queued", "running"})
            if busy >= self._limit:
                return None
            job = Job(id=secrets.token_hex(6), target=target, commit=commit, profile=profile)
            self._jobs[job.id] = job
        self._pool.submit(self._run, job)
        return job

    def _run(self, job: Job) -> None:
        def progress(stage: str) -> None:
            job.stage = stage
            job.started[stage] = time.time()

        job.state = "running"
        try:
            document = self._runner(job, progress)
            out = self.path(job.id)
            out.parent.mkdir(parents=True, exist_ok=True)
            out.write_text(json.dumps(document), encoding="utf-8")
            job.state = "done"
        except Exception as exc:
            log.warning("web_scan_failed", job=job.id, error=str(exc))
            job.error = str(exc) or type(exc).__name__
            job.state = "failed"
        finally:
            job.finished_at = time.time()

    def shutdown(self) -> None:
        self._pool.shutdown(wait=False, cancel_futures=True)
