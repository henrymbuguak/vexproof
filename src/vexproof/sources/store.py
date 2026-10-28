"""SourceStore: get the SourceTree for an exact package version, cached on disk."""

from __future__ import annotations

import shutil
import tempfile
import threading
from collections.abc import Sequence
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

import structlog

from vexproof.domain import Package
from vexproof.sources.archive import extract_sdist, extract_wheel
from vexproof.sources.pypi import PyPIClient, SourceError
from vexproof.sources.tree import MANIFEST, SourceTree, build_tree

log = structlog.get_logger(__name__)


class SourceStore:
    def __init__(self, cache_dir: Path, pypi: PyPIClient) -> None:
        self._dir = cache_dir / "sources"
        self._pypi = pypi
        self._locks: dict[str, threading.Lock] = {}
        self._guard = threading.Lock()

    def _lock(self, key: str) -> threading.Lock:
        with self._guard:
            return self._locks.setdefault(key, threading.Lock())

    def get(self, package: Package) -> SourceTree:
        key = f"{package.name}-{package.version}"
        root = self._dir / key
        with self._lock(key):
            if (root / MANIFEST).is_file():
                return SourceTree.load(root)
            artifact = self._pypi.artifact(package)
            self._dir.mkdir(parents=True, exist_ok=True)
            with tempfile.TemporaryDirectory(dir=self._dir, prefix=f".{key}.") as tmp:
                work = Path(tmp)
                archive = self._pypi.download(artifact, work / artifact.filename)
                staging = work / "tree"
                extract = extract_wheel if artifact.kind == "wheel" else extract_sdist
                extracted = extract(archive, staging)
                tree = build_tree(package.name, package.version, artifact.kind, extracted)
                tree.save()
                if root.exists():
                    shutil.rmtree(root)
                staging.replace(root)
            log.info("source_ready", package=key, kind=artifact.kind, modules=len(tree.modules))
            return SourceTree.load(root)

    def get_many(
        self, packages: Sequence[Package], workers: int = 8
    ) -> tuple[dict[Package, SourceTree], dict[Package, str]]:
        """Load all packages concurrently. Returns (trees, failures with reasons)."""

        def attempt(package: Package) -> SourceTree | str:
            try:
                return self.get(package)
            except SourceError as exc:
                log.warning("source_unavailable", package=package.name, reason=str(exc))
                return str(exc)

        trees: dict[Package, SourceTree] = {}
        failures: dict[Package, str] = {}
        with ThreadPoolExecutor(max_workers=workers) as pool:
            for package, result in zip(packages, pool.map(attempt, packages), strict=True):
                if isinstance(result, SourceTree):
                    trees[package] = result
                else:
                    failures[package] = result
        return trees, failures
