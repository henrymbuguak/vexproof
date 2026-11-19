"""Workload for observe.py: start the app, then import every production module of the project.

Module loading depends far less on what users do than function calls do, so this sweep is the
strongest cheap check of vexproof's closure: every module it loads must be in the closure, or a
module-level clear could be wrong (ADR 0011). It EXECUTES the project, so run it only in the
container from `sweep_in_docker.sh`, with networking off.

    python observe.py --project /src --settings myproj.settings \
        --workload workloads/import_sweep.py --out sweep.json

`--settings -` skips Django (Flask, FastAPI). Test code is skipped the way vexproof skips it, so
the sweep loads what production can load, never more.
"""

import importlib
import os
import sys
import traceback
from pathlib import Path

# The same split as vexproof's is_test_path and SKIP_DIRS (src/vexproof/static/project.py), so
# the sweep imports production code only. Skipping docs as well imports less, never more.
_TEST_DIRS = {"tests", "test", "testing"}
_SKIP_DIRS = {
    ".git", ".hg", ".svn", ".venv", "venv", "env", ".env", "node_modules", "build", "dist",
    "site-packages", "__pycache__", ".tox", ".nox", ".eggs", "docs", "doc",
}


def _is_test(rel):
    name = rel.name
    return (
        any(part in _TEST_DIRS for part in rel.parts[:-1])
        or name.startswith("test_")
        or name.endswith("_test.py")
        or name in {"conftest.py", "tests.py", "test.py"}
    )


def _modules(project):
    """Dotted names of the project's production modules, packages first, in a stable order."""
    names = []
    for path in sorted(project.rglob("*.py")):
        rel = path.relative_to(project)
        if any(p in _SKIP_DIRS or p.startswith(".") for p in rel.parts[:-1]) or _is_test(rel):
            continue
        parts = list(rel.with_suffix("").parts)
        if parts[-1] == "__init__":
            parts = parts[:-1]
        if parts and all(p.isidentifier() or p[0].isdigit() for p in parts):
            names.append(".".join(parts))
    return sorted(set(names), key=lambda n: (n.count("."), n))


def setup(project, settings, scratch):  # noqa: ARG001 - observe.py calls it with keywords
    if settings != "-":
        os.environ.setdefault("DJANGO_SETTINGS_MODULE", settings)
        import django  # noqa: PLC0415

        django.setup()  # loads INSTALLED_APPS, as the app does at start
    return None


def run(project, settings, scratch, state):  # noqa: ARG001
    steps = []
    for name in _modules(Path(project)):
        if name in sys.modules:
            continue
        try:
            importlib.import_module(name)
            steps.append({"step": "import " + name, "status": "ok"})
        except BaseException as exc:  # noqa: BLE001 - a failed import is data, not a stop
            last = traceback.format_exception_only(type(exc), exc)[-1].strip()
            steps.append({"step": "import " + name, "status": "error", "error": last[:300]})
    return steps
