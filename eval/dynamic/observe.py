"""Run a project under a workload and record what actually loads and executes.

This is the evaluation oracle, not part of vexproof: it EXECUTES the target project, so run it
only in a throwaway environment (a fresh venv or the Dockerfile next to this file) holding the
project's exact pinned dependencies. vexproof itself never runs target code (ADR 0001).

    python observe.py --project path/to/repo --settings myshop.settings \
        --workload workloads/shop.py --out observed.json

A workload file defines `setup()` (database, users, fixtures; not observed for calls) and
`run()` (what users do; every call is recorded). Output: the modules in sys.modules at the end,
and every function called during `run()`, named `module.Class.function` as vexproof names them. Standard library only; runs on
Python 3.8+ so old projects can use the interpreter they were written for.
"""

from __future__ import annotations

import argparse
import ast
import importlib.util
import json
import os
import platform
import shutil
import sys
import sysconfig
import tempfile
import threading
import time
from pathlib import Path

_CALLS = set()  # (filename, firstlineno)


def _profile(frame, event, arg):  # noqa: ARG001 - sys.setprofile signature
    if event == "call":
        code = frame.f_code
        _CALLS.add((code.co_filename, code.co_firstlineno))


def _roots(project):
    roots = [project]
    for key in ("purelib", "platlib"):
        path = Path(sysconfig.get_paths()[key]).resolve()
        if path not in roots:
            roots.append(path)
    return roots


def _module_name(path, roots):
    for root in roots:
        try:
            rel = path.relative_to(root)
        except ValueError:
            continue
        parts = list(rel.with_suffix("").parts)
        if parts and parts[-1] == "__init__":
            parts = parts[:-1]
        return ".".join(parts) if parts else None
    return None


def _definitions(path):
    """First line of each def (its first decorator, as code objects count it) -> qualname."""
    try:
        tree = ast.parse(path.read_text(encoding="utf-8", errors="replace"))
    except (OSError, SyntaxError, ValueError):
        return {}
    found = {}

    def walk(node, prefix):
        for child in ast.iter_child_nodes(node):
            if isinstance(child, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
                name = prefix + [child.name]
                if not isinstance(child, ast.ClassDef):
                    lines = [child.lineno] + [d.lineno for d in child.decorator_list]
                    for line in set(lines):
                        found[line] = ".".join(name)
                walk(child, name)

    walk(tree, [])
    return found


def executed_functions(project):
    roots = _roots(project)
    names = set()
    cache = {}
    for filename, line in _CALLS:
        path = Path(filename)
        if not path.is_absolute() or path.suffix != ".py":
            continue
        path = path.resolve()
        module = _module_name(path, roots)
        if module is None:
            continue
        if path not in cache:
            cache[path] = _definitions(path)
        qual = cache[path].get(line)
        if qual:
            names.add(module + "." + qual)
    return sorted(names)


def _load_workload(path):
    spec = importlib.util.spec_from_file_location("vexproof_workload", str(path))
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _versions():
    try:
        from importlib import metadata  # noqa: PLC0415
    except ImportError:  # pragma: no cover - Python < 3.8
        return {}
    return {d.metadata["Name"].lower(): d.version for d in metadata.distributions()}


def main():
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    parser.add_argument("--project", required=True, type=Path)
    parser.add_argument("--settings", required=True, help="Django settings module")
    parser.add_argument("--workload", required=True, type=Path)
    parser.add_argument("--out", required=True, type=Path)
    args = parser.parse_args()

    project = args.project.resolve()
    out = args.out.resolve()
    workload = _load_workload(args.workload.resolve())
    scratch = Path(tempfile.mkdtemp(prefix="vexproof-observe-"))
    sys.path.insert(0, str(project))
    os.chdir(str(scratch))
    started = time.time()
    state = workload.setup(project=project, settings=args.settings, scratch=scratch)
    sys.setprofile(_profile)
    threading.setprofile(_profile)
    try:
        steps = workload.run(
            project=project, settings=args.settings, scratch=scratch, state=state
        )
    finally:
        sys.setprofile(None)
        threading.setprofile(None)
        os.chdir(str(project))
        shutil.rmtree(str(scratch), ignore_errors=True)
    result = {
        "project": project.name,
        "workload": args.workload.name,
        "python": platform.python_version(),
        "packages": _versions(),
        "seconds": round(time.time() - started, 1),
        "steps": steps,
        "loaded_modules": sorted(sys.modules),
        "executed_functions": executed_functions(project),
    }
    out.write_text(json.dumps(result, indent=1) + "\n", encoding="utf-8")
    print(
        "observed {} steps: {} modules loaded, {} functions executed -> {}".format(
            len(steps), len(result["loaded_modules"]), len(result["executed_functions"]), out
        )
    )


if __name__ == "__main__":
    main()
