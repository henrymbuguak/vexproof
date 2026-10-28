"""A real local git repository with a vulnerable commit and a fix, for fetcher tests."""

from __future__ import annotations

import subprocess
from dataclasses import dataclass
from pathlib import Path

VULNERABLE = """import os


def load(data):
    return eval(data)


class Parser:
    def feed(self, chunk):
        self.buf = chunk

    def close(self):
        return self.buf


VERSION = "1.0"
"""

FIXED = """import ast
import os


def load(data):
    return ast.literal_eval(data)


class Parser:
    def feed(self, chunk):
        if len(chunk) > 1024:
            raise ValueError("chunk too large")
        self.buf = chunk

    def close(self):
        return self.buf


VERSION = "1.0.1"
"""


@dataclass(frozen=True)
class Upstream:
    path: Path
    vulnerable: str
    fix: str
    native_fix: str


def _git(repo: Path, *args: str) -> str:
    return subprocess.run(  # noqa: S603 - test helper with fixed arguments
        ["git", "-C", str(repo), *args],  # noqa: S607
        check=True,
        capture_output=True,
        text=True,
    ).stdout.strip()


def make_upstream(root: Path, owner: str = "example", repo: str = "examplelib") -> Upstream:
    path = root / f"{owner}__{repo}"
    path.mkdir(parents=True)
    _git(path, "init", "-q", "-b", "main")
    _git(path, "config", "user.email", "t@example.com")
    _git(path, "config", "user.name", "t")
    _git(path, "config", "uploadpack.allowAnySHA1InWant", "true")
    _git(path, "config", "uploadpack.allowFilter", "true")
    files = {
        "src/examplelib/__init__.py": "",
        "src/examplelib/parser.py": VULNERABLE,
        "src/examplelib/_speedups.c": "int f(void) { return 0; }\n",
        "tests/test_parser.py": "def test_load():\n    pass\n",
    }
    for rel, text in files.items():
        (path / rel).parent.mkdir(parents=True, exist_ok=True)
        (path / rel).write_text(text)
    _git(path, "add", "-A")
    _git(path, "commit", "-qm", "vulnerable")
    vulnerable = _git(path, "rev-parse", "HEAD")
    (path / "src/examplelib/parser.py").write_text(FIXED)
    (path / "src/examplelib/new_module.py").write_text("def added():\n    pass\n")
    (path / "tests/test_parser.py").write_text("def test_load():\n    assert True\n")
    _git(path, "add", "-A")
    _git(path, "commit", "-qm", "fix: stop using eval")
    fix = _git(path, "rev-parse", "HEAD")
    (path / "src/examplelib/_speedups.c").write_text("int f(void) { return 1; }\n")
    (path / "tests/test_parser.py").write_text("def test_load():\n    assert 1\n")
    (path / "CHANGES.rst").write_text("fixed overflow\n")
    _git(path, "add", "-A")
    _git(path, "commit", "-qm", "fix: overflow in C code")
    native_fix = _git(path, "rev-parse", "HEAD")
    return Upstream(path=path, vulnerable=vulnerable, fix=fix, native_fix=native_fix)
