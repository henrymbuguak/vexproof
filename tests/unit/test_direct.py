from __future__ import annotations

from pathlib import Path

from tests.helpers import FIXTURES
from vexproof.ingest.direct import direct_dependency_names


def test_reads_pyproject_extras_and_requirements() -> None:
    names = direct_dependency_names(FIXTURES / "repos/mini-app")
    assert names == frozenset({"examplelib", "other-lib", "pytest", "flask"})


def test_poetry_sections(tmp_path: Path) -> None:
    (tmp_path / "pyproject.toml").write_text(
        "[tool.poetry.dependencies]\npython = '^3.12'\nDjango = '^5'\n"
        "[tool.poetry.group.test.dependencies]\npytest = '*'\n"
    )
    assert direct_dependency_names(tmp_path) == frozenset({"django", "pytest"})


def test_broken_pyproject_is_tolerated(tmp_path: Path) -> None:
    (tmp_path / "pyproject.toml").write_text("[project\n")
    assert direct_dependency_names(tmp_path) == frozenset()
