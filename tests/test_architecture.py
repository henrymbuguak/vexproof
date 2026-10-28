"""Import-direction rules: each stage may depend only on domain and earlier stages."""

from __future__ import annotations

import ast
from pathlib import Path

import pytest

SRC = Path(__file__).parents[1] / "src" / "vexproof"
ALLOWED = {
    "domain": {"domain", "errors"},
    "ingest": {"domain", "errors", "ingest", "gitcmd"},
    "intel": {"domain", "errors", "intel"},
    "sources": {"domain", "errors", "sources", "gitcmd", "intel"},
    "static": {"domain", "errors", "static", "sources"},
}


def test_gitcmd_depends_only_on_errors() -> None:
    assert _vexproof_imports(SRC / "gitcmd.py") <= {"errors"}


def _vexproof_imports(path: Path) -> set[str]:
    found: set[str] = set()
    for node in ast.walk(ast.parse(path.read_text(encoding="utf-8"))):
        if isinstance(node, ast.ImportFrom) and node.module and node.module.startswith("vexproof."):
            found.add(node.module.split(".")[1])
        elif isinstance(node, ast.Import):
            found |= {a.name.split(".")[1] for a in node.names if a.name.startswith("vexproof.")}
    return found


@pytest.mark.parametrize("stage", sorted(ALLOWED))
def test_stage_imports_respect_direction(stage: str) -> None:
    stage_dir = SRC / stage
    if not stage_dir.is_dir():
        pytest.skip(f"stage {stage} not built yet")
    for module in stage_dir.rglob("*.py"):
        illegal = _vexproof_imports(module) - ALLOWED[stage]
        assert not illegal, f"{module.relative_to(SRC)} imports {sorted(illegal)}"
