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
    # the model layer knows nothing about vulnerabilities; symbols uses it but never the network
    "llm": {"errors", "llm"},
    "prompts": set(),
    "symbols": {"domain", "errors", "llm", "prompts", "symbols"},
    # evidence combines static analysis with the model; static never depends on it
    "evidence": {"domain", "errors", "evidence", "llm", "prompts", "static"},
    # reports read finished findings only: they cannot change a verdict or call the model
    "report": {"domain", "errors", "report"},
    # evaluation reads findings and an observation; it reuses how clears pick their modules
    "evaluate": {"domain", "errors", "evaluate", "evidence", "symbols"},
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


def test_only_the_model_layer_talks_to_the_model_api() -> None:
    for module in SRC.rglob("*.py"):
        if module.parent.name == "llm":
            continue
        source = module.read_text(encoding="utf-8")
        assert "import openai" not in source, f"{module.relative_to(SRC)} imports openai"


def test_prompts_are_versioned_files() -> None:
    prompts = sorted(p.name for p in (SRC / "prompts").glob("*.md"))
    assert prompts
    assert all(".v" in name for name in prompts)
