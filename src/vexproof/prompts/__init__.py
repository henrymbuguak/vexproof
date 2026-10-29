"""Versioned prompt templates. A prompt never changes in place: edits get a new version file."""

from __future__ import annotations

from importlib.resources import files


def load_prompt(name: str) -> str:
    """Load e.g. `symbol_pick.v1` from `symbol_pick.v1.md` next to this module."""
    return files(__package__).joinpath(f"{name}.md").read_text(encoding="utf-8")
