"""Ask the model which shortlisted candidate function(s) an advisory is about."""

from __future__ import annotations

from typing import Literal

from pydantic import BaseModel, ConfigDict, Field

from vexproof.domain import Finding
from vexproof.llm.structured import StructuredCaller
from vexproof.prompts import load_prompt

PROMPT_VERSION = "symbol_pick.v1"
PURPOSE = "symbol_pick"
MAX_CANDIDATES = 12
MAX_ADVISORY_CHARS = 6000
# Reasoning models (Muse Spark, Muse Spark Open) spend output tokens on thinking before the JSON
# answer; too low a cap cuts the answer off. Only tokens actually generated are billed.
MAX_OUTPUT_TOKENS = 4096


class SymbolPick(BaseModel):
    model_config = ConfigDict(extra="forbid")

    selected: list[str] = Field(description="exact candidate names; empty if none match")
    none_match: bool = Field(description="true if no candidate belongs to this advisory")
    advisory_quote: str = Field(description="words copied exactly from the advisory")
    rationale: str = Field(description="one or two sentences")
    confidence: Literal["high", "medium", "low"]


def _neutralise(text: str) -> str:
    """Stop untrusted text from closing our data tags early."""
    return text.replace("</", "< /")


def render_user(finding: Finding) -> str:
    advisory = finding.advisory
    evidence = finding.evidence
    candidates = evidence.candidates[:MAX_CANDIDATES] if evidence else ()
    body = f"{advisory.summary}\n\n{advisory.details}".strip()[:MAX_ADVISORY_CHARS]
    parts = [
        f'<advisory id="{advisory.id}" package="{finding.package.name}" '
        f'installed_version="{finding.package.version}">',
        _neutralise(body),
        "</advisory>",
        "",
        "<candidates>",
    ]
    for candidate in candidates:
        parts += [
            f'<candidate name="{candidate.qualname}" file="{candidate.file}" '
            f'changed_lines="{candidate.changed_lines}">',
            _neutralise(candidate.diff or "(diff unavailable)"),
            "</candidate>",
        ]
    parts.append("</candidates>")
    return "\n".join(parts)


def pick_symbols(finding: Finding, caller: StructuredCaller) -> SymbolPick:
    return caller.ask(
        SymbolPick,
        purpose=PURPOSE,
        prompt_version=PROMPT_VERSION,
        system=load_prompt(PROMPT_VERSION),
        user=render_user(finding),
        max_output_tokens=MAX_OUTPUT_TOKENS,
    )
