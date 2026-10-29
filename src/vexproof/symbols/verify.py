"""Check every model pick deterministically. The AI proposes; the verifier proves.

A pick is accepted only if:
- every selected name is one of the finding's candidates (which Chapter 2 already verified to
  exist in the installed code);
- the selection is consistent: either some names and `none_match` false, or no names and
  `none_match` true;
- the quote appears in the advisory text (ignoring case, whitespace and markdown formatting),
  and is long enough to mean something.
"""

from __future__ import annotations

import re
from dataclasses import dataclass

from vexproof.domain import Finding
from vexproof.symbols.select import SymbolPick

MIN_QUOTE_CHARS = 12
# Typographic quotes (U+201C, U+201D, U+2018, U+2019) compare equal to plain ones.
_FORMATTING = str.maketrans(
    {
        "`": "",
        "*": "",
        "_": " ",
        chr(0x201C): '"',
        chr(0x201D): '"',
        chr(0x2018): "'",
        chr(0x2019): "'",
    }
)
_SPACE = re.compile(r"\s+")


def normalise(text: str) -> str:
    return _SPACE.sub(" ", text.translate(_FORMATTING)).strip().casefold()


@dataclass(frozen=True)
class Verified:
    selected: tuple[str, ...]
    none_match: bool
    quote: str
    confidence: str
    rationale: str


@dataclass(frozen=True)
class Rejected:
    reasons: tuple[str, ...]
    rationale: str


def verify(pick: SymbolPick, finding: Finding) -> Verified | Rejected:
    candidates = {c.qualname for c in finding.evidence.candidates} if finding.evidence else set()
    selected = tuple(dict.fromkeys(pick.selected))  # drop duplicates, keep order
    reasons: list[str] = []
    unknown = [name for name in selected if name not in candidates]
    if unknown:
        reasons.append(f"selected names that are not candidates: {', '.join(unknown)}")
    if pick.none_match and selected:
        reasons.append("none_match is true but functions were selected")
    if not pick.none_match and not selected:
        reasons.append("no function selected and none_match is false")
    quote = normalise(pick.advisory_quote)
    advisory = normalise(f"{finding.advisory.summary} {finding.advisory.details}")
    if len(quote) < MIN_QUOTE_CHARS:
        reasons.append("quote too short to support the answer")
    elif quote not in advisory:
        reasons.append("quote does not appear in the advisory")
    if reasons:
        return Rejected(reasons=tuple(reasons), rationale=pick.rationale)
    return Verified(
        selected=selected,
        none_match=pick.none_match,
        quote=pick.advisory_quote.strip(),
        confidence=pick.confidence,
        rationale=pick.rationale,
    )
