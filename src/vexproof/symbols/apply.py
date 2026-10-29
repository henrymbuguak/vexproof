"""Record a verified (or rejected) model pick in a finding's evidence."""

from __future__ import annotations

from vexproof.domain import Finding
from vexproof.symbols.verify import Rejected, Verified

CHECKS = ("symbols_in_shortlist", "symbols_in_installed_code", "quote_found_in_advisory")


def apply_outcome(finding: Finding, outcome: Verified | Rejected, label: str) -> Finding:
    evidence = finding.evidence
    if evidence is None:
        return finding
    if isinstance(outcome, Rejected):
        note = f"model pick rejected by verifier: {'; '.join(outcome.reasons)}"
        updated = evidence.model_copy(update={"notes": (*evidence.notes, note)})
    elif outcome.none_match:
        updated = evidence.model_copy(
            update={
                "symbol_quote": outcome.quote,
                "symbol_model": label,
                "checks_passed": (*evidence.checks_passed, "quote_found_in_advisory"),
                "notes": (
                    *evidence.notes,
                    "model assessment: none of the changed functions matches this advisory "
                    f"({outcome.confidence} confidence): {outcome.rationale}",
                ),
            }
        )
    else:
        updated = evidence.model_copy(
            update={
                "vulnerable_symbols": outcome.selected,
                "symbol_quote": outcome.quote,
                "symbol_model": label,
                "checks_passed": (*evidence.checks_passed, *CHECKS),
                "notes": (
                    *evidence.notes,
                    f"model assessment ({outcome.confidence} confidence): {outcome.rationale}",
                ),
            }
        )
    return finding.model_copy(update={"evidence": updated})
