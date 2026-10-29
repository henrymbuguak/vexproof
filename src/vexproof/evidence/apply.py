"""Record a call path (or why there is none) in a finding's evidence."""

from __future__ import annotations

from vexproof.domain import Finding, Verdict
from vexproof.evidence.trace import TraceOutcome

CALL_PATH_VERIFIED = "call_path_verified"
PATH_REVIEWED = "uncertain_hops_reviewed_by_model"


def apply_trace(finding: Finding, symbol: str, outcome: TraceOutcome, label: str | None) -> Finding:
    evidence = finding.evidence
    if evidence is None:
        return finding
    if outcome.path is None:
        note = f"{symbol}: {outcome.note}"
        if outcome.candidate is not None:
            note += f" (candidate: {outcome.candidate.render()})"
        updated = evidence.model_copy(update={"notes": (*evidence.notes, note)})
        return finding.model_copy(update={"evidence": updated})
    path = outcome.path
    checks = (CALL_PATH_VERIFIED, PATH_REVIEWED) if outcome.reviewed else (CALL_PATH_VERIFIED,)
    if outcome.reviewed:
        summary = (
            f"call path from your code to {symbol}: {len(path.hops) - 1} hops, "
            f"{path.possible_hops} uncertain hop(s) judged plausible by the model: {outcome.note}"
        )
    else:
        summary = f"call path from your code to {symbol}: {len(path.hops) - 1} hops, all certain"
    updated = evidence.model_copy(
        update={
            "call_chain": path.hops,
            "chain_model": label if outcome.reviewed else None,
            "checks_passed": (*evidence.checks_passed, *checks),
            "notes": (*evidence.notes, summary),
        }
    )
    return finding.model_copy(
        update={"verdict": Verdict.AFFECTED, "justification": None, "evidence": updated}
    )
