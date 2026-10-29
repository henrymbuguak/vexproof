"""OpenVEX v0.2.0: one statement per alert, with the evidence behind its status.

- not_affected: the machine-readable justification plus an impact statement saying how
  vexproof knows (package never imported, or module never loaded).
- affected: an action statement (upgrade to the fixed version) and the verified call path in
  status_notes.
- under_investigation: status_notes saying why it is still open.

The document @id is derived from its content (as vexctl does), so the same findings give the
same id.
"""

from __future__ import annotations

import hashlib
import json
from typing import Any
from urllib.parse import quote

from vexproof.domain import Finding, Verdict
from vexproof.report.context import ReportContext, package_purl
from vexproof.report.priority import Ranked, Tier, rank

CONTEXT = "https://openvex.dev/ns/v0.2.0"
NOT_IN_EXECUTE_PATH = "vulnerable_code_not_in_execute_path"
MAX_NOTE = 1000


def openvex(context: ReportContext, author: str = "vexproof") -> dict[str, Any]:
    ranked = {r.finding.id: r for r in rank(context.findings, context.profile)}
    statements = [
        _statement(f, ranked[f.id], context.product)
        for f in sorted(context.findings, key=lambda f: (f.package.name, f.advisory.id, f.id))
    ]
    digest = hashlib.sha256(
        json.dumps([context.product, statements], sort_keys=True).encode()
    ).hexdigest()
    return {
        "@context": CONTEXT,
        "@id": f"https://openvex.dev/docs/public/vex-{digest}",
        "author": author,
        "role": "Document Creator",
        "timestamp": context.generated_at.isoformat().replace("+00:00", "Z"),
        "version": 1,
        "tooling": context.tooling,
        "statements": statements,
    }


def _statement(finding: Finding, ranked: Ranked, product: str) -> dict[str, Any]:
    advisory = finding.advisory
    vulnerability: dict[str, Any] = {
        "@id": f"https://osv.dev/vulnerability/{quote(advisory.id, safe='')}",
        "name": advisory.id,
    }
    if advisory.summary:
        vulnerability["description"] = advisory.summary
    if advisory.aliases:
        vulnerability["aliases"] = list(advisory.aliases)
    statement: dict[str, Any] = {
        "vulnerability": vulnerability,
        "products": [{"@id": product, "subcomponents": [{"@id": package_purl(finding)}]}],
    }
    if finding.verdict is Verdict.NOT_AFFECTED:
        statement["status"] = "not_affected"
        statement["justification"] = finding.justification or NOT_IN_EXECUTE_PATH
        statement["impact_statement"] = _clip("; ".join(ranked.reasons))
    elif finding.verdict is Verdict.AFFECTED:
        statement["status"] = "affected"
        statement["action_statement"] = _action(finding)
        statement["status_notes"] = _clip(_path_notes(finding, ranked))
    else:
        statement["status"] = "under_investigation"
        statement["status_notes"] = _clip("; ".join(ranked.reasons))
    return statement


def _action(finding: Finding) -> str:
    name, fixed = finding.package.name, finding.advisory.fixed_in
    if fixed:
        return f"Upgrade {name} from {finding.package.version} to {fixed} or later."
    return f"No fixed version of {name} is published; limit use of the call path below."


def _path_notes(finding: Finding, ranked: Ranked) -> str:
    chain = finding.evidence.call_chain if finding.evidence else ()
    steps = " -> ".join(f"{h.symbol} ({h.file}:{h.line})" for h in chain)
    urgency = "fix now" if ranked.tier is Tier.FIX_NOW else "fix soon"
    return f"{ranked.reasons[0]}. Priority: {urgency}. Call path: {steps}"


def _clip(text: str) -> str:
    return text if len(text) <= MAX_NOTE else text[: MAX_NOTE - 3] + "..."


STATUSES = {"not_affected", "affected", "fixed", "under_investigation"}
JUSTIFICATIONS = {
    "component_not_present",
    "vulnerable_code_not_present",
    "vulnerable_code_not_in_execute_path",
    "vulnerable_code_cannot_be_controlled_by_adversary",
    "inline_mitigations_already_exist",
}
DOCUMENT_FIELDS = ("@context", "@id", "author", "timestamp", "version", "statements")


def problems(document: dict[str, Any]) -> list[str]:
    """The OpenVEX v0.2.0 rules this document breaks (empty when it is valid)."""
    found = [f"missing {name}" for name in DOCUMENT_FIELDS if name not in document]
    for i, statement in enumerate(document.get("statements", [])):
        where = f"statement {i}"
        status = statement.get("status")
        if not statement.get("vulnerability", {}).get("name"):
            found.append(f"{where}: vulnerability has no name")
        if not statement.get("products"):
            found.append(f"{where}: no products")
        if status not in STATUSES:
            found.append(f"{where}: unknown status {status!r}")
        justification = statement.get("justification")
        if justification is not None and justification not in JUSTIFICATIONS:
            found.append(f"{where}: unknown justification {justification!r}")
        if status == "not_affected" and not (justification or statement.get("impact_statement")):
            found.append(f"{where}: not_affected needs a justification or impact statement")
        if status == "affected" and not statement.get("action_statement"):
            found.append(f"{where}: affected needs an action statement")
    return found
