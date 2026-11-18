# ADR 0017: The MCP surface is read and propose only; approval is human

**Status:** proposed · **Date:** 2026-11-18 · See `docs/design.md`, "MCP server, Claude Code and
human approval"

## Context
vexproof becomes usable from Claude Code and other MCP clients. A clear suppresses an alert, so
an agent must not be able to turn its own work into a `not_affected` statement. An agent with a
shell, running as the same user, can do anything that user can, so no local check is a security
boundary.

## Decision
- The MCP server exposes reading and proposing only: scans, alerts, evidence and VEX drafts.
  There is no approve tool.
- Approval happens through `vexproof approve` in an interactive terminal (it refuses without one)
  or through the review UI, whose approve endpoint requires a same-origin fetch header and a
  per-form token.
- An approval records the reviewer, the time and a hash of the facts that decide the clear: the
  package and version, the referenced fix commits, the deciding modules, and the closure's reasons
  and blockers. Free text is not hashed, so a re-run does not void approvals.
- The export writes `not_affected` only for an alert whose approval record matches that hash.
  Every other clear is exported as `under_investigation`, pending review.
- Reachable verdicts need no approval, since a false alarm is the safe direction.

## Consequences
The guarantee is that every `not_affected` statement vexproof emits traces to an approval record.
A file an agent writes by hand is not vexproof output. Signed approvals with a reviewer key held
outside the agent's environment are future work.
