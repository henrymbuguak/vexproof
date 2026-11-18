# ADR 0014: Loops use native tool calls and append-only history

**Status:** proposed · **Date:** 2026-11-18 · See `docs/design.md`, "Agent loop"

## Context
`Tracer._review` re-renders the whole history into one user message at every step and shortens
older observations. The prefix changes each time, so nothing can be cached, and cost grows with
the square of the step count. Actions are free-form JSON with about 100 lines of synonym and
wrapper repair, which a model with enforced schemas does not need and which could hide its
regressions.

## Decision
- The existing loop is refactored in place, not duplicated. Its five actions become strict tools
  called with `tool_choice: auto`; a tool is never forced.
- History is append-only for the whole loop. Tool results are bounded at the source. A loop that
  would need compaction ends, and a new, separately recorded request starts from a summary.
- One loop per target function, never per alert, run in sequence in report order, as `prove()`
  does today. The loop never sees the advisory or the fix diff.
- A loop replays from start to finish or runs live from start to finish. In `cache` mode a miss
  reruns the whole loop live; in `replay` mode a miss is an error.
- Synonym and wrapper repair moves into the Muse adapter.

## Consequences
The cached prefix (tools, system prompt, framework notes) is shared by every loop in a scan.
Alerts that share a vulnerable function keep sharing one review and one recording. Loops cannot
run in parallel while approved hops carry over between them.
