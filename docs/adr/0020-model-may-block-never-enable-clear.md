# ADR 0020: A model may block a clear, never enable or narrow one

**Status:** accepted · **Date:** 2026-11-18, implemented 2026-11-19 · Amends ADR 0008 · See `docs/design.md`, "Where the
model stays out"

## Context
ADR 0008 clears an alert when every module that decides it is outside the closure, and takes
those modules from the verified vulnerable functions when there are any. So a model's pick narrows
the set of modules that must be unloaded: a wrong pick with a real quote passes the verifier and
can support a wrong clear. All 14 clears in the sample scan rest on a pick.

## Decision
- A clear requires **every** module the fix changes to be outside the closure: the modules of
  every changed function and every module-level change, whatever the model picked.
- Model output may block a clear and nothing more. A none-match answer keeps blocking clears, as
  it does today, because the vulnerable code may lie outside the changed functions.
- Changed modules come only from fix commits named in the advisory's own references. A
  model-inferred fix commit and a version-drift mapping can never supply or remove a module that
  decides a clear.
- An advisory with no referenced fix commit is never cleared at module level; it can still be
  cleared at Level 0 when its whole package is outside the import closure.
- A pick only steers where the path search aims.

## Consequences
A recount on both evaluated scans shows all 30 existing clears survive the stricter rule
(14 of 14 on the shop, 16 of 16 on justdjango), so no published result changes. Clears now rest
on deterministic facts alone, which every false-clear figure and every VEX statement depends on.
More modules decide each clear, so clears group more tightly: 20 groups instead of 24.
