# ADR 0015: A model output is admitted only with a named deterministic check

**Status:** proposed · **Date:** 2026-11-18 · Extends ADRs 0002 and 0007 · See `docs/design.md`,
"Where the model works, and where it must not"

## Context
The design adds model work in five places: hop review on native tools, typed edges, version-drift
mapping, fix-commit discovery and plain-language explanations. Each is a new way for a model's
answer to reach a report.

## Decision
A model use is admitted only together with a named deterministic check of its output, written
as code with tests. Where no such check exists, the model stays out. The checks:

| Use | Check |
| --- | --- |
| Function pick | Each name is a candidate; the quote is in the advisory |
| Uncertain hops | The accepted path is re-verified hop by hop |
| Typed edges | One check per edge kind, anchored in reached code (ADR 0016) |
| Version drift | The function exists in the installed version; body similarity above a threshold |
| Fix-commit discovery | The commit lies in the vulnerable-to-fixed range and touches the package |
| Explanations | Every file, line and name in the text appears in the evidence record |

Every stop reason other than normal completion (`refusal`, `max_tokens`, a schema failure after
the one repair retry) leaves the alert open with a typed reason, never a negative answer.

## Consequences
Some model uses that might help are left out until a check exists for them, for example a bridge
from a C function to its Python entry point.
