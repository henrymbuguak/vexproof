# ADR 0007: The model proposes, a verifier decides, and every answer is recorded

**Status:** accepted · **Date:** 2026-10-28

## Context
Symbol selection is the first step where a model's output becomes evidence. A wrong function
sends the call-path search after the wrong target; an invented one would be worse. Model calls
also cost money and vary between runs, which makes results hard to reproduce and to evaluate.

## Decision
- **Closed choice.** The model only chooses among candidates that deterministic analysis already
  found in the fix commit *and* in the installed code. It never names functions freely.
- **Verified grounding.** Each pick carries a quote from the advisory. A verifier accepts the pick
  only if every name is a candidate, the selection is consistent, and the quote appears in the
  advisory (ignoring case, spacing, markdown and typographic quotes). Rejected picks change
  nothing.
- **Untrusted input.** Advisory text and diffs are wrapped in data tags and cannot close them;
  the prompt says to treat them as data.
- **Structured output.** Strict JSON schemas generated from Pydantic models, one repair retry,
  then a clear error. Responses API first, Chat Completions as a fallback.
- **Recordings.** Every answer is stored as JSON lines, keyed by a hash of model, prompt version,
  prompts and schema. `cache` (default) reuses them, `replay` refuses to call the API, `live`
  never records. Changing a prompt means a new version file, so old answers are never reused for
  new prompts.
- **Budget.** A hard token budget per run (`VEXPROOF_MODEL_MAX_TOKENS`); when it is spent, the
  remaining alerts are left unselected with a note, never guessed.
- **Go/no-go gate.** `vexproof check-model` scores the model on gold labels written before any
  model was run. GO requires 75% accuracy and zero invented names.

## Consequences
The model can lower recall (a missed pick leaves the alert at L1) but cannot create false
evidence. All tests run offline against a scripted transport; the HTTP layer is tested through
the SDK with a mock transport. A full scan of a real Django project costs roughly 40k input
tokens.
