# ADR 0018: Model tier is chosen per purpose in config, with measured escalation

**Status:** proposed · **Date:** 2026-11-18 · See `docs/design.md`, "Model provider layer"

## Context
Claude comes in tiers with very different prices: the shop scan is estimated at about $4.03 on
Opus 5.5 and about $0.10 on Haiku 5.5. Cost reports and benchmarks are keyed by purpose and
model, so the way a model is chosen has to be fixed before they exist.

## Decision
- Each purpose (`symbol_pick`, `trace_path`) names its model and effort in settings. It starts on
  the smallest tier that passes `vexproof check-model` for that purpose.
- Thinking is controlled through effort, set explicitly per purpose; it is not switched on or off.
  Output limits are sized for thinking.
- Escalation is per target, on a stated trigger, and reruns that target's loop from the start on
  the larger model, because neither thinking blocks nor the prompt cache carry across models.
- Prices live in a per-model table that covers cache reads and writes. Cost per alert is computed
  from recorded token counts, not estimated.

## Consequences
The benchmark, not habit, decides whether escalation and higher effort pay for themselves. Each
new purpose ships with gold labels and a `check-model` threshold before it is enabled by default.
