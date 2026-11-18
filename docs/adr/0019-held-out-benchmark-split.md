# ADR 0019: The benchmark has a held-out split that prompts never see

**Status:** proposed · **Date:** 2026-11-18 · Extends ADR 0011 · See `docs/design.md`,
"Evaluation plan"

## Context
Today's evidence rests on two projects chosen by the author and 14 hand labels. A public
benchmark replaces them, and its numbers are only worth something if prompts and rules were not
tuned on the cases they are scored on. A leaked split cannot be repaired after the fact.

## Decision
- 30% of advisories and 3 whole projects are held out. Prompts, tool descriptions and framework
  rules are tuned only on the rest.
- The held-out evaluation runs once for a release and is published unchanged, including failures.
- Clears are checked only against production-shaped runs: the scripted workload and an import
  sweep of production modules. Test-suite runs confirm reachable paths and picks, and are never
  compared with clears.
- The false-clear rate is reported with two 95% bounds, per clear and per group of clears sharing
  a deciding module within one package version. The grouping is code in `vexproof eval`, and the
  per-group bound is the headline.
- Labels, project pins and workloads live in a separate, neutrally named repository with its own
  licence and changelog. `vexproof bench` takes the dataset path as an argument.

## Consequences
Held-out results may look worse than today's small-sample numbers. Reaching a per-group bound
under 2% needs about 150 groups, which means more projects and more package versions, not more
alerts from the same ones.
