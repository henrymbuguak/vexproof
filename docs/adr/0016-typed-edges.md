# ADR 0016: Typed edges: one check per edge kind, added as code

**Status:** proposed · **Date:** 2026-11-18 · See `docs/design.md`, "Typed edges (use 3)"

## Context
Frameworks connect code by declaration rather than by call: signal receivers, plugin registries,
URL routes, settings, template filters. The call index cannot see these, so targets reached only
this way have no candidate path and get no model call today.

## Decision
- The trace loop can propose a typed edge: a kind, a file, a name and a target. The model
  supplies names and patterns; the verifier parses the file and finds the node and its line.
- Each kind has its own check, written as code with tests, never added by prompt. A kind without
  a check is not accepted.
- Every edge is anchored in reached code. Its "from" side must be reached, and for signals and
  registries the module holding the registration must also be loaded. An edge whose anchor is not
  reached is rejected, never treated as a new entry point.
- Signals and registries are built first. Template filters wait for a Django template parser.

## Consequences
Evidence records and the VEX export carry the edge kind. New frameworks need new checks before
the model can use their edges.
