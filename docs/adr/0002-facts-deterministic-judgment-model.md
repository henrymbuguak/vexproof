# ADR 0002: Facts are deterministic; judgment is the model's

**Status:** accepted · **Date:** 2026-10-27

## Context
A security tool loses all credibility if a model invents a CVE, a version or a line number.

## Decision
Advisory data, scores, versions, import maps, diffs and line numbers come from code and public data
sources. Muse Spark only chooses among verified candidates, traces paths using read-only tools, and
writes explanations. Every model output passes a deterministic verifier before it is stored; a
failed check produces *needs review*, never *not affected*.

## Consequences
Some alerts stay in *needs review*. That abstention rate is reported as a metric instead of hidden.
