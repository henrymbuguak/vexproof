# ADR 0001: Never execute target code

**Status:** accepted · **Date:** 2026-10-27

## Context
vexproof analyses untrusted repositories and third-party packages. Installing or importing them
would run arbitrary code (setup scripts, import-time side effects) on the analyst's machine.

## Decision
vexproof reads source as data only. Repositories are cloned without submodules, hooks or the local
file protocol. Package source comes from wheels unzipped with path checks; sdists are never built.
Tests of target projects are never run. Subprocesses (git, syft) receive argument lists with timeouts.

## Consequences
Analysis is static, so dynamic behaviour (plugins, `getattr`, runtime imports) cannot be observed.
Those cases are reported as *needs review* rather than guessed.
