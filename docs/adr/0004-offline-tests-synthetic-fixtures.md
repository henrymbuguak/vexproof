# ADR 0004: Offline tests with synthetic fixtures

**Status:** accepted · **Date:** 2026-10-27

## Context
CI must be fast, free and reproducible for anyone who clones the repository, without API keys.

## Decision
Every external call goes through an injectable client. Tests use `respx` with synthetic fixtures in
the real OSV, CycloneDX and SPDX shapes. Live behaviour is checked by `network`-marked smoke tests,
skipped by default. Model calls will be recorded and replayed (Chapter 3).

## Consequences
Fixtures can drift from real API shapes; the smoke tests exist to catch that.
