# ADR 0021: `main` is frozen for good at `v0.1.0`; `develop` is the trunk

**Status:** accepted · **Date:** 2026-11-18

## Context
The demo video, the hlab.tech case study and the hackathon listing all point at this repository
and describe the version built during the Meta Global AI Developer Hackathon. The upgrade to
Claude changes most of the model layer. Readers of those pages must keep finding the version they
describe, and the upgrade still needs a normal place to land.

## Decision
- `main` stays frozen at `0f8c70a`, tagged `v0.1.0`. A ruleset blocks updates, deletion and force
  pushes on it, with no bypass. Nothing is merged into it, ever.
- `develop`, cut from `v0.1.0`, is the default branch and the trunk. Every change reaches it as
  one squash commit through a pull request that passes `check` on an up-to-date branch, with
  linear history. Task branches are short and named by phase (`p0/...`).
- Release tags (`v0.2.0` onward) go on `develop`. A tag ruleset on `v*` blocks moving or deleting
  them.
- Dependabot reads its settings from the default branch, so its pull requests now target
  `develop`.
- `develop`'s README opens with a link to `v0.1.0` and the command to clone exactly that version.

## Consequences
- A plain clone and the repository's front page now show `develop`. Readers who want the
  hackathon version follow the banner or clone `--branch v0.1.0`.
- `v0.1.0` keeps the dependencies it shipped with, including CVE-2026-126360 in
  `opentelemetry-api` (fixed on `develop` in #14). The web app listens on 127.0.0.1 by default.
- The CI badge in `main`'s README shows the default branch's status, so `develop` must stay green.
