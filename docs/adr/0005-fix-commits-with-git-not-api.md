# ADR 0005: Fetch fix commits with git, not the GitHub REST API

**Status:** accepted · **Date:** 2026-10-28

## Context
Shortlisting vulnerable functions needs each fix commit's diff and the pre-fix file contents.
The GitHub REST API offers both, but needs a token for usable rate limits (60 requests/hour
without one), truncates large patches, and caps files per commit.

## Decision
Use git directly. One bare, partial clone per upstream repository; commits fetched by SHA with
`--depth=2 --filter=blob:none`; all of an alert's commits for one repository in one fetch.
Diffs come from `git diff -U0`, pre-fix files from `git show <parent>:<path>`.

vexproof never asks git about an object it has not fetched: in a partial clone git answers such a
question by downloading the object with its entire history (observed: 557 MB for Django instead of
22 MB). A manifest of fetched commits and parents is the source of truth.

## Consequences
No token, no rate limit, exact diffs, and one fewer setup step for anyone running the project.
Only GitHub-hosted fixes are supported for now; others are reported as needs review.
