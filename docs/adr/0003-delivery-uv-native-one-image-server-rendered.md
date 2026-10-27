# ADR 0003: uv for development, one Docker image for delivery, server-rendered UI

**Status:** accepted · **Date:** 2026-10-27

## Context
Solo build, nine days, and judges who must be able to run the project.

## Decision
Develop natively with uv (fast feedback, debugger and type checker work directly). Ship one Docker
image with pinned Python, Syft and locked dependencies. Build the dashboard with FastAPI, Jinja
templates and htmx rather than a separate JavaScript application.

## Consequences
One language, one process, one lockfile to audit. The UI is deliberately simple: three views
(funnel, finding list, evidence panel).
