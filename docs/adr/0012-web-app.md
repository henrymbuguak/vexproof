# ADR 0012: The web app: server-rendered, accessible, local by default

**Status:** accepted · **Date:** 2026-10-29 · Amends ADR 0003

## Context
Judges and teams need to see a result without reading terminal output, and to start a scan
without installing Python tools. The pages show untrusted text (advisories, model output) and
a scan clones code and may spend model tokens, so the app must be safe to leave running.

## Decision
- **Server-rendered pages (FastAPI and Jinja2, autoescaped) that work without JavaScript.**
  One small script of our own only enhances: it follows a running scan and announces each stage
  through a live region. ADR 0003 planned htmx; a small script of our own does the one job, with no
  third-party code in the page.
- **The call path is the visual centre.** Each step shows the code that proves it; solid lines
  are steps the code shows, dashed ones were judged by the model, and the text says so too, so
  meaning never rests on colour or line style alone.
- **Accessibility is tested, not assumed.** Semantic landmarks and headings, a skip link,
  labelled fields with hints and errors tied by `aria-describedby`, an error summary that takes
  focus, visible focus everywhere, WCAG AA contrast in light and dark themes, reduced motion
  and forced colours respected, pages that reflow to 320 px. axe-core reports no violations
  (WCAG 2.2 AA plus best practice) on every page, in both themes, at desktop and phone widths.
- **Typeface:** Atkinson Hyperlegible Next and Mono (Braille Institute, OFL), made for low
  vision readers and served from the app itself.
- **Safe by default:** a Content-Security-Policy allowing only this app's own scripts, styles
  and fonts (no inline code, no external requests), `X-Frame-Options: DENY`, forms refused when
  posted from another site (Fetch metadata, then Origin), a form size limit, one scan at a
  time with at most three waiting, and `vexproof serve` listening on 127.0.0.1 unless told
  otherwise. The CLI and the app run scans through the same `service.run_scan`.
- **One Docker image:** Ubuntu 24.04 with uv and Syft at pinned versions checked against their
  published SHA-256, Python from uv, dependencies from `uv.lock`, a non-root user, a `/data`
  volume for caches, and a health check. Compose binds the port to 127.0.0.1.

## Consequences
- Scans and their results live in memory and under the cache directory; links work until the
  server restarts. Enough for one person or a demo; a shared deployment would need storage and
  authentication.
- A model server at `localhost` (Ollama) is reached from the container through
  `VEXPROOF_LOCALHOST_ALIAS=host.docker.internal`, so one `.env` works natively and in Docker.
