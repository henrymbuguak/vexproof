# vexproof

**Which dependency vulnerabilities actually reach your code, with proof.**
*The AI proposes. The verifier proves.*

Scanners flag every vulnerable *version* of a dependency. Most of those alerts are not exploitable
in a given codebase, because the vulnerable function is never called. vexproof uses Meta's Muse
Spark to read advisories and fix commits, traces call paths into your code, verifies every claim
deterministically, and exports the result as [OpenVEX](https://github.com/openvex/spec).

> Status: under construction for the Meta Global AI Developer Hackathon (Oct 26 – Nov 4, 2026).
> Chapter 1 (ingest + vulnerability intel) is complete; reachability analysis lands in later chapters.

## Quick start

```bash
uv sync --locked --all-groups
cp .env.example .env
uv run vexproof scan path/to/python/project            # needs syft installed, or:
uv run vexproof scan path/to/project --sbom sbom.json  # use an existing CycloneDX/SPDX SBOM
uv run vexproof scan https://github.com/<owner>/<repo> --commit <sha> --json findings.json
```

## Development

| Command | What it does |
| --- | --- |
| `make check` | Lint, format check, mypy strict, offline tests with coverage gate (what CI runs) |
| `make fmt` | Format and apply safe lint fixes |
| `make audit` | Audit vexproof's own locked dependencies |
| `make smoke` | Live tests against OSV, KEV and EPSS (needs network) |

## Built during the Meta Global AI Developer Hackathon

All code in this repository was written during the event (Oct 26 – Nov 4, 2026); the commit
history shows its progression.

- **Meta models:** Muse Spark via the Meta Model API (symbol selection, evidence engine, summary). *(from Chapter 3)*
- **Third-party libraries (dependencies, not our code):** pydantic, pydantic-settings, httpx,
  stamina, packaging, cvss, PyYAML, typer, rich, structlog, unidiff, openai; FastAPI, Jinja2,
  uvicorn (web). See `pyproject.toml` and `uv.lock` for exact versions.
- **External tools:** [Syft](https://github.com/anchore/syft) for SBOM generation.
- **Data sources:** [OSV.dev](https://osv.dev) (including GitHub Security Advisories and the PyPA
  advisory database), [CISA KEV](https://www.cisa.gov/known-exploited-vulnerabilities-catalog),
  [FIRST EPSS](https://www.first.org/epss/).

## Related work

Endor Labs, Snyk and Semgrep offer reachability analysis; [Vexcalibur](https://pypi.org/project/vexcalibur/)
generates VEX documents from SBOMs and OSV findings. vexproof's contribution is using a model to
identify vulnerable functions from human-written advisories and fix commits, then verifying every
claim before producing OpenVEX with call-path evidence.

## License

MIT, see [LICENSE](LICENSE).
