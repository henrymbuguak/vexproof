# vexproof

**Which dependency vulnerabilities actually reach your code, with proof.**
*The AI proposes. The verifier proves.*

Scanners flag every vulnerable *version* of a dependency. Most of those alerts are not exploitable
in a given codebase, because the vulnerable function is never called. vexproof uses Meta's Muse
Spark to read advisories and fix commits, traces call paths into your code, verifies every claim
deterministically, and exports the result as [OpenVEX](https://github.com/openvex/spec).

> Status: under construction for the Meta Global AI Developer Hackathon (Oct 26 – Nov 4, 2026).
> Done: ingest, vulnerability intel, and deterministic analysis (import closure, fix-commit
> shortlists). Next: Muse Spark symbol selection and the evidence engine.

## How an alert is analysed

| Level | Meaning | How it is decided |
| --- | --- | --- |
| L0 | Package not reachable from your code: **cleared** | Import closure of your code, including framework strings such as `INSTALLED_APPS`; conservative rules for plugins and dynamic imports |
| L1 | The functions the fix changed exist in your installed version | Fix commit fetched with git, diffed, mapped to functions, verified against the installed wheel |
| L2 | Only the changed module is known | Module-level changes, or changed functions absent from your version |
| L3 | Needs review | No fix commit, fix in native code (C, bundled libraries), or code absent from the package |

Nothing is installed or executed: package code comes from wheels read as data, and fix commits are
fetched with `git fetch --depth=2 --filter=blob:none` (no token or API needed).

## Quick start

```bash
uv sync --locked --all-groups
cp .env.example .env
uv run vexproof scan path/to/python/project            # needs syft installed, or:
uv run vexproof scan path/to/project --sbom sbom.json  # use an existing CycloneDX/SPDX SBOM
uv run vexproof scan https://github.com/<owner>/<repo> --commit <sha> --json findings.json
uv run vexproof show findings.json CVE-2019-19844       # explain one alert
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
  [FIRST EPSS](https://www.first.org/epss/), [PyPI](https://pypi.org) (package files, verified by
  SHA-256), and fix commits fetched from the upstream projects' public GitHub repositories.

## Related work

Endor Labs, Snyk and Semgrep offer reachability analysis; [Vexcalibur](https://pypi.org/project/vexcalibur/)
generates VEX documents from SBOMs and OSV findings. vexproof's contribution is using a model to
identify vulnerable functions from human-written advisories and fix commits, then verifying every
claim before producing OpenVEX with call-path evidence.

## License

MIT, see [LICENSE](LICENSE).
