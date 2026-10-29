# vexproof

**Which dependency vulnerabilities actually reach your code, with proof.**
*The AI proposes. The verifier proves.*

Scanners flag every vulnerable *version* of a dependency. Most of those alerts are not exploitable
in a given codebase, because the vulnerable function is never called. vexproof uses Meta's Muse
Spark to read advisories and fix commits, traces call paths into your code, verifies every claim
deterministically, and exports the result as [OpenVEX](https://github.com/openvex/spec).

> Status: under construction for the Meta Global AI Developer Hackathon (Oct 26 – Nov 4, 2026).
> Done: ingest, vulnerability intel, deterministic analysis (import closure, fix-commit
> shortlists), Muse Spark symbol selection with a verifier, and the evidence engine (module-level
> clears, verified call paths). Next: prioritization, OpenVEX and reports.

## How an alert is analysed

| Level | Meaning | How it is decided |
| --- | --- | --- |
| L0 | Package not reachable from your code: **cleared** | Import closure of your code, including framework strings such as `INSTALLED_APPS`; conservative rules for plugins and dynamic imports |
| L1 | The functions the fix changed exist in your installed version | Fix commit fetched with git, diffed, mapped to functions, verified against the installed wheel |
| L2 | Only the changed module is known | Module-level changes, or changed functions absent from your version |
| L3 | Needs review | No fix commit, fix in native code (C, bundled libraries), or code absent from the package |

### Muse Spark picks the vulnerable function; the verifier checks it

One fix commit often touches several functions, and sometimes fixes several advisories at once
(Pillow's commit `756fff33` fixes ICO, ICNS and BLP issues together). For each L1 alert, Muse Spark
reads the advisory and each candidate function's diff and picks the function(s) this advisory is
about, quoting the advisory to justify the pick. Nothing it says is trusted until checked:

| Check | Fails when |
| --- | --- |
| `symbols_in_shortlist` | A picked name is not one of the candidates (an invented function) |
| `symbols_in_installed_code` | Already true for every candidate: Chapter 2 verified each one in your installed wheel |
| `quote_found_in_advisory` | The quote is not in the advisory text, or is too short to mean anything |

A rejected pick changes nothing and is recorded as a note. Every answer is recorded, keyed by
model, prompt version and inputs, so a re-run is free and reproducible (`VEXPROOF_MODEL_MODE`).

### Where each alert ends up

| Outcome | Evidence | Decided by |
| --- | --- | --- |
| **cleared** | the package is never imported by your code | import closure (L0) |
| **cleared** | the module holding the vulnerable function is never loaded | module closure: imports, dotted strings, and written-down framework rules (Django app loading, Pillow's plugin list); refused if anything loads code by a name it cannot see |
| **reachable** | a call path from your code to the vulnerable function, every hop certain | path search and verifier, no model |
| **reachable** | a call path whose uncertain hops Muse Spark judged plausible | path search proposes, Muse Spark reviews, the verifier re-checks every hop |
| **open** | neither | listed for review, never silently dropped |

A *certain* hop calls something whose identity the code shows: a function through its imports,
or a method on an object whose class is known (`self`, `super()`, `form = PasswordResetForm()`).
An *uncertain* hop calls a method on an object of unknown type, which Python resolves at run time;
those are what the model reviews. Types are carried along a path, so once your view builds a
`CartAddProductForm`, `self.clean()` further down cannot be `AuthenticationForm.clean`. No path
found never clears an alert: only the module closure does.

The shape of a reported path (abridged):

```
$ uv run vexproof show findings.json GHSA-95q3-8gr9-gm8w
call path from your code (uncertain hops reviewed by muse-spark-open:cloud / trace_path.v3)
     myshop.urls                                myshop/urls.py:7
   ? django.contrib.admin.options.ModelAdmin.urls  ...
     ...
     PIL.Image.open                              PIL/Image.py:2549 via call
     PIL.ImageFile.ImageFile.__init__            PIL/ImageFile.py:102 via pillow_open_registry
     ...
     PIL.IcoImagePlugin.IcoFile.frame            PIL/IcoImagePlugin.py:153 via call
```

### What to fix first

Evidence decides *whether* an alert matters; exploit signals and your service profile decide
*how soon*. `vexproof report` turns a findings file into a ranked list with reasons, the smallest
upgrade per package, an [OpenVEX](https://openvex.dev) document and a self-contained HTML report.

| Priority | Rule |
| --- | --- |
| **fix now** | reachable, and listed in CISA KEV, or EPSS ≥ 10%, or critical severity, or high severity in an internet-facing service whose criticality is not low |
| **fix soon** | reachable otherwise |
| **review** | open; known-exploited first, then by severity and EPSS |
| **not affected** | cleared with evidence |

The profile (`examples/service_profile.yaml`) only moves alerts between *fix now* and *fix soon*;
it never changes a verdict. In the OpenVEX output, cleared alerts are `not_affected` with
`vulnerable_code_not_in_execute_path` and the evidence as impact statement; reachable alerts are
`affected` with the upgrade as action statement and the verified call path in `status_notes`;
open alerts are `under_investigation` with the reason.

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
uv run vexproof report findings.json --profile examples/service_profile.yaml \
    --html report.html --openvex vex.json              # what to fix first; exports
```

`scan` takes `--html` and `--openvex` too. The HTML report is one file with no scripts and a
Content-Security-Policy that forbids them; every advisory and model text in it is escaped.

With a model configured, `scan` also picks vulnerable functions and reviews call paths
(`--no-model` turns the model off; `--no-trace` skips call paths only).
Before trusting a model, run the go/no-go check:

```bash
uv run vexproof check-model                    # key, model list, structured output
uv run vexproof check-model findings.json      # + the gold test in eval/gold/symbols.yaml
```

GO needs at least 75% of the gold cases right **and** no invented function names.

Any OpenAI-compatible endpoint works. Through [Ollama](https://ollama.com) you can use Meta's
open-weight **Muse Spark Open** (`muse-spark-open:cloud`) or a local Llama, with no Meta API key
(see the commented blocks in `.env.example`). The same verifier and gold test apply, and each
finding records which model chose its symbols.

## Evaluation: checked against the running project

Static claims are checked against an oracle: the demo project itself, run with its exact
pinned packages under a scripted workload (browse, cart, checkout, admin login, and product
image uploads in twelve formats). `eval/dynamic/observe.py` records every module that loaded
and every function that ran; `vexproof eval` compares the scan with it:

```bash
uv run vexproof eval findings.json --observed eval/observed/shop-1aa90f6.json \
    --gold eval/gold/symbols.yaml --markdown eval/results/shop.md
```

| Check | Fails the gate |
| --- | --- |
| A cleared alert's module loaded at run time | yes |
| A module loaded at run time is missing from the scan's closure | yes |
| A reachable alert's vulnerable function ran | no: confirms the path |
| An open alert's picked function ran | no: a lead the path search missed |
| Function picks against gold labels, and model cost per alert | no: reported |

The oracle runs target code, so it lives outside the scanner (ADR 0011) and runs in a
throwaway environment: `eval/dynamic/observe_shop.sh` rebuilds the observation from scratch.
Its first run found a real gap, now fixed: Django loads migration files such as
`0001_initial.py` by name, and the closure had skipped them.

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

- **Meta models:** Muse Spark via the Meta Model API (OpenAI-compatible SDK): symbol selection
  from Chapter 3, call-path review from Chapter 4. Prompts are versioned files in
  `src/vexproof/prompts/`.
- **Third-party libraries (dependencies, not our code):** pydantic, pydantic-settings, httpx,
  stamina, packaging, cvss, PyYAML, typer, rich, structlog, unidiff, openai; FastAPI, Jinja2,
  uvicorn (web). See `pyproject.toml` and `uv.lock` for exact versions.
- **External tools:** [Syft](https://github.com/anchore/syft) for SBOM generation;
  optionally [Ollama](https://ollama.com) to serve Meta's open-weight models (Muse Spark Open,
  Llama). For evaluation only: uv-managed CPython 3.8 to run the demo project, and the demo
  project's own pinned packages.
- **Standards:** [OpenVEX v0.2.0](https://github.com/openvex/spec) for the VEX export and
  [package URLs](https://github.com/package-url/purl-spec) to name products.
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
