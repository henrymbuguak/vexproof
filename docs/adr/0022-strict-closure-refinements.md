# ADR 0022: Strict-closure refinements; assumed clears tested and rejected

**Status:** accepted · **Date:** 2026-11-19 · Amends ADR 0008 · Evidence:
`eval/results/phase1-feasibility-pass1.md` and the import sweeps below

## Context

ADR 0008 refuses every module-level clear in a project when reached code imports a module by a
computed name that no framework rule covers. On the two demo apps that rule cleared 30 alerts; on
11 real applications it cleared 2 at module level, because each one reaches such an import in
ordinary dependencies (django-compressor, django-extensions, boto3, Celery, plotly and others), and
88 alerts were "never loaded by your code, but not cleared" only because of one.

Two ideas were weighed: review libraries one by one (84 distinct libraries across the 11 apps,
16 to 27 for the larger ones), or a second, *assumed* kind of clear resting on one assumption:
that a library which passes a module name to an import function receives a name written somewhere
in code, which the closure already holds. This ADR was first written to propose the second, with
its evidence fixed in advance; the evidence rejected it, and what it found made the strict closure
more correct.

## Decision

### 1. The strict closure is refined

Each change only widens the closure, except the first, which rests on no assumption and passed
every sweep.

- **A bare one-word string in library code names no module** (`"py"`, a Pygments language name,
  had pulled pytest into the closure). Project code keeps every string, since `INSTALLED_APPS`
  lists one-word apps. A library that imports such a word by name passes it to an import
  function, which is recorded separately.
- **Repository configuration files** (`.yaml`, `.yml`, `.toml`, `.ini`, `.cfg`, `.json`, `.env`
  files, outside test and skipped folders) are scanned for dotted names, which join the closure.
- **Relative and `fromlist` dynamic imports are read fully**: `import_module(".sub", package)`
  reaches `package.sub` (it was skipped) and `__import__("pkg", fromlist=[...])` reaches each
  submodule (they were ignored).
- **A library that finds modules by listing them** (`pkgutil.iter_modules` or `walk_packages`,
  `os.listdir`, `os.walk`, `scandir`, `glob`, `Path.iterdir`, entry points) has every one of its
  modules reached once any is, because it can load any of its own. Reviewed distributions
  (Django, Pillow) keep their framework rules instead.
- **Compiled code that imports Python modules** is covered by reviewed rules read from the C
  sources: psycopg2's extension imports `psycopg2.errors`, `extensions`, `extras`, `sql` and `tz`.
- **Package source is never taken from a wheel built only for Python 2**: PyYAML 5.4.1's smallest
  wheel held its Python 2 code, whose implicit relative imports named no `yaml.*` module.

### 2. Computed imports are recorded with what their names are made of

Each one is kept as *plain* (a name passed in), *pattern* (literal text around a variable part,
with `__name__` and `__package__` read as the module's own name) or *opaque*, together with whether
its module lists packages or directories. These facts block clears exactly as before; they are
what a reviewer reads before writing a framework rule that covers a library (ADR 0008).

### 3. Assumed clears are rejected

The design, fixed before it was measured: a clear blocked only by library imports that pass a
name in, or build one around literal text, would stay open as `clear_assumed`, list the imports it
rested on, and become `not_affected` only through a person's approval. It was built, tested, and
measured against import sweeps, then withdrawn:

- **The assumption failed on a real library.** The babybuddy sweep found 45 loaded modules
  missing from the closure. Faker lists its providers' folders and imports each name, so the names
  come from the file system, not from code. Babybuddy's 10 assumed clears were not contradicted,
  but only because none was in Faker.
- **Made sound, it cleared nothing.** Once libraries that list modules were excluded, every one of
  the 11 projects still had a library that lists modules or builds names with nothing to match:
  0 assumed clears, with 90 alerts still held back.

A feature that is unsound where it applies and idle once made sound is not kept.

## Evidence

Import sweeps (`eval/dynamic/sweep_in_docker.sh`: pins installed in a container, every
production module imported with the network off) and recorded runs, against the refined closure:

| Project | Evidence | Loaded modules missing from the closure | Strict clears |
| --- | --- | --- | --- |
| shop | recorded run | 0 of 470 | 14, none contradicted |
| justdjango | recorded run | 0 of 776 | 17, none contradicted |
| babybuddy | import sweep | 0 of 926 (45 before the fixes) | 0 |
| healthchecks | import sweep | 0 of 594 | 0 |

## Consequences

- Strict clears are what they were, on a closure that is now sound on four projects with
  run-time evidence; published numbers are unchanged.
- Clears on real applications come back through reviewed rules for the libraries that block them
  (ADR 0008), each checked by an import sweep, starting with the projects that have the fewest:
  healthchecks (django-compressor), babybuddy (plotly, Faker), djangogirls (django-extensions),
  netbox (gunicorn, two sites in its own code).
- The benchmark's false-clear bound will rest on fewer groups than first planned; its weight moves
  toward reachable precision and the reasons alerts stay open.
- Every new benchmark project gets an import sweep before its results count.
