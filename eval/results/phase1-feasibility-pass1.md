# Phase 1 feasibility, pass 1 (19 November 2026)

The two-day check the plan opens Phase 1 with: before any labelling, confirm that candidate
projects can be scanned, and count the independent groups of clears they would give (ADR 0019).
Every scan ran with `--no-model`, so no model was called, from `develop` at `c62a5b4`.

## Method

Twenty candidate applications, chosen for being real, permissively licensed Python web apps of
middle size: 12 Django, 5 Flask, 3 FastAPI. For each, the last commit before 1 June 2021 on the
default branch (old enough for vulnerable pins, recent enough to install). Repositories were cloned
as data only: no checkout, no hooks, no submodules, no local-file protocol. Then
`vexproof scan <url> --commit <sha> --no-model --json`.

Groups follow ADR 0019: clears that share a deciding module within one package version are one
group. Without a model, every changed module decides a clear, as ADR 0020 requires anyway. "Adds"
counts the groups a project contributes beyond the tuning set (the shop and justdjango, 20 groups).

## Results

| Project | Framework | Commit | Licence | Django | Packages | Alerts | With a fix commit | Clears | Adds groups | Blockers |
| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |
| nsidnev/fastapi-realworld-example-app | FastAPI | `9f1be60d9e96` | MIT | | 105 | 106 | 44 | 45 (package-level) | 3 | 1 |
| DjangoGirls/djangogirls | Django | `a20a44996a2b` | BSD | 2.0.12 | 39 | 114 | 72 | 2 | 2 | 1 |
| saleor/saleor | Django | `bd154e57bf17` | BSD | 3.2.2 | 218 | 289 | 219 | 0 | 0 | 3 |
| netbox-community/netbox | Django | `8d0a3c8e6932` | Apache-2.0 | 3.2.3 | 24 | 110 | 86 | 0 | 0 | 2 |
| babybuddy/babybuddy | Django | `d9485f0208b5` | BSD | 3.2 | 39 | 126 | 102 | 0 | 0 | 1 |
| djangopackages/djangopackages | Django | `93650acee095` | MIT | 2.2.22 | 36 | 48 | 46 | 0 | 0 | 2 |
| healthchecks/healthchecks | Django | `a0cd2c63e97d` | BSD | 3.2.2 | 9 | 40 | 39 | 0 | 0 | 1 |
| flaskbb/flaskbb | Flask | `354bebcf3607` | BSD | | 59 | 128 | 84 | 0 | 0 | 2 |
| getredash/redash | Flask | `041b184d37ca` | BSD | | 95 | 86 | 58 | 0 | 0 | 3 |
| CTFd/CTFd | Flask | `11954542586c` | Apache-2.0 | | 59 | 51 | 42 | 0 | 0 | 2 |
| Netflix/dispatch | FastAPI | `515cd130ce1a` | Apache-2.0 | | 133 | 184 | 130 | 0 | 0 | 2 |
| readthedocs/readthedocs.org | Django | `177dcb13ce13` | MIT | | 0 | | | | | |
| mozilla/kitsune | Django | `788bba1c983f` | BSD | | 0 | | | | | |
| allegro/ralph | Django | `eb316c349098` | Apache-2.0 | | 0 | | | | | |
| wagtail/bakerydemo | Django | `7803f451d2a4` | unclear | | 0 | | | | | |
| fastapi/full-stack-fastapi-template | FastAPI | `490c554e2334` | MIT | | 0 | | | | | |
| miguelgrinberg/flasky | Flask | `4459abeb9598` | MIT | | 0 | | | | | |
| miguelgrinberg/microblog | Flask | `23b3fc85d407` | MIT | | 0 | | | | | |
| django/djangoproject.com | Django | `692636486a6d` | BSD | | | | | | | scan failed: a package download was cut off |
| python/pythondotorg | Django | | | | | | | | | clone timed out |

All together with the tuning set: **25 groups**.

## Findings

**1. Blockers stop almost every clear.** Each of the 11 scanned projects has at least one blocker:
a computed import in reached code that no framework rule covers. Under ADR 0008 a single blocker
refuses every module-level clear in the project. They come from ordinary dependencies:

| Source of the computed import | Projects |
| --- | --- |
| `boto3.utils` | djangogirls, CTFd |
| `django_extensions.collision_resolvers` | djangogirls, djangopackages |
| `_pytest` (pytest) | saleor, fastapi-realworld |
| `compressor` (django-compressor) | healthchecks |
| `cacheops.conf` | netbox |
| `_plotly_utils` | babybuddy |
| `billiard`, `celery.app.registry` | flaskbb |
| `IPython.core` | dispatch |
| `flask.cli`, `flask.config` | redash |
| `cffi.verifier` | CTFd |

Seven projects also import by computed name in their own code (plugin loaders, settings-driven
imports, migrations), which blocks clears too.

**2. The ceiling is real.** 88 alerts are "never loaded by your code, but not cleared because" of
a blocker, across 92 deciding (package, version, module) keys: saleor 25, netbox 13, djangogirls
11, babybuddy 10, flaskbb 10, djangopackages 5, healthchecks 4, redash 4, dispatch 3,
fastapi-realworld 2, CTFd 1. None of them was held back by a change to compiled code.

**3. Seven of twenty projects lost every dependency at ingest.** Syft found no packages, mostly
because the pins live in nested files (`requirements/base.txt`, `-r` includes) or in a
`requirements/` folder at the chosen commit. These are a tooling gap, not unsuitable projects.

**4. pytest and IPython are reached from production code** in three projects. That points to the
closure over-approximating through some dependency, and needs a look before any rule changes.

## Consequence

With today's rules the benchmark cannot produce a meaningful false-clear bound: about 25 groups,
an upper bound near 12%. Choosing different projects does not change that; the rules decide it.

## Next: Phase 1a, before labelling

1. Scope blockers to what they could load (ADR 0022): a computed name with a literal prefix can
   load only modules under that prefix, so it blocks clears in that package alone; an unbounded
   name keeps blocking everything. It loosens the rule that guards against false clears, so it
   ships only with run-time evidence: every module loaded at run time is in the closure, on
   several projects, through the planned import sweep.
2. Find why pytest and IPython are reached from production code.
3. Read nested requirements files, so the seven projects that lost their dependencies can be
   scanned.
4. Repeat this pass, at no model cost, and set the false-clear target from the groups available.
