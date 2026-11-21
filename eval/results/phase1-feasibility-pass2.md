# Phase 1 feasibility, pass 2 (21 November 2026)

The repeat that Phase 1a ends with: the same twenty candidate projects as pass 1
(`phase1-feasibility-pass1.md`), the same commits, the same method, after the Phase 1a work
(#25 to #29). Every scan ran with `--no-model`, so no model was called, from `develop` at
`1ee2928` plus the symlink fix in this change, which affects only readthedocs (the only project
with symbolic links among the files vexproof reads).

## Method

As in pass 1: `vexproof scan <url> --commit <sha> --no-model --json` on each project, and the
shop and justdjango, the tuning set, scanned the same way. Groups follow ADR 0019: clears that
share a deciding module within one package version are one group, joined transitively. Without a
model every changed module decides a clear, as ADR 0020 requires anyway. "Adds" counts the
groups a project contributes beyond the tuning set. "Held back" counts alerts that are never
loaded by the project's code but are not cleared because of a blocker.

python/pythondotorg is still left out: it had no chosen commit after its clone timed out.

## Results

| Project | Django | Packages | Alerts | With a fix commit | Clears | Adds groups | Blockers | Held back |
| --- | --- | --- | --- | --- | --- | --- | --- | --- |
| shop (tuning) | 2.0 | 5 | 96 | 91 | 14 | (9) | 0 | 0 |
| justdjango (tuning) | 2.2.14 | 22 | 140 | 131 | 17 | (11) | 0 | 0 |
| babybuddy/babybuddy | 3.2 | 39 | 126 | 121 | 9 | 6 | 0 | 0 |
| healthchecks/healthchecks | 3.2.2 | 9 | 40 | 39 | 4 | 2 | 0 | 0 |
| nsidnev/fastapi-realworld-example-app | | 105 | 106 | 87 | 45 (package-level) | 3 | 1 | 2 |
| DjangoGirls/djangogirls | 2.0.12 | 39 | 114 | 109 | 2 (package-level) | 2 | 1 | 9 |
| saleor/saleor | 3.2.2 | 218 | 289 | 253 | 0 | 0 | 3 | 32 |
| **mozilla/kitsune** | 2.2.23 | **215** | 242 | 219 | 0 | 0 | 2 | 28 |
| **readthedocs/readthedocs.org** | 2.2.23 | **87** | 248 | 221 | 0 | 0 | 2 | 25 |
| **django/djangoproject.com** | 2.2.23 | **28** | 101 | 98 | 0 | 0 | 1 | 12 |
| netbox-community/netbox | 3.2.3 | 24 | 110 | 105 | 0 | 0 | 2 | 12 |
| **allegro/ralph** | 1.8.19 | **73** | 124 | 117 | 0 | 0 | 2 | 9 |
| flaskbb/flaskbb | | 59 | 128 | 118 | 0 | 0 | 2 | 9 |
| djangopackages/djangopackages | 2.2.22 | 36 | 48 | 47 | 0 | 0 | 2 | 7 |
| Netflix/dispatch | | 133 | 184 | 148 | 0 | 0 | 2 | 3 |
| getredash/redash | | 95 | 86 | 73 | 0 | 0 | 3 | 2 |
| CTFd/CTFd | | 59 | 51 | 46 | 0 | 0 | 2 | 1 |
| **wagtail/bakerydemo** | | **8** | 0 | | | | | |
| fastapi/full-stack-fastapi-template | | 0 | | | | | | |
| miguelgrinberg/flasky | | 0 | | | | | | |
| miguelgrinberg/microblog | | 0 | | | | | | |

In bold: projects that had no packages, or no scan, in pass 1.

All together: **33 groups** (20 in the tuning set, 13 added), from 25 in pass 1. Counting each
distinct set of changed modules as its own group, without joining sets that share a module,
gives 40; that looser count is not the ADR 0019 grouping.

## Findings

**1. The nested requirements reader recovered four projects, but none clears.** kitsune (215
packages), readthedocs (87), ralph (73) and djangoproject.com, whose scan now completes, add 715
alerts and 74 held back, but every one has a blocker. bakerydemo pins only 8 packages, none with
an advisory, and leaves Django and Wagtail as ranges. flasky, microblog and the FastAPI template
have no requirements files at their commits, so no reader recovers them.

**2. Most projects are also blocked by their own code.** Ten of the sixteen candidates with packages
import modules by a computed name in their own code: plugin loaders (CTFd, saleor, redash),
settings-driven imports (netbox, readthedocs, kitsune), data migrations (saleor) and management
commands (djangopackages, kitsune, ralph). No reviewed library rule can lift these. Every one of
the ten also has a library blocker, so neither kind alone frees a project.

**3. The library blockers that remain:**

| Source of the computed import | Projects |
| --- | --- |
| `_pytest` (pytest) | saleor, readthedocs, redash, fastapi-realworld |
| `django_extensions` | djangogirls, djangopackages, ralph |
| `IPython.core` | dispatch, kitsune |
| `alembic.templates`, `babel.messages` | flaskbb, CTFd, ralph |
| `cacheops.conf` | netbox |
| `django_hosts`, `django_push`, `djmoney` | djangoproject.com |
| `cffi.verifier`, `docutils.languages` | CTFd |
| `billiard` | flaskbb |
| Source unavailable (`redash-dummy`, `codecov`) | redash, saleor |

pytest is reached in four projects. Phase 1a traced pass 1's case to a one-word string rule.
Here, at least for readthedocs, nested requirements now put pytest in the inventory through
`requirements/testing.txt`. Why it is reached from production code still needs checking per
project.

A django-extensions rule would unblock no project: djangogirls stays blocked on principle
(oauth2client), and djangopackages and ralph have project-code blockers. The same holds for
gunicorn and netbox.

**4. Two scans failed on the first run.** kitsune and readthedocs timed out downloading from
files.pythonhosted.org during a network outage, and readthedocs then stopped on a broken symbolic
link: `.isort.cfg` points into `common/`, a submodule that is never cloned. vexproof now skips a
link that points at nothing or out of the repository, for both Python and configuration files,
since a cloned repository is data. Both scans passed when re-run.

## Consequence for the false-clear target

With no false clears observed, the per-group 95% upper bound is `1 - 0.05^(1/n)`:

| Groups | Upper bound |
| --- | --- |
| 25 (pass 1) | 11.3% |
| 33 (this pass) | 8.7% |
| 150 (the design's goal) | 2.0% |

The design's success line, a per-group bound below 2%, needs about 150 groups. This set gives
33, and its remaining blockers are mostly in project code, where library rules cannot reach.
Choosing the target is a decision the plan leaves open; it is not set here.

**Added 21 November, when the target was set:** 28 of the 33 groups come from the shop,
justdjango, healthchecks and babybuddy, whose rules were written against their code and import
sweeps, so they are tuning groups under ADR 0019 (10.1%). Only 5, from djangogirls and
fastapi-realworld, come from projects nobody tuned on (45.1%). The 8.7% above covers every
project and is not a held-out figure. The target is in `docs/design.md`, Phase 1a.
