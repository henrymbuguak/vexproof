# ADR 0022: Strict clears and assumed clears, measured apart

**Status:** proposed · **Date:** 2026-11-19 · Amends ADR 0008 · Evidence:
`eval/results/phase1-feasibility-pass1.md`

## Context

ADR 0008 refuses every module-level clear in a project when any reached code imports a module by
a computed name that no framework rule covers. On the two demo apps that rule still cleared 30
alerts. On 11 real applications it cleared 2: every one of them reaches such an import, in 84
different libraries (`import_module(mod_name)` in django-compressor, `__import__(name)` in boto3,
`import_string(path)` in django-extensions), and 88 alerts were "never loaded by your code, but
not cleared" only because of one. Reviewing libraries one by one does not scale: the larger apps
need 16 to 27 each.

Most of those imports pass a name through a variable. The names they receive are, in the cases
read so far, dotted strings written in reached code (a library's defaults, the project's
settings), which the closure already contains. What code cannot show is a name that arrives from
outside it: an environment variable, a command-line argument, a database row.

vexproof's existing clears, and every number published for them, must keep their meaning.

## Decision

### 1. Two kinds of clear

- A **strict clear** is today's clear (ADRs 0006, 0008, 0020), changed only as section 3 says.
- An **assumed clear** meets every condition of a strict clear except one: the only blockers are
  *assumable* computed imports (2). It is decided on one stated assumption: **the project's
  configuration names no module beyond those written in its code and repository files, and
  every package installed at run time is in the scanned dependency list.**

### 2. Which computed imports are assumable

A computed import is assumable when all of these hold:

- it is in third-party code, not the project's own;
- its name argument is either a plain reference (a variable, attribute, subscript or call
  result), or a name built in the call with a literal part to match (concatenation, `%` or
  `.format()` formatting, an f-string). A built name with a literal part also adds every
  installed module matching it to the closure: `"%s.base" % x` adds every module ending `.base`,
  `"pkg.backends." + x` every module under `pkg.backends`;
- the package's source was read.

Pattern matching is sound only if the dependency list holds every installed package, which is
why it sits with the assumption for now rather than in strict clears.

Still blocking, for both kinds of clear:

- a computed import in the project's own code, until a reviewer records that site as reviewed
  for that project (a list kept with the project, each entry with its reason);
- a built name with no literal part to match (`"%s" % x`, `"".join(parts)`, `f"{a}{b}"`);
- **any** computed import of a distribution that finds modules by listing something: a package
  (`pkgutil.iter_modules`, `walk_packages`), a directory (`os.listdir`, `os.walk`, `scandir`,
  `glob`, `Path.iterdir`) or entry points. Its names come from the file system or package
  metadata, not from code, so the assumption does not hold for it. The whole distribution
  counts, since Faker lists folders in `faker.utils.loading` and imports the names in
  `faker.factory`;
- a package whose source could not be read;
- a fix that changes compiled code (ADR 0008), and none-match picks (ADR 0020), as today.

### 3. Changes to strict clears

- **Relative and `fromlist` dynamic imports are read fully.** `import_module(".sub", package)`
  now reaches `package.sub` (it was skipped), and `__import__("pkg", fromlist=[...])` reaches each
  listed submodule (they were ignored); computed entries count as a pattern under `pkg`. These
  only widen the closure, closing two gaps found while reading real blockers.
- **Compiled code that imports Python modules is covered by reviewed rules**, read from the C
  sources: psycopg2's extension imports `psycopg2.errors`, `extensions`, `extras`, `sql` and
  `tz`. A rule only widens the closure.
- **Repository configuration files** (`.yaml`, `.yml`, `.toml`, `.ini`, `.cfg`, `.json`, `.env`
  and `.env.*` files, outside test and vendored folders) are scanned for dotted strings, which
  join the closure like strings in code. This only widens the closure: it can remove a clear,
  never add one.
- **In library code, a bare one-word string is no longer a module reference** (`"py"`, a
  Pygments language name, had pulled pytest into the closure). Project code keeps every string,
  since `INSTALLED_APPS` lists one-word apps. This narrows the closure, so it can add strict
  clears. It rests on no assumption: a library that does import such a word by name passes it to
  an import function, which is a literal import or a computed one, tracked separately. It ships
  only after the import sweep of every benchmark project finds no loaded module missing from
  the closure; it has passed the shop, justdjango and healthchecks so far.

### 4. How an assumed clear is recorded and shown

- Its verdict stays `under_investigation` with the reason `clear_assumed`, and its evidence
  carries the check `module_not_loaded_assuming_configuration`. So no export, from this version
  on, can turn it into `not_affected`.
- Its evidence lists the computed imports it relied on (file and line, with their count), so a
  reader can check what was assumed, and its note states the assumption in words.
- Reports count strict and assumed clears apart, everywhere a clear is counted.
- It becomes `not_affected` only through the human approval flow (ADR 0017), and that statement's
  impact statement names the assumption.

### 5. Evidence it must earn

- Every benchmark project gets an import sweep (`eval/dynamic/sweep_in_docker.sh`): its pinned
  packages installed in a container, every production module imported with the network off.
  Any loaded module of a scanned package that is missing from the closure fails the project.
- The benchmark reports the assumed-clear false rate on its own: an assumed clear is contradicted
  when any module that decides it loaded at run time. Upper bounds are given per clear and per
  group (ADR 0019), with each project's sweep and workload coverage.
- These criteria are fixed now, before the benchmark runs. A contradicted assumed clear is
  published with its root cause. Whether assumed clears ever count as strict is decided by a
  later ADR, from published results, not by this one.

## Limits

- An import sweep loads what start-up and module imports load. A computed import reached only
  during a request is seen only where a workload drives that request, so the measured rate is a
  lower bound, as for strict clears (ADR 0011).
- Names supplied only at deployment (environment, command line, database) are outside the
  assumption by definition; the impact statement says so.
- Compiled code can import Python modules that no source scan sees. Each case needs a reviewed
  rule (section 3); the import sweep of every benchmark project is what finds the ones left.

## Evidence so far

- The babybuddy sweep (19 November 2026) found the closure unsound: 45 loaded modules missing,
  from Faker's providers (found by listing folders), what they import (PyYAML,
  `text_unidecode`), and `psycopg2.errors` (imported by compiled code). Its 10 assumed clears
  were not contradicted, but only because none was in Faker. The discovery rule and the
  psycopg2 rule above are the response, and both closures must pass that sweep again.
- healthchecks: sound, and 0 of 4 assumed clears contradicted.

## Consequences

- No claim made today becomes weaker. A strict clear means what it meant; its one loosening, the
  one-word string rule, rests on no assumption and must pass every benchmark sweep first.
- Real applications get decided alerts again, labelled with what they rest on, without waiting
  for a review of every library.
- Each benchmark project costs an import sweep and a review of its own computed imports.
- More code paths to test: the classifier of computed imports, pattern widening, the
  configuration scan, and the new evidence and reporting fields.
