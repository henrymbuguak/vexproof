# ADR 0006: Level 0 clears only what nothing can load

**Status:** accepted · **Date:** 2026-10-28

## Context
Level 0 marks an alert *not affected* without looking at any vulnerable function, so a wrong
clear hides a real risk. Python can load code in ways a plain import scan misses.

## Decision
The import closure is computed over distributions and deliberately over-approximates: imports
inside functions and `try` blocks count, string references to modules (Django `INSTALLED_APPS`,
middleware paths) count, and each reached package's own imports pull in more packages. A package
is cleared only if it is outside the closure **and**:

- the project has no imports with computed names;
- its source was readable and yields at least one importable module name;
- it registers no plugin entry points (frameworks load those by name);
- no unreadable package could account for an unmatched import;
- nothing your code loads imports a name that looks like this package (`sqlalchemy`, `yaml`
  for PyYAML) while no package provides it.

Packages imported only by test code are cleared with a separate check, `imported_only_by_tests`.

## Consequences
Fewer clears than an aggressive analysis, all of them defensible. On a real Django app every
package was correctly kept: Pillow is reached through Django's `ImageField`, olefile through
Pillow, django-crispy-forms only through an `INSTALLED_APPS` string.

A scan of we45/Vulnerable-Flask-App (2026-10-30) cleared SQLAlchemy although Flask-SQLAlchemy
imports it: SQLAlchemy 1.1's sdist keeps its code under `lib/`, so its modules were read as
`lib.sqlalchemy...` and `import sqlalchemy` matched nothing. Source trees now drop such layout
folders, and the look-alike rule above refuses a clear whenever an import goes unmatched in
this way, so a layout we have not seen yet cannot produce the same error.
