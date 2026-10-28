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
- no unreadable package could account for an unmatched import.

Packages imported only by test code are cleared with a separate check, `imported_only_by_tests`.

## Consequences
Fewer clears than an aggressive analysis, all of them defensible. On a real Django app every
package was correctly kept: Pillow is reached through Django's `ImageField`, olefile through
Pillow, django-crispy-forms only through an `INSTALLED_APPS` string.
