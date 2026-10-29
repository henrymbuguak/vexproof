# ADR 0008: Clear at module level, with framework rules written down

**Status:** accepted · **Date:** 2026-10-29

## Context
After Level 0 (ADR 0006), every alert in a used package stays open. On a real Django shop all
five packages were in use, so nothing was cleared. Yet much vulnerable code sits in modules the
project never loads: Django's `contrib.gis`, `contrib.postgres` and `admindocs`; Pillow's
`ImageMath`, `ImageCms`, font loaders and `TarIO`.

## Decision
Compute the closure over modules instead of packages, conservatively:
- project production code, everything it imports (anywhere in a file), every module a dotted
  string in reached code names, and parent packages;
- framework rules for modules loaded by computed names: Django loads `apps`, `models`, `admin`,
  `templatetags`, `management` and `migrations` of every app and the database backend named in
  settings; Pillow's `Image.init()` loads every plugin listed in `_plugins`;
- a computed import that no rule covers (outside reviewed distributions), unreadable package
  source, or computed imports in project code block every module-level clear.

An alert is cleared when every module that decides it is outside the closure: the modules of
the verified vulnerable functions, or, without them, of every changed function and module-level
change. Never when the model found no matching function, and never when the fix also changes
compiled code in the package, which can run without any Python module naming it.

## Consequences
On the real project: 14 of 94 alerts (15%) cleared, each with the module named and the reason.
Clears depend on reviewed framework rules; a new framework with computed imports blocks clearing
until its rule is written, which is the safe failure. Function-level "not reachable" is not
attempted: Python's dynamic dispatch (`getattr(self, request.method)`) makes it unsound.
