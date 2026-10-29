# ADR 0011: Evaluate by running the project, outside the scanner

**Status:** accepted · **Date:** 2026-10-29

## Context
vexproof's claims are static: "this module is never loaded", "this call path exists". Gold
labels written by a person check the model's picks, but nobody can label hundreds of module
loads by hand, and a wrong clear (telling a team a reachable vulnerability does not matter) is
the one error the tool must not make. The claims need an independent oracle.

## Decision
- **The oracle is the running project.** `eval/dynamic/observe.py` runs the target with its
  exact pinned packages under a scripted workload (what visitors and admins do, including
  uploads in every image format) and records every loaded module and every function called.
  It uses only the standard library and runs on old interpreters (the demo needs Python 3.8).
- **Kept out of the scanner.** ADR 0001 stands: `vexproof scan` never runs target code. The
  oracle is a separate script for a throwaway environment; the `evaluate` stage reads only its
  JSON output, and the architecture test keeps it from importing anything that runs code.
- **What is checked:**
  - *Closure soundness:* every module of the scanned packages that loaded at run time must be
    in the scan's module closure (now saved in `findings.json`). A miss means a clear could be
    wrong, so it fails the gate, as does
  - *a contradicted clear:* a cleared alert whose module loaded.
  - *Confirmed paths:* a reachable alert whose vulnerable function ran. Not running is "not
    exercised", never evidence against the path.
  - *Missed leads:* open alerts whose picked function ran.
  - Function picks against `eval/gold/symbols.yaml`, and cost per alert from the model usage
    now saved in `findings.json`.
- `vexproof eval` exits 1 when the scan is unsound, so it can gate CI like `make check`.

## Consequences
- The oracle found a real soundness gap on its first run: Django imports every migration file
  by name (`0001_initial.py`), and those names are not identifiers, so the source tree skipped
  them and the closure missed 14 loaded modules. Fixed; cached trees rebuild once.
- A run can falsify a clear but never prove one; the closure check over all loaded modules is
  the stronger test. Coverage depends on the workload, which is a file anyone can extend.
- Compiled extensions (`PIL._imaging`) load without Python source; they are reported, not
  counted as misses, since the fix-commit evidence already refuses clears when C code changed.
- The demo project targets Python 3.6, which current tools no longer install; the oracle runs
  it on 3.8 with the same package versions.
