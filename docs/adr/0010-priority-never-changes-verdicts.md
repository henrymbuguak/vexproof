# ADR 0010: Priority is explained and never changes a verdict; OpenVEX carries the evidence

**Status:** accepted · **Date:** 2026-10-29

## Context
After Chapter 4 each alert is cleared, reachable (with a verified call path) or open. A team
still has to decide what to do first, and other tools need the result in a standard form.
Opaque risk scores are hard to trust and easy to game; mixing business context into
reachability would let a profile "clear" real exposure.

## Decision
- **Tiers from written rules.** *Fix now* needs a verified call path plus one named reason:
  CISA KEV, EPSS ≥ 10%, critical severity, or high severity in an internet-facing service whose
  criticality is not low. Other reachable alerts are *fix soon*; open alerts are *review*;
  cleared alerts are *not affected*. Each ranked alert carries its reasons as text.
- **A score only orders alerts within a tier:** severity (up to 50), EPSS (up to 30), KEV (20).
  CVSS is preferred; a severity label stands in when there is none.
- **The service profile only moves alerts between fix now and fix soon.** It is never read by
  the evidence stages, and the architecture test forbids the report stage from importing them.
- **Upgrade plan per package:** the highest `fixed_in` among standing alerts (clears them all)
  and among reachable alerts (clears what is proven), flagged when the major version changes.
- **OpenVEX v0.2.0, one statement per alert.** `not_affected` uses
  `vulnerable_code_not_in_execute_path` with the evidence as impact statement; `affected` has
  the upgrade as action statement and the call path in `status_notes`; open alerts are
  `under_investigation` with the reason. Products are the project's package URL
  (`pkg:github/<owner>/<repo>@<commit>`) with the dependency as subcomponent. The document id
  is a hash of its content. `problems()` checks the spec's MUST rules before anything is
  written.
- **HTML report:** one file, standard library only, every external string escaped, links only
  for https URLs, and a Content-Security-Policy with `default-src 'none'`.

## Consequences
- Anyone can see why an alert is first and argue with a rule rather than a number.
- EPSS and KEV are snapshots; re-running `report` on the same findings with fresh signals
  needs a new scan (signals are stored in the findings file).
- The upgrade plan does not check compatibility between packages or across major versions; it
  says when a major version changes.
- "Reachable" paths ignore runtime conditions, so the report calls them strong leads, not
  proven exploits.
