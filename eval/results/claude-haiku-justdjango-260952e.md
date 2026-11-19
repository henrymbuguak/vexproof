# Claude Haiku 5.5 on justdjango @ `260952e75344` (Phase 0)

Run on 19 November 2026 from `develop` at `ac2a817`, against the same project, commit and run-time
observation as [justdjango-260952e.md](justdjango-260952e.md) (Muse Spark Open, October 2026).
Effort `high`, structured outputs, the server-side refusal fallback, list prices, no prompt
caching. Sonnet 5.5 and Opus 5.5 on this project are moved to after Phase 2 (about $5 and $10
today, mostly for a review loop that Phase 2 rebuilds with caching).

OSV changed between the runs: 140 alerts now, 137 then (three new advisories, none removed).

| Measure | Muse Spark Open | Claude Haiku 5.5 |
| --- | --- | --- |
| Alerts | 137 | 140 |
| Cleared (all by module) | 16 | 17 |
| Clears contradicted by the run | 0 of 16 | 0 of 17 |
| Reachable | 15 | 30 |
| Reachable alerts whose vulnerable function ran | 12 of 15 | 15 of 30 |
| Function picks matching gold labels | 9 of 9 | 9 of 9 |
| Picks identical to Muse Spark's (of 88) | | 78 |
| Model calls (pick / path review) | 94 / 517 | 90 / 318 |
| Refusals, cut-off replies, model errors | | 0 |
| Model cost of a scan without recordings | $3.61 (estimate) | $0.29 ($0.044 pick, $0.244 path review) |
| Scan time | | 2,516 s |

The extra clear is a new oauthlib advisory, GHSA-7984, whose changed modules justdjango never
loads; it is decided by the deterministic rule and not contradicted. The other 16 clears are the
same as Muse Spark's.

## Alerts that became reachable (15)

| Group | Alerts | Ran at run time | Assessment |
| --- | --- | --- | --- |
| Pillow TIFF (GHSA-wqgw), every hop certain | 1 | yes | Correct; a new advisory, no model judgment involved |
| `sqlparse` through the debug toolbar's SQL formatting (GHSA-2m57, -prg7) | 2 | yes | Correct |
| `sqlparse`, the same route to other functions (GHSA-27jp, -f2ff) | 2 | no | Plausible |
| `PaymentView.post` → Stripe → `requests` / `urllib3` (GHSA-pq67, -9hjg, -9wx4, -gc5v, -vxq7, -g4mx) | 6 | no | Plausible: checkout calls Stripe, which uses `requests`. The workload never made a real payment, so the oracle cannot confirm or refute them |
| `manage.py` commands: `createsuperuser`'s password check (GHSA-53qw), `FilteredRelation` (GHSA-6w2r) | 2 | no | Development commands; the second needs a `FilteredRelation` the project never builds, as on the shop |
| `CheckoutView.get` → `DebugNode.render` (GHSA-95rw); a template tag → Postgres `explain_query_prefix` (GHSA-w24h) | 2 | no | **Doubtful.** They need the `{% debug %}` tag and `QuerySet.explain()`, which the project does not appear to use |

## What this shows

- **Clears are unaffected by the model.** Seventeen clears, none contradicted, on a second project.
- **Haiku 5.5 accepts uncertain hops readily.** Model-reviewed paths went from 4 to 18. Three of the
  15 new reachable alerts are confirmed at run time, eight are plausible but outside what the
  workload exercised, and at least two look wrong. With the shop's GHSA-4558, this confirms the
  conclusion there: the cheapest tier is fine for picks and not, by default, for hop review.
- **The workload is now a limit.** Half of the reachable alerts were not exercised, most of them
  in the payment flow. Phase 1 scores untraced functions as unknown, and a payment step in the
  workload would let the oracle judge six of these.
