# Claude tiers on the shop @ `1aa90f67f455` (Phase 0)

Run on 19 November 2026 from `develop` at `527991d`, against the same project, commit and run-time
observation as [shop-1aa90f6.md](shop-1aa90f6.md) (Muse Spark Open, October 2026). Prompts are
unchanged (`symbol_pick.v1`, `trace_path.v3`). Every Claude request used effort `high`, structured
outputs and the server-side refusal fallback. Costs are list prices per million tokens: Opus 5.5
$4 / $20, Sonnet 5.5 $2 / $10, Haiku 5.5 $0.10 / $0.50, with no prompt caching yet. Muse Spark's
cost is the published estimate at the rates in the README.

OSV changed between the runs: the shop now has 96 alerts, not 94 (three new Pillow advisories, and
one from October no longer listed). The scan comparison below covers the 93 alerts present in both.

## Gold test: picking the vulnerable function

`vexproof check-model examples/demo/findings.json`: 13 hand-checked cases for the shop (a 14th is
written for another Pillow version and is skipped for every model).

| Model | Correct | Invented names | Input / output tokens | Cost | Time |
| --- | --- | --- | --- | --- | --- |
| Muse Spark Open | 13 of 13 | 0 | | | |
| Claude Opus 5.5 | 13 of 13 | 0 | 26,053 / 2,440 | $0.153 | 52 s |
| Claude Sonnet 5.5 | 13 of 13 | 0 | 26,053 / 2,424 | $0.076 | 37 s |
| Claude Haiku 5.5 | 13 of 13 | 0 | 26,053 / 4,498 | $0.005 | 41 s |

All three answered the hardest case correctly: GHSA-f4w8, where none of the changed functions
matches the advisory. Replaying the Opus run from its recordings gave the same 13 of 13 with no
tokens spent.

## Full scan

`vexproof scan` with `--profile examples/shop_profile.yaml`, then `vexproof eval` against
`eval/observed/shop-1aa90f6.json`.

| Measure | Muse Spark Open | Claude Haiku 5.5 | Claude Sonnet 5.5 | Claude Opus 5.5 |
| --- | --- | --- | --- | --- |
| Alerts | 94 | 96 | 96 | 96 |
| Cleared (all by module) | 14 | 14 | 14 | 14 |
| Clears contradicted by the run | 0 of 14 | 0 of 14 | 0 of 14 | 0 of 14 |
| Reachable | 14 | 18 | 17 | 18 |
| Reachable alerts whose vulnerable function ran | 13 of 14 | 15 of 18 | 15 of 17 | 15 of 18 |
| Picks identical to Muse Spark's (of 50) | | 45 | 45 | 47 |
| Model calls (pick / path review) | | 52 / 89 | 52 / 100 | 52 / 92 |
| Refusals, cut-off replies, model errors | | 0 | 0 | 0 |
| Input / output tokens | 228k / 156k | 342k / 117k | 373k / 64k | 360k / 56k |
| Model cost of a scan without recordings | $0.95 (estimate) | $0.093 | $1.38 | $2.56 |
| Scan time | 507 s | 630 s | 668 s | 692 s |

The clears are the same 14 in every run. Since ADR 0020 a pick cannot change a clear, and none did.

### Alerts that became reachable

| Alert | How | Ran at run time | Haiku 5.5 | Sonnet 5.5 | Opus 5.5 | Assessment |
| --- | --- | --- | --- | --- | --- | --- |
| GHSA-frmv (Django `Q`) | order form → `complex_filter` → `Q.__init__`, one uncertain hop | yes | reachable | reachable | reachable | Correct. Muse picked the function but accepted no path |
| GHSA-wqgw (Pillow TIFF) | admin upload → TIFF reader, every hop certain | yes | reachable | reachable | reachable | Correct; a new advisory, no model judgment involved |
| GHSA-6w2r (Django `FilteredRelation`) | `manage.py makemigrations` → `values_list` → `annotate` → `add_filtered_relation`, four uncertain hops | no | reachable | open | reachable | Every call exists and every type the models named is right, but `annotate` reaches `add_filtered_relation` only when given a `FilteredRelation`, which the project never does, and the path starts in a development command. Within ADR 0009's definition (runtime conditions are not judged); a false alarm in practice |
| GHSA-9v9v (Pillow WMF) | admin upload → WMF plugin `_open`, every hop certain | no | open | reachable | reachable | Opus and Sonnet also picked `WmfStubImageFile._open`, which the fix changed; Muse said no candidate matched. Plausible; to be settled by the Phase 1 labels |
| GHSA-4558 (Pillow `frombytes`) | ICO upload → embedded frame → `GbrImageFile.load`, one uncertain hop | no | **reachable** | open | open | **Wrong hop accepted by Haiku.** In Pillow 4.3 an ICO opens an embedded frame through `Image.open` only when it starts with the PNG signature, which the GBR plugin rejects. Sonnet and Opus rejected the same path |

## What this shows

- **Picking functions:** every tier matches the gold labels, so by the design's rule (the smallest
  tier that passes `check-model`) Haiku 5.5 qualifies for `symbol_pick`. Thirteen cases from one
  project cannot separate three perfect scores; the Phase 1 benchmark has to.
- **Reviewing uncertain hops:** Haiku 5.5 accepted one hop that is wrong; Sonnet 5.5 and Opus 5.5
  did not, and Sonnet also turned down the conditional `FilteredRelation` path, at about half
  Opus's cost. On justdjango Haiku accepted far more (see below). The tier for `trace_path`
  should not be the cheapest by default. Tiering and escalation (ADR 0018)
  need to be measured on hop review specifically.
- **Safety:** no model affected a clear, and no run contradicted one. The model errors this run
  surfaced are all in the safe direction (a false "reachable").
- **Cost:** the path review is about three quarters of it, and it re-sends its whole history at
  every step, so the Phase 2 move to native tools with append-only, cached history is the main
  saving to expect. Split by purpose from the recordings (replayed with per-model list prices,
  so no tokens were spent; totals match the live runs exactly):

  | Model | Pick: calls, tokens in / out, cost | Path review: calls, tokens in / out, cost |
  | --- | --- | --- |
  | Opus 5.5 | 52, 116,618 / 10,198, $0.670 | 92, 243,557 / 46,008, $1.894 (74%) |
  | Sonnet 5.5 | 52, 116,618 / 9,424, $0.327 | 100, 256,775 / 54,366, $1.057 (76%) |
  | Haiku 5.5 | 52, 116,618 / 21,183, $0.022 | 89, 225,279 / 95,775, $0.070 (76%) |
- **Not measured yet:** prompt caching; Sonnet 5.5 and Opus 5.5 on justdjango, moved to after
  Phase 2, when the cached review loop makes them cheaper and their numbers stay current.
