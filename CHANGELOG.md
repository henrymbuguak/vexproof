# Changelog

Releases are tags on `develop`. `main` stays frozen at `v0.1.0`, the hackathon version
(ADR 0021). Each release has a results file under `eval/results/`.

## 0.2.0 - Phase 0: Claude as a second model

Claude is available beside Muse Spark, which stays the default. Every existing recording still
replays, and no published result changes.

### Changed

- **A model can block a clear but never enable or narrow one** (ADR 0020). A clear now needs every
  module the fix changes to be unloaded, whatever function the model picked. All 30 published
  clears still hold, and `vexproof eval` checks the stricter rule: a clear is contradicted if any
  changed module loaded at run time (#16).
- **A refused or cut-off answer is a named failure**, for every model. The alert stays open with
  the reason; a reply cut off at the output limit is no longer "repaired" as bad JSON (#18).
- Output limits for the function pick, the call-path review and the `check-model` ping are 16,000
  tokens, since thinking counts toward them (#18).
- Dependencies updated, including a fix for CVE-2026-126360 in `opentelemetry-api`. `v0.1.0`
  keeps the vulnerable version (#14).

### Added

- **Claude transport** (`VEXPROOF_MODEL_API=anthropic`) through the Anthropic SDK: structured
  outputs, strict tools that are never forced, effort (`VEXPROOF_MODEL_EFFORT`), and a server-side
  refusal fallback (`VEXPROOF_MODEL_FALLBACKS`). Credentials come from `ANTHROPIC_API_KEY` or an
  `ant auth login` profile. `vexproof check-model` lists Claude models and tests them (#18).
- Requests are message lists with optional tools, cache points and effort (ADR 0013). A
  single-message request keeps the recording key it had in `v0.1.0` (#17).
- Recordings keep stop reasons, cache tokens, tool calls, the model that served each answer, and
  every content block of a Claude reply, which goes back to the API unchanged (#17, #18, #20).
- Per-model list prices, with Claude Haiku 5.5's long-prompt rates priced per request; cache
  tokens counted in budgets; tokens and cost by purpose in `findings.json` and the CLI (#21).
- The design and implementation plan (`docs/design.md`) and ADRs 0013 to 0021 (#15).

### Measured

- Gold test on the shop, 13 hand-checked picks: Claude Opus 5.5, Sonnet 5.5 and Haiku 5.5 all
  13 of 13, as Muse Spark. Full shop scans: the same 14 clears, none contradicted at run time.
  Haiku 5.5 accepted one wrong uncertain hop that Opus 5.5 rejected. See
  `eval/results/claude-tiers-shop-1aa90f6.md`.

## 0.1.0 - the hackathon version

Built during the Meta Global AI Developer Hackathon, October 26 to November 4, 2026. Described in
the demo video and the hlab.tech case study; kept unchanged on `main`.
