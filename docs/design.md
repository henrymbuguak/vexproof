# vexproof on Claude: design doc and implementation plan

Nov 16, 2026 · @Henry

## Problem and value

**Problem.** A Python team with a few hundred dependency alerts cannot tell which ones matter, because scanners match package versions and not the code the application runs. Triage by hand is slow, and the AI tools that speed it up ask the team to trust a model's judgment on a security decision.

**Who has it**

- An application security engineer or maintainer working through a Dependabot or pip-audit backlog on a Django, Flask or FastAPI service.
- A team that must tell a customer or auditor why an alert does not apply, in a form the other side can check.

Not the audience: organisations already paying for commercial reachability analysis across many languages.

**What vexproof gives them**

For each alert, one of three answers, each with its proof: reachable, with a call path a reviewer can read hop by hop; cleared, with the module-level reason, exported as an OpenVEX not\_affected statement once a reviewer approves it; or open, with the stated cause. No answer rests on a model's word.

**Value, measured**

| Measure | Today | What it means for the user |
| --- | --- | --- |
| Alerts decided with evidence | 59 of 231 (26%) across the two evaluated projects | A quarter of the backlog needs no manual triage |
| Cleared alerts contradicted at run time | 0 of 30 | Suppressed alerts have not hidden a live risk so far, on a small sample |
| Reachable alerts whose function ran | 25 of 29 | The fix-first list is mostly real |
| Model cost per scan | $0.95 and $3.61 | Cheap enough to run on every pull request |

**What this project adds**

1. **More alerts decided.** The model investigates the open alerts it can help with, under the same verifier.
2. **Evidence a stranger can trust.** A public benchmark replaces two self-chosen projects, and the false-clear rate gets a stated confidence bound.
3. **Use where the work happens.** Triage from Claude Code or any MCP client, with a human approving every clear.
4. **A reusable pattern.** A worked example of using a model in a decision that cannot tolerate a wrong answer: closed choices, cited evidence, deterministic checks, recorded calls.

**What it does not claim**

- Exploitability. A reachable path shows the call exists in the code, not that an attacker can trigger it.
- That open means safe. An open alert is undecided.
- That moving to Claude improves accuracy by itself. Function picks already match all gold labels on the current model. The port pays off through tool use, caching, tiering and the integrations; the benchmark will show whether picks improve too.

**How we will know it worked**

The share of alerts decided with evidence rises on the held-out projects, the per-group upper bound on the false-clear rate falls below 2%, and someone outside the project reproduces the benchmark from the published instructions.

## Summary

vexproof moves to Claude and gains an agent that investigates the alerts it currently leaves open, while the deterministic verifier stays the only component allowed to accept evidence. The work ships as a provider layer, an agent loop, an MCP server, a Claude Code integration, and an independent benchmark.

**Goals**

- Halve the largest model-addressable group of open alerts (a function was picked but no path was accepted), with no increase in false clears, and report the open rate by cause.
- Replace the small-sample accuracy claim with a published benchmark: at least 100 labelled advisories across at least 10 third-party projects.
- Report cost and latency per alert for each Claude tier, against the existing Muse Spark baseline.
- Make vexproof usable from Claude Code and any MCP client, with human approval before a clear becomes a VEX statement.
- Show that poisoned advisories, commits and repository files cannot cause a wrong clear.

**Non-goals**

- Languages other than Python, or ecosystems other than PyPI.
- Multi-tenant hosting, authentication and billing.
- Automatic remediation pull requests.
- Generating exploits. Ground truth comes from runtime tracing and public fix commits.

**Success metrics**

| Metric | Today | Target |
| --- | --- | --- |
| Open-alert rate | 74% | Under 60% overall; picked-but-no-path group halved |
| False-clear rate, upper 95% bound | About 12.5% under today's rule (0 contradicted, 30 clears in 24 module groups), or about 15% (20 groups) under the pick-independent rule that ships in v0.2.0; provisional until vexproof eval computes it | 3 divided by the number of independent groups; under 2% needs about 150 groups, confirmed or revised after the Phase 1 feasibility check |
| Vulnerable-function pick accuracy | 22 of 22 on 14 labels | Reported on 100+ labels with interval |
| Injection attacks causing a wrong clear | Not tested | 0 across the attack suite |
| Cost per alert | $0.95 and $3.61 per scan, untiered | Reported per tier, with caching on and off |

## Background

vexproof already has the right trust model; what it lacks is reach, evidence and any use of Claude. The figures below come from the [vexproof case study](https://hlab.tech/posts/how-i-built-vexproof-python-vulnerability-reachability/).

**How it works today**

1. Collect: Syft lists dependencies, OSV supplies advisories, git fetches fix commits, and changed lines are mapped to functions.
2. Pick: the model chooses the vulnerable function from those candidates and quotes the advisory.
3. Prove: a search looks for a call path from project code to that function.
4. Verify: a deterministic verifier checks each step at its cited lines.
5. Report: alerts become fix now, cleared or open, exported as OpenVEX.

**Gaps this design closes**

| Gap | Evidence | Addressed in |
| --- | --- | --- |
| Most alerts stay open | 172 of 231 open | Agent loop |
| Accuracy rests on a tiny sample | 14 hand labels, two Django projects | Evaluation plan |
| The false-clear claim is weak | 0 of 30 clears in 24 module groups bounds the rate only below about 12.5% under today's rule, or about 15% (20 groups) under the pick-independent rule | Evaluation plan |
| A wrong pick with a real quote can pass | The verifier checks grounding, not meaning | Agent loop, verifier contract |
| No tool use, no MCP, no Claude | The model only picks among candidates | Provider layer, MCP server |
| Untrusted text reaches the model untested | Advisories and commits are attacker-writable | Security and threat model |

**What stays unchanged**

- The verifier remains deterministic and is the only path to a cleared or reachable verdict.
- vexproof never executes the code it scans.
- Model responses stay recorded and keyed by model, prompt version and inputs, so runs replay offline.

## What the code review found

Reviewed at commit `0f8c70a` (11 Nov 2026). The code is further along than the case study suggests, and the sample scan shows that half of the open alerts are not a model problem at all.

**Already in place, to keep**

- A vendor-neutral `Transport` protocol with recording, budget and structured-output layers stacked on it.
- Record and replay keyed by model, prompt version, prompts and schema, with `cache`, `replay` and `live` modes.
- Versioned prompt files (`trace_path.v1` to `v3`), so a prompt change never reuses old answers.
- A go/no-go gate, `vexproof check-model`, that scores a model on gold labels before it is trusted.
- A model-driven review loop in `evidence/trace.py` with five actions and a 12-step cap.
- Twelve architecture decision records and a test that enforces module boundaries.

**What limits Claude today**

| Finding | Where | Consequence | Change |
| --- | --- | --- | --- |
| The only transport speaks the OpenAI-style Responses and Chat APIs | `llm/meta.py`, `llm/factory.py` | No prompt caching controls, no native tool use | Add `AnthropicTransport` |
| A request is one system string and one user string | `llm/types.py` | No multi-turn history, no tool results, no cache breakpoints | Extend `ModelRequest` |
| The loop re-renders its whole history into one user message each step and shortens older observations | `Tracer._render` | The prefix changes every step, so nothing can be cached; cost grows with the square of the step count | Append-only messages with tool results |
| Actions are free-form JSON with about 100 lines of synonym and wrapper repair | `TraceAction._normalise`, `_SYNONYMS` | Needed for a model without enforced schemas; hides errors with one that has them | Native tools for Claude; keep repair only in the Muse adapter |
| The response carries no stop reason or cache token counts | `ModelResponse` | Truncation looks like bad JSON; cached tokens are priced as fresh | Extend `ModelResponse` |
| One token budget for the whole run | `BudgetTransport` | One hard alert can starve the rest | Add per-target and per-purpose caps |
| One input price and one output price from the environment | `config.py` | Cannot compare tiers or price cache reads | Per-model price table |
| Django facts are written into the review prompt | `trace_path.v3.md` | Grows with every framework; always paid for | Framework notes loaded by detected framework |
| No model call when the search finds no candidate path | `Tracer._trace` | The largest model-addressable group gets no investigation | Typed-edge proposals |

**Why alerts stay open (sample scan in `examples/demo`, 94 alerts, 66 open)**

| Cause | Open alerts | Share of open | Can a model help? |
| --- | --- | --- | --- |
| The fix changes only non-Python code (bundled JavaScript, C) | 33 | 50% | No; these are compiled C sources, which file presence cannot clear |
| A function was picked but no path was accepted | 19 | 29% | Yes; main target of this design |
| The advisory names no fix commit | 5 | 8% | Yes, with a version-range check |
| No candidate matches the advisory | 4 | 6% | Partly; often a correct abstention |
| The fix changes module-level code or functions absent from the installed version | 4 | 6% | Yes, with a similarity check |
| The fix changes code outside the installed package | 1 | 2% | No |

These counts are provisional. Several alerts carry more than one of these notes, and each was placed in a single group by hand. The `open_reason` field will assign one reason per alert using a written order of precedence (non-Python fix, no fix commit, fix outside package, changed code absent, none-match, no path), and the table will be regenerated from it. Under that order the 3 alerts that have both a pick and a non-Python fix count as non-Python, so the picked-but-no-path group is about 16, not 19; the goal is measured against the regenerated count.

This sets the ceiling. If the model resolved every alert it can plausibly help with, the open rate on this scan would fall from 70% to about 40%; a realistic first target is to halve the picked-but-no-path group (about 16 once the table is regenerated) and report the rest by cause.

## Architecture

Everything a model produces is a proposal, and the deterministic verifier is the only component that writes evidence or a verdict.

Clients reach vexproof only through the MCP server or the CLI. The fixed pipeline handles every alert first; the agent loop takes the ones left open. Both send candidates and proposals to the verifier, which re-reads the cited code itself. A cleared alert becomes a draft, and a human approval turns the draft into an OpenVEX statement.

**Components**

| Component | Responsibility | Trust |
| --- | --- | --- |
| Collectors | Dependencies, advisories, fix commits, function mapping | Deterministic; inputs untrusted |
| Provider layer | One interface to Claude and Muse Spark, caching, cost records | Output untrusted |
| Fixed pipeline | Pick the vulnerable function, search for a call path | Mixed; verdicts go through the verifier |
| Agent loop | Investigate open alerts with read-only tools | Output untrusted |
| Verifier | Check every pick, hop and clear; write evidence | Trusted |
| MCP server | Expose scans, alerts, evidence and drafts to clients | Trusted code, untrusted callers |
| Review UI and CLI | Human approval of clears | Trusted |
| Evaluation harness | Benchmark, ablations, injection suite, CI gate | Trusted |

**Request flow for one alert**

1. Collectors gather the advisory, the fix diff and candidate functions.
2. The provider layer asks the model to pick a candidate; the verifier checks the candidate and the quote.
3. The path search runs; the verifier checks each hop.
4. If a verified path exists, the alert is reachable. If module checks pass, it is cleared. Otherwise it is open.
5. For an open alert, the agent loop proposes further hops or typed edges for each target function until it finds a verified path, gives up or runs out of budget.
6. A cleared alert can be proposed as a VEX draft, which a human approves or rejects.

## Where the model works, and where it must not

Model use grows in five places, and each one is admitted only because a deterministic check exists for its output; where no such check exists, the model stays out.

| # | Use | Today | Proposed | What the verifier checks | Tier | Priority |
| --- | --- | --- | --- | --- | --- | --- |
| 1 | Pick the vulnerable functions (per alert) | One call per alert | Unchanged, on Claude with structured outputs | Each name is a candidate; quote is in the advisory | Smallest that passes `check-model` | Phase 0 |
| 2 | Review uncertain hops (per target) | JSON-action loop | Same loop on native tools, with `accept_path` | Accepted path re-verified hop by hop | Smallest that passes, escalating | Phase 2 |
| 3 | Investigate targets with no candidate path | No model call | Same loop proposes typed edges the call index cannot see | Edge-specific check in the cited file, anchored in reached code | Same as 2 | Phase 2 |
| 4 | Map a fix onto the installed version | Alert left open | Model proposes the function that held the code before a rename or move | Function exists in the installed version; body similarity to the pre-fix code above a threshold. Feeds path search only, never a clear | Same as 1 | Phase 2 |
| 5 | Find the fix commit when the advisory names none | Alert left open | Model ranks commits from the vulnerable-to-fixed range | Commit lies in that range and touches the package; marked inferred. Feeds path search only, never a clear | Small | After release |
| 6 | Explain a verdict in plain language | Raw evidence only | Short summary for the report and the MCP `explain_evidence` tool | Every file, line and name in the text must appear in the evidence record; otherwise the text is dropped | Small, batched | Phase 3 |

**Typed edges (use 3)**

Frameworks connect code by declaration, not by call. An edge only matters if its "from" side is already reached: a filter used in a template counts only if a reached view renders that template. So every edge kind names its anchor in reached code, and an edge whose anchor is not reached is rejected rather than treated as a new entry point. Much of this already exists: URL routes, middleware and admin wiring are hand-written rules, and settings references are mostly covered by the string sites the closure already follows.

| Edge kind | Must be reached or loaded | Model supplies | Deterministic check | Status |
| --- | --- | --- | --- | --- |
| Signal or hook registration | The module that sends the signal is reached, and the module holding the connect call or decorator is loaded | File, receiver | The decorator or connect call exists in that loaded module and names the receiver | First to build |
| Registry or plugin dispatch | The lookup site is reached, and the module holding the registration call is loaded, as `_pillow_open` already requires | Registration file, key | The registration call exists in that loaded module and its key matches the lookup | First to build |
| URL route | The URL config the project mounts | URL config file, view | The pattern exists and resolves to the view | Extend existing rules |
| Settings reference | Settings the project loads | Settings key, dotted path | The string resolves to the target | Mostly covered today |
| Template filter or tag | A reached view that renders the template | Template path, filter name | The view renders the template, the template uses the filter, and the filter is registered to the target | Later; needs a Django template parser |

For every edge kind the model supplies a file and a name or pattern, and the verifier parses that file and finds the node and its line itself. The model does the matching; code does the counting. An edge kind without a check is not accepted, and new kinds are added as code, with tests, never by prompt.

**Where the model stays out**

- **Clears.** Today a verified pick narrows which modules decide a clear, so a wrong pick can support a wrong one; all 14 clears in the sample scan rest on a pick. This design fixes the rule in one direction: a model may block a clear, never enable or narrow one. A clear requires every module the fix changes to be outside the closure, whatever the model picked. A none-match answer keeps blocking clears, as it does today, because the vulnerable code may lie outside the changed functions. The changed modules must come from fix commits named in the advisory's own references, so a model-inferred fix commit (use 5) and a version-drift mapping (use 4) can never supply or remove a module that decides a clear. An advisory with no referenced fix commit can never be cleared at module level: it is reachable or open, unless the whole package is outside the import closure.
- **Facts.** Versions, CVSS, EPSS, KEV, diffs and line numbers keep coming from code and public data.
- **Priority.** Ranking never changes a verdict, as the existing decision record states.
- **Non-Python fixes.** In the sample scan, 32 of these 33 alerts are Pillow, and the changed files are almost all C sources compiled into the extension. A file-presence check cannot clear them, and the code rightly refuses to. The useful deterministic step is a registry rule that maps a C decoder to the Python plugin that requests it, which can move alerts to reachable but never to cleared. Treat a model-proposed bridge from a C function to its Python entry point as research, not as part of this release.
- **Approval.** No model can approve a VEX draft.

## Model provider layer

The repository already has the right seam: a `Transport` protocol wrapped by `RecordingTransport`, `BudgetTransport` and `StructuredCaller` in `src/vexproof/llm/`. Claude arrives as a second transport beside `MetaTransport`, and the request and response types grow to carry what Claude needs. Nothing above `llm/` should import a vendor SDK.

**Interface**

```python
# llm/types.py: extend the existing dataclasses, keep the Transport protocol
@dataclass(frozen=True)
class ModelRequest:
    purpose: str
    prompt_version: str
    system: str
    messages: tuple[Message, ...]  # replaces the single `user` string
    tools: tuple[ToolSpec, ...] = ()  # empty for plain structured calls
    schema_name: str = ""
    schema: dict[str, Any] = field(default_factory=dict, hash=False)
    cache_points: tuple[int, ...] = ()  # message indexes that end a cacheable prefix
    max_output_tokens: int = 2000
    # key(model) must hash messages and tools as well as the current fields;
    # cache_points are a cost hint and stay out of the key


@dataclass(frozen=True)
class ModelResponse:
    text: str
    model: str
    tool_calls: tuple[ToolCall, ...] = ()
    stop_reason: str = ""
    input_tokens: int = 0
    cache_read_tokens: int = 0
    cache_write_tokens: int = 0
    output_tokens: int = 0
    latency_ms: int = 0
    replayed: bool = False


# llm/anthropic.py: AnthropicTransport implements Transport with the Anthropic SDK
# llm/meta.py: unchanged behaviour, adapted to the new request shape
```

**Design decisions**

- **Structured outputs as the main path.** The pick and every other single-answer task use structured outputs (`output_config.format`) with the Pydantic-generated schema. Tools in the loop use `tool_choice: auto` with `strict: true`, and the prompt says when each tool applies. Never force a tool: Opus 5.5 and Sonnet 5.5 reject `tool_choice` of `any` or a named tool with a 400. Keep Pydantic validation and the one repair retry behind it.
- **Thinking is set by effort, not switched on or off.** Opus 5.5 always thinks and defaults to medium effort; the current Sonnet and Haiku models think by default too. Set effort explicitly per purpose in config, and where the design once said "enable thinking on hard cases", raise the effort for that request instead.
- **Output limits sized for thinking.** Thinking counts toward `max_tokens`, so today's `MAX_OUTPUT_TOKENS = 4096` for the pick, the 4096 for the trace loop and the 1024 ping in `check-model` will truncate answers. Raise them to a ceiling well above expected use (start at 16,000) and treat `stop_reason: max_tokens` as a typed failure that leaves the alert open, never as bad JSON to repair.
- **Caching, with realistic expectations.** The cache matches a prefix in the order tools, system, then messages, separately for each model. The pick and the trace loop have different tools and system prompts, so nothing carries between them, and escalating to another model starts cold. The real saving is inside a loop: tools, system prompt and framework notes are identical for every trace loop of a scan, and a rolling breakpoint caches each loop's growing history. Prefixes below the model's minimum (512 to 4,096 tokens) silently do not cache, which can include a short pick prompt. Count savings only from `cache_read_input_tokens` in the usage records.
- **Tiering by purpose, escalating by restart.** Each purpose starts on the smallest tier that passes `check-model`. Escalation reruns that target's loop from the start on the larger model, because thinking blocks are tied to the model and the conversation and the cache does not carry over.
- **Batch for offline work.** Benchmark runs and backfills go through the Message Batches API. Interactive scans use the synchronous API.
- **Every stop reason has a handler.** Rate limit and overload errors retry with backoff and jitter. `refusal` leaves the alert open with `model_refused`; `max_tokens` leaves it open with `model_error`; schema failures after the repair retry likewise. None is treated as a negative answer.
- **Cost accounting from records.** Every response stores input, cache-read, cache-write and output tokens, so cost per alert and per target is computed from recordings, not estimated.

**Tasks routed through the provider**

| Task | Unit | Input | Output | Default tier |
| --- | --- | --- | --- | --- |
| Pick vulnerable functions | Per alert | Advisory, fix diff, candidate list | `FunctionPick` via structured outputs | Smallest tier that passes `check-model` |
| Trace loop | Per target function, shared across alerts | Target, current candidate path, tool results | Tool calls ending in `accept_path`, `give_up` or a verified path | Smallest tier that passes, escalating per target |

Model IDs live in one config file. Confirm current IDs and structured-output support in the [Claude docs](https://docs.claude.com) before pinning them.

**Refusals**

The cyber safety classifier can decline benign security work, and vulnerability advisories are exactly the kind of text that may trip it. A refusal arrives as HTTP 200 with `stop_reason: "refusal"` and a category in `stop_details`. vexproof records it, leaves the alert open with `model_refused`, and reports the refusal rate per purpose and model. The server-side `fallbacks` parameter (beta) can retry a refused request on another model; it is rejected on the Message Batches API, so refused batch items are rerun synchronously with fallback enabled. A response served by a fallback model is recorded under that model.

**Estimated cost of the shop scan on Claude**

These apply list prices to the token counts the shop scan recorded on Muse Spark (about 228,000 input and 156,000 output tokens, no caching). Thinking and the tokenizer will change the real counts, so Phase 0 replaces these with measured figures.

| Model | Input and output price per million tokens | Estimated scan cost | Per alert (94 alerts) |
| --- | --- | --- | --- |
| Opus 5.5 | $4 and $20 | about $4.03 | about $0.043 |
| Sonnet 5.5 | $2 and $10 | about $2.02 | about $0.021 |
| Haiku 5.5 | $0.10 and $0.50 | about $0.10 | about $0.001 |

Haiku 5.5 costs about a fortieth of Opus 5.5, so the tier question is decided by `check-model` accuracy and the benchmark, not by budget. Prices from the [pricing page](https://platform.claude.com/docs/en/about-claude/pricing), checked 18 Nov 2026.

## Agent loop

vexproof already runs a small agent: `evidence/trace.py` lets the model review a candidate path in up to 12 steps, choosing accept, search, callers, source or give up. This design keeps that loop, its rule that the model steers the search but never adds a hop, and its unit of work: one loop per target function, never per alert. Today a trace request depends only on the target and the evidence shown, so alerts that share a vulnerable function share one review and one recording. The loop moves onto native tool use and also runs for targets where the search finds no candidate path, which today get no model call.

**Why an agent here and a workflow elsewhere**

Collect, pick and verify are fixed steps with known inputs, so they stay a workflow. Open alerts fail for varied reasons: dynamic dispatch, framework wiring, re-exports, or a path the search did not try. Finding the next thing to look at is open-ended, which is the case an agent loop fits.

**Tools (all read-only)**

| Tool | Arguments | Returns | Notes |
| --- | --- | --- | --- |
| `read_source` | qualified name, or path and line range | The source span with file and line numbers | Today's `source`; paths confined to the scan root and installed packages |
| `find_callers` | qualified name | Call sites from the static index, certain ones first | Today's `callers` |
| `find_symbol` | name | Definitions and re-exports | Covers aliasing and `__init__` re-exports |
| `framework_routes` | none | URL routes, signals and middleware the existing rules know | Django first; Flask and FastAPI later |
| `search` | `avoid`, `through` | A new verified candidate path, or the reason none exists | Today's `search`; `avoid` entries accumulate |
| `propose_hop` | caller, callee | Verifier result for that call edge | Accepted hops join the path |
| `propose_edge` | kind, file, name, target | Verifier result for that typed edge | Only kinds with a reached "from" side; see Typed edges |
| `accept_path` | reason per uncertain hop | The re-verified path, or why it no longer verifies | Today's `accept`; needed only when the path has uncertain hops |
| `give_up` | reason | Ends the loop | Reason is stored with the target |

Tool descriptions state what each returns, when to use it and what it cannot do. Errors come back as structured results with `is_error` set and a message the model can act on, not as exceptions.

This table is the complete list of tools exposed to the model, and the `ToolSpec` definitions are generated from it one for one. Nothing in it reads the advisory or the fix diff: those belong to the pick stage, which runs once per alert and returns the target set. Keeping advisory text out of the loop preserves shared reviews across alerts and keeps untrusted advisory text away from the tools. A path made only of certain hops is complete as soon as the verifier connects an entry point to the target, and the loop ends without `accept_path`; that tool exists because an uncertain hop is a judgment about an object's run-time type, which the verifier cannot settle and the model must explain. An alert is reachable when any target in its set has a verified path. The existing cap of 12 steps is the starting value for the turn budget.

**Verifier contract**

- `propose_hop` sends `{caller, callee}`. The model supplies names, never line numbers. The verifier locates the call site in the caller itself and accepts only if it resolves to the callee.
- An accepted hop is appended to the path by the verifier. The agent cannot write to the path.
- A path is reachable only when verified hops connect a project entry point to the picked function.
- A clear still requires the existing module-level checks. The agent cannot propose a clear; it can only fail to find a path, which leaves the alert open.
- A pick can block a clear (none-match) but never enable or narrow one: every module the fix changes must be outside the closure. A pick therefore affects only where the path search aims, and a path search on a valid pick is never blocked by other changed modules.

**Budgets and stopping**

- Per target function: a cap on turns, on total tokens and on wall-clock time, all configurable. Starting values: the existing 12 steps and 150,000 input tokens.
- The loop stops on a verified path, on `give_up`, or when a cap is hit. A cap hit is recorded as `budget_exhausted`, distinct from `no_path_found`.
- History is append-only for the whole loop, so the cached prefix stays valid. Tool results are bounded in size at the source. If a loop ever needs compaction, it ends, and a new, separately recorded request starts from a summary.

**Implementation**

Refactor the existing `Tracer._review` loop in place; do not write a second loop beside it. The five actions become five tools, the hand-rendered history becomes an append-only message list, and the new proposal tools are added to the same loop. Keep it hand-written on the Messages API so it stays testable against the scripted transport. Evaluate the Claude Agent SDK only after the benchmark exists, and adopt it only if it removes code without weakening replay.

**Deliberately not multi-agent**

One loop per target function, run in sequence in report order, exactly as `prove()` does today. Approved hops carry over from one review to the next, so the order must be fixed for runs and their recordings to reproduce; parallel loops would make that order depend on timing. Parallelism stays possible later only if approvals become order-independent, for example by recording them as per-scan facts in a first pass and reading them in a second. Targets are independent apart from that shared memory, so there is nothing for several agents to coordinate.

## MCP server, Claude Code and human approval

The MCP server is the single integration surface: Claude Code, other MCP clients and the review UI all reach vexproof through it, and none of them can sign a VEX statement without a human.

**MCP server (FastMCP, Python)**

| Tool | Purpose | Side effects |
| --- | --- | --- |
| `scan_project` | Start a scan of a path; returns a scan ID | Writes scan records |
| `scan_status` | Progress and counts by verdict | None |
| `list_alerts` | Alerts filtered by verdict, package or severity, paginated | None |
| `get_alert` | One alert with its evidence chain | None |
| `explain_evidence` | The verified path or clear reason as cited file spans | None |
| `investigate_alert` | Run the trace loop on demand for an open alert's targets | Model spend, bounded by budget |
| `propose_vex` | Create a draft VEX statement for an alert | Draft only |

Resources expose read-only evidence: `vexproof://scan/{id}/report` and `vexproof://alert/{id}/evidence`. A prompt template, `triage-backlog`, walks a client through scan, list, investigate, propose.

An on-demand `investigate_alert` run reads the scan's approved hops but never adds to them, and its requests are recorded apart from the scan's. The scan's fixed order, and every replay of it, are therefore unaffected by what anyone investigates later.

- Transport: stdio for local use with Claude Code. Streamable HTTP is out of MVP scope because it needs authentication.
- Tool results are compact and paginated, with IDs the client can pass back. Large evidence is fetched through resources, not inlined.
- There is no approve tool on the MCP server. That alone does not put approval out of reach: Claude Code has a shell, so it could run the approve command or write a VEX file directly. The approval flow below is built for that.

**Human approval flow**

1. `propose_vex` writes a draft with status `pending_review` and returns its ID.
2. The reviewer opens the draft in the review UI (the existing FastAPI app) or runs `vexproof approve <id>` in an interactive terminal, where it shows the evidence and asks the reviewer to retype the alert ID; it refuses when no terminal is attached, which is the case for Claude Code's shell and for CI. That includes `! vexproof approve` typed into Claude Code, which also runs without a terminal, so a reviewer approves from a separate terminal or from the review UI.
3. Approval records the reviewer, time and evidence hash, then writes the OpenVEX document.
4. Rejection records a reason, which is added to the benchmark's hard cases.

Reachable verdicts need no approval to appear in a report, because a false alarm is the safe direction. Only clears, which suppress an alert, are gated.

**What the export says about unapproved clears**

Today `vexproof report --openvex` and the web download write `not_affected` for every clear, with no approval step. From the release that adds approval (`v0.4.0`), the export follows one rule: a statement is `not_affected` only when the alert has an approval record whose evidence hash matches the current evidence. Every other clear is exported as `under_investigation`, with status notes saying vexproof found the deciding modules never loaded and the clear is pending human review. The HTML report shows the same distinction. Until that release, the README states plainly that exported clears are unreviewed.

**What the approval hash covers**

The hash covers only the facts that decide a clear, so a live re-run that rewrites the model's rationale or other free text does not quietly void approvals: the package name and version, the fix commits the advisory references, the deciding modules, and the closure's reasons and blockers for those modules. Any change to those facts voids the approval, which is the intent.

**The web route**

The review UI is a second approval route, and today it is open to an agent: `_same_origin` in `web/app.py` accepts any request that sends neither `Origin` nor `Sec-Fetch-Site`, plain `curl` sends neither, and the app has no authentication. The approve endpoint will require `Sec-Fetch-Site: same-origin` and a per-form token, and the Claude Code settings deny requests to the approve URL. Like the terminal check, this stops mistakes rather than a determined agent, which can fetch the form, read the token and send any header; the guarantee stated below still rests on the export rule and the approval record.

**What this does and does not guarantee**

An agent with a shell, running as the same user, can do anything that user can, including faking a terminal or writing an OpenVEX file by hand. Deny rules and the terminal check stop mistakes and well-behaved agents; they are not a security boundary. The guarantee is narrower and holds anyway: every `not_affected` statement that vexproof itself emits traces to an approval record made through a channel the agent integration is not configured to use. A file the agent writes by hand is not vexproof output. For teams that need approval to be unforgeable on a shared machine, the next step is signing approval records with a reviewer key held outside the agent's environment; that is listed as future work, not built in this release.

**Claude Code integration**

- **`.mcp.json`** in the repo registers the server for the project.
- **Skill `triage-dependency-alerts`**: instructions for running a scan, investigating open alerts in severity order, and presenting drafts for approval. It tells Claude to treat advisory text as data.
- **PreToolUse hook on Bash**: a script inspects the command, and when it matches `pip install`, `uv add` or `poetry add` it checks the package against OSV, and against an approved-package registry only if one is configured (the governed dependency pipeline is one such registry; without one the hook checks OSV alone). The hook is optional and does not gate any release. It blocks only when a configured registry does not know the package name, or the package has a reachable alert of high or critical severity; with no registry configured, an unknown name never blocks. Open alerts and lower severities produce a warning that is added to Claude's context, and the install proceeds.
- **Permissions**: the project settings allow the vexproof MCP tools and deny the approve command in every spelling an agent might use (vexproof approve, uv run vexproof approve, python -m vexproof approve) and any curl or wget request to the review UI's approve URL. This is a guard against mistakes, not a boundary; the export rule above is what keeps unapproved clears out of VEX output.
- **Headless mode** in CI: `claude -p` with the skill runs the scan on pull requests and posts the summary. The CI gate itself calls the CLI directly and does not depend on a model.

Check hook input format and exit-code semantics against the current [Claude Code docs](https://docs.claude.com) before implementing.

## Data model and schemas

Five record types carry everything, and each verdict can be rebuilt from its records without calling a model.

| Record | Key fields | Written by |
| --- | --- | --- |
| `Alert` | id, package, version, advisory ID, verdict, reason, scan ID | Pipeline |
| `Evidence` | alert ID, kind (pick, hop, clear reason), file, line span, content hash, verifier result | Verifier only |
| `ModelCall` | cache key, provider, model, prompt version, token counts, latency, stop reason, parsed output | Provider layer |
| `AgentRun` | target function, turns, tool calls, proposals accepted and rejected, stop cause, total cost | Agent loop |
| `VexDraft` | alert ID, status, evidence hash, reviewer, decided at, rejection reason | MCP server, review UI |

**Model output schemas**

```python
class FunctionPick(BaseModel):
    selected: list[str]  # each must be one of the supplied candidates
    none_match: bool
    advisory_quote: str  # must appear verbatim in the advisory
    confidence: Literal["high", "medium", "low"]


class HopProposal(BaseModel):
    caller: str  # qualified name
    callee: str  # qualified name; the verifier finds file and line


class EdgeProposal(BaseModel):
    kind: Literal["signal", "registry", "url", "settings", "template"]
    file: str  # path inside the scan root
    name: str  # receiver, key, view, dotted path or filter
    target: str  # qualified name the edge leads to


class AcceptPath(BaseModel):
    reasons: list[str]  # one per uncertain hop, in path order
```

- Fields the verifier can check (candidate names, quote, caller, callee, edge file and name) are required. Free-text reasoning is optional and never used for a verdict.
- Keep the existing `Verdict` values (`affected`, `not_affected`, `under_investigation`), which map directly to OpenVEX and are already in `findings.json`, the demo and the evaluation. Add an `open_reason` field instead, set only when the verdict is `under_investigation`, with values matching the cause table: `non_python_fix`, `no_path_found`, `no_fix_commit`, `none_match`, `changed_code_absent`, `fix_outside_package`, plus `changed_module_loaded`, `closure_blocked`, `budget_exhausted`, `model_refused` and `model_error`.
- The recording key stays backward compatible: a request with one user message, no tools and no effort setting must hash exactly as `key()` does today, so every existing recording replays. Messages, tools, effort and thinking settings join the hash only when present.

**Storage**

SQLite for scan state and drafts, plus the existing on-disk response cache. Postgres is unnecessary until there is more than one user.

## Security and threat model

The model reads attacker-writable text on every alert, so the design assumes its output is hostile and makes a wrong clear impossible without a verifier failure or a human approving it.

**Assets**: the correctness of a clear, the scanned source code, the API key, and the user's machine.

**Untrusted inputs**: advisory text, fix commit messages and diffs, dependency source, the scanned repository's own files (README, comments, docstrings), and package metadata.

| Threat | Example | Control |
| --- | --- | --- |
| Injection to force a clear | Advisory text says the package is unaffected and to mark it cleared | A clear requires every module the fix changes to be outside the closure, so no pick can narrow it |
| Injection to steer the pick | A commit message names a harmless function as the vulnerable one | Pick must be a supplied candidate with a verbatim advisory quote; a wrong pick can only misdirect the path search, never clear an alert |
| Injection to exfiltrate code | A docstring tells the agent to send file contents somewhere | No network or write tools exist; all tools are read-only and path-restricted |
| Path traversal through tools | `read_source` asked for `~/.ssh/id_rsa` | Paths resolved and confined to scan root and site-packages; symlinks rejected |
| Budget exhaustion | A file crafted to trigger endless exploration | Per-target turn, token and time caps; per-scan spend cap |
| Fabricated evidence | Model invents a call at a line | Verifier re-reads the file and resolves the call itself |
| Poisoned response cache | A tampered cache entry replays a favourable answer | The cache directory is trusted local state, like the source tree. A tampered entry can at worst leave an alert open, never clear it, because the verifier runs on replay. CI replays only from reviewed recordings |
| Agent approves its own work | Claude Code edits the VEX file directly | No approve tool on the MCP server; approve refuses without an interactive terminal; the web approve endpoint requires a same-origin fetch header and a form token; deny rules on the approve command; the export writes not\_affected only for alerts with a matching approval record. A hand-written file is not vexproof output, and signed approvals are future work |
| Malicious package install by a coding agent | A hallucinated package name gets installed | PreToolUse hook checks the approved registry before install |
| Secret leakage | API key in logs or cache | Key read from environment only; requests and responses logged without headers |

**Prompt-level hygiene**

- Untrusted text is wrapped in clearly delimited blocks, and the system prompt states that content inside them is data. This lowers the attack rate; it is not the control. The controls are the missing capabilities and the verifier.
- Tool results from `read_source` carry the file path and line numbers so the verifier and the reviewer can check the same span.

**What is deliberately out of scope**

- Executing scanned code or dependencies, in any sandbox.
- Writing exploits or proof-of-concept payloads. Claude's safeguards may decline such requests, and the design never needs them.

**Residual risk**

With clears made independent of the pick, a wrong pick can no longer hide a risk; it can only send the path search after the wrong function and leave the alert open. What remains is the closure itself: a module that loads in a way no rule covers would be cleared wrongly. The existing blockers for computed imports and plugin entry points guard this, the benchmark measures it, and human approval is the last gate.

## Evaluation plan

The benchmark is a deliverable in its own right: a public, versioned dataset and harness that anyone can run against any model, with the false-clear rate as the headline number.

**Benchmark construction**

- **Function labels.** At least 100 advisories, each labelled with the vulnerable function or functions. Sources: fix commits read by hand, advisory text that names a symbol, and upstream tests added with the fix. A second pass by a different method (the upstream regression test) confirms each label.
- **Projects.** At least 10 open-source applications not written by the author: a mix of Django, Flask and FastAPI, pinned to commits with known-vulnerable dependencies.
- **Reachability ground truth.** For each project, record loaded modules and executed functions from two production-shaped runs only: the scripted workload and an import sweep of every production module. These are the only runs that can contradict a clear. The project's own test suite imports modules that production never loads, which would make correct production clears look contradicted, so test-suite runs are used only to confirm reachable paths and function picks, and their loaded modules are never compared with clears. A function that ran is reachable. A function that did not run is unknown, not unreachable, and is scored separately.
- **Split.** Hold out 30% of advisories and 3 projects. Prompts are tuned only on the rest.
- **Versioning.** Labels, project pins and the workload scripts live in a separate repo with a changelog and a licence.

**Metrics**

| Metric | Definition | Why it matters |
| --- | --- | --- |
| False-clear rate | Cleared alerts with any deciding module loaded at run time (the ADR 0011 test), over all clears, with a 95% upper bound counted by independent group | The safety-critical number |
| Pick accuracy | Picks matching a labelled function | Quality of the model step alone |
| Open rate | Alerts left open, over all alerts | Usefulness |
| Reachable precision | Verified-reachable alerts whose function ran | Cost of false alarms |
| Cost per alert | Sum of recorded token cost over alerts | Tier and caching decisions |
| Latency per alert | Median and 95th percentile | Interactive use |
| Attack success rate | Injection cases producing a wrong clear or out-of-policy tool call | Security claim |

**Statistics**

With zero misses in n independent trials, the 95% upper bound on the false-clear rate is about 3 divided by n. Clears are not independent trials. The unit is the module, because a closure error happens per module, as a missing rule for how one module loads, and every clear that rests on that module fails with it. So a group joins clears that share a deciding module within the same package version.

The grouping rule moves the result a long way. An independent recount on both scans gives 24 groups today (about 12.5%) and 20 under the pick-independent rule (about 15%); grouping by package version alone would give 5 groups and about 60%. An earlier hand count in this doc (14 and 12 groups, about 21%) grouped across package versions, used incomplete module lists, and could not be reproduced. The grouping now goes into `vexproof eval` as code, and this doc quotes its output once that exists; until then the figures above are provisional.

So every result reports two bounds: per clear, and per independent group, where a group joins clears that share a deciding module within the same package version. The per-group bound is the headline. Reaching under 2% needs about 150 groups, which in practice means more projects and more distinct package versions, not more alerts from the same ones.

**Limits of the oracle**

A clear counts as "not contradicted", not as "proven correct": a module that would load only on a path no test or workload exercises goes unseen, so the measured false-clear rate is a lower bound. Three steps narrow the gap. Report line and module coverage of each project's run next to its results. Add an import sweep that starts the application and imports every production module of the project, never its tests, since module loading is far less dependent on workload than function execution. And keep the bound and the coverage figure together wherever the rate is quoted.

**Comparisons and ablations**

1. Muse Spark versus each Claude tier on pick accuracy and cost.
2. Workflow only versus workflow plus agent loop, on open rate and false clears.
3. Verifier off: how often the raw model output would have been wrong. This quantifies what the verifier buys.
4. Caching on versus off, on cost.
5. Mid tier only versus escalation to the top tier, on open rate per dollar.

**Injection suite**

At least 30 cases across the untrusted inputs: instructions in advisory text, commit messages, docstrings, README files and package metadata, each aiming at a wrong clear, a wrong pick, a path escape or budget exhaustion. Each case has a pass condition checked by code.

**CI gate**

- Every pull request replays the recorded responses for a fixed subset and fails on any change in verdicts.
- A weekly job runs the live benchmark on the held-out set and fails if false clears rise above zero, pick accuracy drops more than 3 points, or cost per alert rises more than 20%.
- Prompt and tool-description changes bump the prompt version, which invalidates the cache for affected tasks.

**Debugging aids**

Each `AgentRun` stores its full trace. A `vexproof trace <alert>` command prints turns, tool calls and verifier decisions, so a failure can be placed in the integration code, the tool design or the model output.

## Implementation plan

Six phases, each ending in something that runs and can be written up; only the Claude port happens before the exam on 27 November.

**Repository layout (additions to vexproof)**

```text
src/vexproof/
  llm/              types.py (extended), anthropic.py (new), meta.py, structured.py,
                    recording.py, budget.py (per-target budgets, cache-aware cost),
                    pricing.py (new), tools.py (new: ToolSpec, ToolCall)
  evidence/         trace.py (loop on native tools), edges.py (new: typed edges),
                    paths.py, clear.py, apply.py
  symbols/          select.py, verify.py, drift.py (new: version-drift mapping)
  sources/          git.py, fixfind.py (new: fix-commit discovery)
  prompts/          versioned prompt files, plus frameworks/ (django.md, flask.md, fastapi.md)
  mcp_server/       server.py, resources.py (new)
  web/              existing app, plus drafts and approval
  evaluate/         score.py, markdown.py, plus bench.py and injection/ (new)
  cli.py            existing commands, plus investigate, approve, trace, bench
integrations/claude-code/
  .mcp.json, skills/triage-dependency-alerts/SKILL.md, hooks/check_install.py
eval/               gold/, dynamic/workloads/, results/ (existing, extended)
docs/adr/           0013 onwards for each decision in this doc
```

The benchmark dataset lives in its own repository so others can cite and extend it.

### Phase 0: Claude port (now to 26 Nov, alongside exam prep)

- [x] Make clears independent of the pick (ADR 0020); a recount shows all 30 existing clears survive the stricter rule, so this changes no published result
- [x] Extend `ModelRequest` and `ModelResponse`, adapt `MetaTransport`, and prove with a test that a one-message, no-tool request hashes exactly as `key()` does today, so every existing recording replays
- [x] Add `AnthropicTransport` for `symbol_pick` using structured outputs, explicit effort, typed errors, retry, and handlers for `refusal` and `max_tokens` (as `ClaudeTransport` in `llm/claude.py`)
- [x] Run one shop scan on Claude and record cost, refusals and agreement with existing picks (Haiku 5.5 and Opus 5.5: `eval/results/claude-tiers-shop-1aa90f6.md`)
- [x] Change `RecordingTransport` to store every content block (text, thinking with its signature, tool-use blocks with their IDs) and replay them unchanged; add effort and thinking settings to the key only when set
- [x] Raise output limits for thinking models (pick, trace loop, `check-model` ping)
- [x] Make `BudgetTransport` count cache reads and writes; add `pricing.py` with a per-model price table
- [x] Run `vexproof check-model` and both Django scans on each Claude tier (done: `check-model` on all three tiers, the shop scan on all three, justdjango on Haiku 5.5; Sonnet 5.5 and Opus 5.5 on justdjango moved to after Phase 2, when the cached review loop makes them cheaper and the numbers stay current)

Phase 0 has about eight days alongside exam preparation. The first four tasks are the minimum; if time runs short, the rest move to the start of Phase 1.

Acceptance: all 355 existing tests pass; a table of cost and pick agreement per tier exists; every existing Muse recording replays under an unchanged key, and a Claude scan replays offline from its own recordings.

### Phase 1: Benchmark (weeks 1 to 3, from 28 Nov)

Begin with a two-day feasibility check before any labelling: confirm each candidate project installs and runs its tests from a lockfile or container, then run the current pipeline and count deterministic clears. If ten projects will not install, go ahead with six. Count independent groups, not clears. If they yield fewer than 150 groups, restate the false-clear target for the number available (60 groups gives a 5% bound) before the benchmark is built, not after, and prefer adding projects with different package versions over adding alerts.

- [ ] Choose and pin 10 or more third-party projects
- [ ] Build the tracing harness and workload scripts per project
- [ ] Label 100 or more advisories and confirm each by a second method
- [ ] Implement `vexproof bench` with the metrics and both confidence bounds, per clear and per module group, with the grouping rule in code
- [ ] Publish baseline results for the current pipeline

Acceptance: the benchmark repo is public with a licence and a changelog; the baseline report is reproducible from one command.

### Phase 2: Agent loop (week 4)

- [ ] Convert `Tracer._review` to native tool calls with append-only history; confirm cache reads in the usage records
- [ ] Move synonym and wrapper repair into the Muse adapter
- [ ] Add typed edges with one verifier check per kind, starting with signals and registries, each anchored in reached code; template edges wait for a Django template parser
- [ ] Run the loop, one target at a time in report order, on targets with no candidate path; add per-target budgets and trace recording
- [ ] Add version-drift mapping with its similarity check
- [ ] Move the Django notes into framework files
- [ ] Run the benchmark with and without each addition

Acceptance: the picked-but-no-path group on the tuning set is halved; zero new false clears; every agent verdict has a verifier-written evidence chain.

### Phase 3: MCP server and Claude Code (week 5)

- [ ] Build the FastMCP server with the seven tools, two resources and one prompt
- [ ] Add drafts, the interactive approve command, the review UI page, and the export rule for unapproved clears in both the CLI and the web download
- [ ] Write the skill, the install hook and the project settings
- [ ] Test end to end from Claude Code on a real repository

Acceptance: a fresh clone can be triaged from Claude Code with one config file; an exported `not_affected` statement exists only for an alert whose approval record matches the hash of its deciding facts, and every unapproved clear exports as `under_investigation` with a pending-review note; `vexproof approve` refuses when run from Claude Code's shell or from CI; a `curl` POST to the web approve endpoint without the same-origin header and form token is refused. The install hook is optional and not part of this test.

### Phase 4: Injection suite (week 6)

- [ ] Write 30 or more attack cases with coded pass conditions
- [ ] Run across tiers and record the attack success rate
- [ ] Fix any failure at the capability or verifier level, not in the prompt

Acceptance: zero wrong clears and zero out-of-policy tool calls; results published including any attacks that succeeded before the fix.

### Phase 5: Release (week 7)

- [ ] Run the held-out evaluation once and publish the numbers unchanged
- [ ] Write the README, threat model and benchmark documentation
- [ ] Record the demo and publish the first two write-ups
- [ ] Submit function-level data for a handful of advisories upstream

Acceptance: tagged release, public results page, and at least one upstream contribution opened.

**Stack**

| Layer | Choice |
| --- | --- |
| Language and tooling | Python 3.12, uv, ruff, strict mypy, pytest |
| Model access | Anthropic Python SDK; Claude Agent SDK evaluated in Phase 2 |
| Schemas | Pydantic v2 |
| MCP | FastMCP, stdio transport |
| Existing base | Syft, OSV, OpenVEX, FastAPI, Docker |
| Storage | SQLite plus the on-disk response cache |
| CI | GitHub Actions: replay tests on every push, live benchmark weekly |

## Engineering standards

These are the decisions that are expensive to reverse, so each is fixed now and recorded as an architecture decision record before code is written.

**Decisions to record (ADR 0013 onwards)**

| ADR | Decision | Why it is costly to change later |
| --- | --- | --- |
| 0013 | Requests are message lists with optional tools; transports are vendor adapters | Every call site and every recording depends on the request shape |
| 0014 | Loops use native tool calls and append-only history | Cache economics and replay keys both rest on a stable prefix |
| 0015 | A model output is admitted only with a named deterministic check | This is the product's safety argument |
| 0016 | Typed edges: one check per edge kind, added as code | Evidence records and the VEX export carry the edge kind |
| 0017 | The MCP surface is read and propose only; approval is human | Clients will be built against the tool list |
| 0018 | Model tier is chosen per purpose in config, with measured escalation | Cost reports and benchmarks are keyed by purpose and model |
| 0019 | The benchmark has a held-out split that prompts never see | A leaked split cannot be repaired after the fact |
| 0021 | `main` is frozen for good at `v0.1.0`; `develop` is the trunk | The video, the case study and every clone of `v0.1.0` depend on it |

**Model calls**

- **One purpose, one prompt file, one schema, one version.** Keep the existing naming (`symbol_pick.v1`). Tool descriptions are part of the prompt version.
- **Stable prefix first.** The API matches the cache prefix in the order tools, system, messages, separately per model, so keep tool definitions, the system prompt and framework notes identical across every loop in a scan, then target context, then the growing history. Never edit or shorten earlier turns in place; compact only at a defined step, into a new recorded request.
- **Enforce structure at the API, validate again in code.** Use structured outputs for answers and strict tools with automatic tool choice for actions; never a forced tool call. Keep Pydantic validation and the one repair retry. Move the synonym and wrapper repair into the Muse adapter so it cannot mask a Claude regression.
- **Read the stop reason.** Truncation, refusal, tool use and normal completion are four different outcomes with four different handlers.
- **Typed failures, never silent defaults.** A failed or refused call leaves the alert open with a reason. It never counts as "no path".
- **Retries belong to the transport.** Backoff with jitter on rate-limit and overload responses, honouring the server's retry hint; no retries on validation errors beyond the single repair.
- **Budgets at three levels.** Per target, per purpose and per run, in tokens, with cache reads and writes counted at their own prices.
- **Tier by purpose, not by habit.** Start each purpose on the smallest tier that passes `check-model`; escalate one target at a time on a stated trigger by rerunning its loop on the larger model, since neither thinking blocks nor the cache carry across models, and let the benchmark show whether the escalation pays.
- **Batch what nobody is waiting for.** Benchmark runs, backfills and report explanations go through the batch interface.
- **Framework knowledge is data.** Move the Django notes out of the prompt into `prompts/frameworks/`, loaded only for frameworks the project uses.

**Tools**

- Each tool does one thing, has a description that says when to use it and what it returns, and takes few, typed parameters.
- Tools are read-only. Anything that changes state is a proposal checked by the verifier.
- Results are short, bounded and paginated, and carry file and line so they can be cited.
- Errors are returned as results the model can act on ("unknown function: use a qualified name shown earlier", as the code does now), not raised.
- Paths are resolved and confined before any read.

**Untrusted input**

- Keep wrapping advisory text, diffs and source in data tags that the content cannot close, as `select.py` already does.
- Treat that wrapping as a courtesy to the model. The security property is that the model has no action that can cause harm.
- Every new input source gets at least one case in the injection suite before it ships.

**Reproducibility and testing**

- The recording key covers model, prompt version, system prompt, messages, tools and schema. Any change to one of them is a new key. A loop either replays from start to finish or runs live from start to finish: if any step misses its recording, the whole loop reruns live, because recorded thinking blocks only work in the account that produced them and must never be mixed into a live conversation. This applies in `cache` mode. In `replay` mode, which CI uses, a missing recording stays an error, as it is today, so CI never spends tokens.
- All tests stay offline against the scripted transport. Live calls happen only in `test_live_smoke.py` and the weekly benchmark.
- Each new purpose ships with gold labels and a `check-model` threshold before it is enabled by default.
- Keep strict typing, the architecture test and the current coverage level; new modules join the import rules.

**Observability**

- Log one structured record per model call: purpose, model, token counts by kind, latency, stop reason, cache hit, alert ID. Never log keys or full prompts at the default level.
- Every agent run stores a trace that `vexproof trace` can print.
- The report keeps showing abstention as a metric, now split by cause.

**Configuration and secrets**

- Provider, model per purpose, budgets and prices live in settings, not in code. Keep reading the key from the environment only.
- Pin SDK versions and record the model ID in every recording and report.

## Repository and release plan

The work stays in [henrymbuguak/vexproof](https://github.com/henrymbuguak/vexproof) under the same name, on short branches merged into `develop`. `main` stays frozen for good at `v0.1.0`, the hackathon version (ADR 0021). Only the benchmark dataset gets a repository of its own.

**Why the same repository and name**

- The design extends code that already exists there: the transport layer, the review loop, the verifier, the recordings and the decision records. A fork would copy them and drift.
- The case study, demo video and hackathon listing all link to this repository. `develop` is the default branch, so readers land on the current work, and its README opens with a link to `v0.1.0` and the command to clone exactly that version.
- One continuous history shows the weakest claim being found and fixed, which is the story worth telling.
- The name describes VEX statements with proof. It never named a model.

**State today (18 Nov 2026)**

- `main` is frozen at `0f8c70a`, tagged `v0.1.0`. A ruleset blocks updates, deletion and force pushes, with no bypass.
- `develop` is the default branch. A ruleset requires a pull request, the `check` status check on an up-to-date branch, linear history and squash merges, and blocks force pushes and deletion.
- A tag ruleset on `v*` blocks moving or deleting release tags.
- The Dependabot updates proposed against `main` were applied to `develop` instead (#14), along with a fix for CVE-2026-126360 in `opentelemetry-api`. That CVE stays in `v0.1.0`, which is frozen.
- Version `0.1.0` in `pyproject.toml`.
- CI runs lint, types, offline tests and a dependency audit on every pull request and on every push to `develop`.

**Before any new work**

- [x] Tag the current commit `v0.1.0`, so the version the case study describes stays reachable
- [x] Create `develop` from `v0.1.0`, make it the default branch, and freeze `main`
- [x] Apply the Dependabot updates on `develop` and close their pull requests against `main`
- [x] Protect `develop` (pull request, `check`, linear history, squash only) and the `v*` tags
- [x] Commit this design as `docs/design.md` and add ADRs 0013 to 0021 as proposed

**Branching**

- One short branch per task, cut from `develop` and named by phase: `p0/request-types`, `p0/anthropic-transport`, `p2/native-tools`. No long-lived feature branch.
- Every task reaches `develop` as one squash commit, through a pull request that passes `check`. Nothing is pushed to `develop` directly, and nothing reaches `main` at all.
- Every merge keeps `develop` releasable. New behaviour arrives behind configuration: Claude is a second transport, and Muse Spark stays the default until the benchmark supports switching it.
- A change to a prompt, a tool description or a schema ships with its new version file and its recordings in the same pull request.

**Releases**

| Tag | Contents | When |
| --- | --- | --- |
| `v0.1.0` | The hackathon version, as described in the case study; also `main`, frozen | Done, 18 Nov 2026 |
| `v0.2.0` | Claude transport, extended request types, pick-independent clears | End of Phase 0 |
| `v0.3.0` | Loop on native tools, typed edges, version-drift mapping | End of Phase 2 |
| `v0.4.0` | MCP server, approval flow, Claude Code plugin | End of Phase 3 |
| `v1.0.0` | Injection suite passed, held-out results published | End of Phase 5 |

Release tags go on `develop`; `main` never moves. Each release gets a changelog entry and a results file under `eval/results/`, named by commit as the existing ones are.

**Separate repositories**

- **Benchmark dataset.** Labels, project pins and workload scripts live apart from the tool, with their own licence and changelog, so others can cite and extend them. Give it a neutral name without "vexproof" in it; a benchmark branded as one tool's test suite is less likely to be adopted. The runner (`vexproof bench`) stays in this repository and takes the dataset path as an argument.
- **Claude Code plugin.** Keep it in `integrations/claude-code/` here. Split it out only if a plugin marketplace requires a repository of its own.

## Coverage of the Claude Developer learning outcomes

The project exercises six of the eight outcomes in Anthropic's [Developer Foundations prep course](https://anthropic-partners.skilljar.com/path/claude-certified-developer-foundations) in depth; three small additions close most of the rest.

| Prep course outcome | Where the project exercises it | Depth |
| --- | --- | --- |
| How Claude works: tokens, context as a budget, non-determinism, tiers, SDK versus REST | Budgets, tier per purpose, recorded calls, transport layer | Strong |
| Production prompts: system prompts, XML tags, examples, constraints, diagnosing a weak prompt | Versioned prompt files, data tags, `check-model` gate | Strong |
| Tool schemas, the tool-use loop, extended thinking across turns | Review loop on native tools | Strong; thinking tuned through effort |
| Production agents: orchestration, memory scope, human checkpoints | Loop design, approved-hop memory within a scan, approval of clears | Strong; memory scope undocumented |
| Claude Code: permissions, project context, Skills and plugins, MCP without leaking credentials | MCP server, skill, hook, project settings | Strong; no plugin packaging |
| Evaluation, tracing, cost, latency and reliability budgets | Benchmark, traces, CI gate, cost per tier | Strong |
| Security: prompt injection, untrusted input, secrets | Threat model, injection suite | Strong |
| Reusable accelerator, platform choice, contributing assets back | Open benchmark, upstream data | Partial |

**Additions**

- **Extended thinking, measured.** Thinking is always on with the current models, so the lever is effort. Raise effort for the function pick only when confidence is low or the first answer fails verification, and report whether it changes accuracy per dollar. Keep the higher setting only if the benchmark shows a gain.
- **Plugin packaging.** Ship the skill, the install hook and the MCP configuration as one Claude Code plugin, so the integration installs in one step.
- **Memory scope, written down.** Approved hops are remembered within one scan of one project and never across projects. An approval is keyed by call site and by the receiver type carried along the path, so a hop approved in one context is not reused where the carried type differs. That type exists today only as the private \_Hop.self\_type in evidence/paths.py, so keying on it adds a field to the public Hop model and to findings.json; the change is additive and older files still load. State this in the agent section and test it.
- **Platform note.** Keep the transport configurable for Claude through a cloud provider. Document it; do not build or test it for this release.

**Prep course modules and the project work that practises each**

The prep course has five modules, taken in order, totalling 774 minutes (about 13 hours). Its listed prerequisites begin with Claude 101 and Claude Code 101.

| # | Module | Length | Project work that practises it |
| --- | --- | --- | --- |
| 1 | MSO Foundations | 57 min | Tier per purpose, token budgets, price table |
| 2 | Production-Grade Prompting, Agents & Tool Use | 209 min | `AnthropicTransport`, enforced schemas, the review loop on native tools |
| 3 | Claude Code, MCP & Integration | 142 min | MCP server, skill, install hook, project settings, plugin packaging |
| 4 | Production Engineering, Evals & Security | 211 min | Benchmark, traces, CI gate, threat model, injection suite |
| 5 | Accelerators & IP Contribution | 155 min | Open benchmark repository, upstream advisory data, reusable integration |

Only Phase 0 of the project runs before the exam, so modules 1 and 2 get hands-on practice from it; modules 3 to 5 are studied first and built afterwards.

## Response to the external review

Nine of the review's points are accepted and one is accepted in part, all now in the design; two were already true in the code, and one recommendation is rejected because it would create false clears.

| Review point | Verdict | What changed |
| --- | --- | --- |
| The agent raises reachable counts but cannot raise clears | Accepted | Stated in the value section; the clear target is checked for feasibility before the benchmark is built |
| 150 clears must come from deterministic rules | Accepted | Phase 1 opens with a count of clears; the bound is restated for the number available |
| A wrong pick can support a false clear | Accepted, and worse than stated | The code confirms it: a verified pick narrows the modules that decide a clear. Clears now require every changed module outside the closure. New ADR 0020 |
| No fix commit should never clear | Already true | The code never clears at module level without fix-commit candidates; recorded as a test |
| Ask for every implicated function, not one | Already true | The pick schema returns a list; kept |
| Dropping old tool results breaks the prompt cache | Accepted | History is append-only; compaction means a new recorded request |
| A tampered cache can replay a give-up | Accepted in part | The cache is declared trusted local state; the worst outcome is an open alert, which is undecided, not suppressed |
| Line numbers from the model waste turns | Accepted | The model supplies names and patterns; the verifier finds lines |
| Approved hops may be context-dependent | Accepted | Approvals are keyed by call site and carried receiver type |
| The install hook is too strict | Accepted | Block on unknown packages and high or critical reachable alerts; warn otherwise |
| Tracing cannot see false clears on unexercised paths | Accepted | Results are labelled "not contradicted"; coverage is reported; an import sweep is added |
| Two weeks is too short for the benchmark | Accepted | Phase 1 is three weeks with a feasibility check and a six-project fallback; the release moves to week 7 |
| Clear alerts whose patched file is absent from the wheel | Rejected | See below |

**Why the file-presence clear is rejected**

The review expects a large gain from clearing alerts whose patched file is not in the installed package. In the sample scan the 33 non-Python alerts are 32 Pillow and 1 Django; the changed files are 36 C sources, 1 header and 3 JavaScript files. A C source is absent from a wheel because it has been compiled into the extension module that the wheel does ship, so its absence says nothing about exposure. The existing code refuses to clear when a fix changes compiled code, and that rule stays. Files that are neither shipped nor compiled into anything shipped, such as documentation or tests, may be categorised, and can be cleared only when the fix changes nothing else.

**ADR to add**

| ADR | Decision | Why it is costly to change later |
| --- | --- | --- |
| 0020 | A model may block a clear, never enable or narrow one; clears use only fix commits the advisory references | Every published false-clear figure and every VEX statement depends on it |

## Risks and open questions

The largest risk is the benchmark, not the code: labelling is slow, and the held-out result may be worse than the current small-sample numbers suggest.

| Risk | Likelihood | Impact | Mitigation |
| --- | --- | --- | --- |
| Labelling 100 advisories overruns two weeks | High | Schedule | Ship at 60 with the interval stated; keep labelling in the background |
| The agent does not move the open rate much | Medium | Headline claim | Report it anyway; categorise why alerts stay open, which is itself a useful result |
| A false clear appears on held-out data | Medium | Safety claim | Publish it with the root cause and the rule that now prevents it |
| Tracing coverage is too low to judge reachability | Medium | Benchmark validity | Score untraced functions as unknown; add workloads for the worst-covered projects |
| API cost of repeated benchmark runs | Medium | Budget | Batch API, caching, smallest passing tier per purpose, replay from cache in CI |
| Model refuses a security-flavoured request (Medium, not Low: the cyber classifier can decline benign security work) | Medium | Coverage | Record refusals as model\_refused and report the rate; enable server-side fallback for synchronous calls; rerun refused batch items synchronously; prompts ask for code reading, never exploitation |
| Claude API or Claude Code features change | Medium | Rework | Isolate behind the provider and integration folders; pin SDK versions |
| Scope creep into other languages or hosting | Medium | Schedule | Non-goals are fixed until the release tag |

**Open questions**

- [ ] Which Claude models are available on the account, and what are their current prices and cache rules?
- [ ] Which effort level does each purpose need on each tier to pass check-model?
- [ ] Hand-written loop or Agent SDK as the default, decided at the end of Phase 2?
- [ ] Which 10 projects? Criteria: active, real test suite, pinned vulnerable dependencies, permissive licence.
- [ ] Which upstream database accepts function-level data for Python advisories, and in what format?
- [ ] Does the install hook belong in this repo or in the governed dependency pipeline's repo?

**Sources**

- [How I built vexproof](https://hlab.tech/posts/how-i-built-vexproof-python-vulnerability-reachability/): pipeline, evaluation figures, stated limitations and future work
- [HLAB projects](https://hlab.tech/projects/): test counts and stack
- [Claude docs](https://docs.claude.com): reference for API, MCP and Claude Code details to confirm during implementation

* [Claude Certified Developer - Foundations Prep Course](https://anthropic-partners.skilljar.com/path/claude-certified-developer-foundations): the eight learning outcomes mapped in the coverage section; the lesson list sits behind partner sign-in and was not read
* [Claude Developer learning path](https://anthropic-partners.skilljar.com/path/claude-developer): course list behind partner sign-in; not read
