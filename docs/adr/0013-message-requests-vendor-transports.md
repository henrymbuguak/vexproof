# ADR 0013: Requests are message lists with optional tools; transports are vendor adapters

**Status:** accepted, implemented in part · **Date:** 2026-11-18 · See `docs/design.md`, "Model
provider layer"

Implemented on 2026-11-19: the request and response types, the backward-compatible key, the
`MetaTransport` adapter and recordings that keep stop reasons, cache tokens and tool calls.
To follow: `AnthropicTransport`, and recordings that keep thinking blocks.

## Context
`ModelRequest` holds one system string and one user string, and the only transport speaks the
OpenAI-style Responses and Chat APIs. Claude needs multi-turn history, tool definitions and
results, cache breakpoints, effort settings and a stop reason, none of which fit that shape.
Every call site and every recording depends on the request shape, so it is costly to change twice.

## Decision
- `ModelRequest` carries `system`, a tuple of `messages`, optional `tools`, an optional schema
  and `cache_points`. `ModelResponse` adds tool calls, the stop reason, cache-read and
  cache-write tokens and latency.
- Transports are adapters, one per vendor: `MetaTransport` (OpenAI-compatible: Muse Spark,
  Ollama) and `AnthropicTransport` (the Anthropic SDK). Nothing above `llm/` imports a vendor SDK,
  and the architecture test enforces it.
- The recording key stays backward compatible: a request with one user message, no tools and no
  effort setting hashes exactly as `key()` does today. Messages, tools, effort and thinking
  settings join the hash only when present; `cache_points` never do.
- Recordings store every content block of a response (text, thinking with its signature,
  tool-use blocks with their IDs) and replay them unchanged.

## Consequences
Every existing Muse recording keeps replaying, and a test proves it. Muse Spark stays the
default until the benchmark supports switching. Recording files grow, since they now hold
thinking blocks.
