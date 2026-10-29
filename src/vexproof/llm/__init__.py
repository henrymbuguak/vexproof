"""Model layer: every call to a language model goes through here.

Layers, each a `Transport` wrapping the next:
  BudgetTransport -> RecordingTransport -> MetaTransport (or a scripted fake in tests)
and `StructuredCaller` on top, which turns a Pydantic schema into a validated object.
"""
