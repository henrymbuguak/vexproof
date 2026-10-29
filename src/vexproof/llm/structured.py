"""Ask for a Pydantic object, get a validated Pydantic object, or a clear error."""

from __future__ import annotations

import json
import re
from typing import Any

from pydantic import BaseModel, ValidationError

from vexproof.llm.types import ModelOutputInvalidError, ModelRequest, Transport

_FENCE = re.compile(r"^```(?:json)?\s*(.*?)\s*```$", re.DOTALL)


def strict_schema(model: type[BaseModel]) -> dict[str, Any]:
    """JSON schema in the strict form structured-output APIs require.

    Every object lists all of its properties as required and forbids extra keys; titles and
    defaults are removed. Optional values must therefore be expressed as nullable types.
    """
    schema = model.model_json_schema()

    def tidy(node: object) -> None:
        if isinstance(node, dict):
            node.pop("title", None)
            node.pop("default", None)
            if node.get("type") == "object" and "properties" in node:
                node["required"] = list(node["properties"])
                node["additionalProperties"] = False
            for value in node.values():
                tidy(value)
        elif isinstance(node, list):
            for item in node:
                tidy(item)

    tidy(schema)
    return schema


def _parse[M: BaseModel](text: str, schema: type[M]) -> M:
    body = text.strip()
    fenced = _FENCE.match(body)
    if fenced:
        body = fenced.group(1)
    return schema.model_validate(json.loads(body))


class StructuredCaller:
    def __init__(self, transport: Transport) -> None:
        self._transport = transport

    @property
    def model(self) -> str:
        return self._transport.model

    def ask[M: BaseModel](
        self,
        schema: type[M],
        *,
        purpose: str,
        prompt_version: str,
        system: str,
        user: str,
        max_output_tokens: int = 2000,
    ) -> M:
        request = ModelRequest(
            purpose=purpose,
            prompt_version=prompt_version,
            system=system,
            user=user,
            schema_name=schema.__name__,
            schema=strict_schema(schema),
            max_output_tokens=max_output_tokens,
        )
        reply = self._transport.complete(request)
        try:
            return _parse(reply.text, schema)
        except (ValueError, ValidationError) as first:
            repair = ModelRequest(
                purpose=purpose,
                prompt_version=prompt_version,
                system=system,
                user=(
                    f"{user}\n\nYour previous reply was not valid: {_brief(first)}\n"
                    "Reply again with only a JSON object that matches the schema."
                ),
                schema_name=request.schema_name,
                schema=request.schema,
                max_output_tokens=max_output_tokens,
            )
            second = self._transport.complete(repair)
            try:
                return _parse(second.text, schema)
            except (ValueError, ValidationError) as exc:
                raise ModelOutputInvalidError(
                    f"{purpose}: reply did not match {schema.__name__}: {_brief(exc)}; "
                    f"the reply began {second.text.strip()[:160]!r}"
                ) from exc


def _brief(exc: Exception) -> str:
    return str(exc).splitlines()[0][:300]
