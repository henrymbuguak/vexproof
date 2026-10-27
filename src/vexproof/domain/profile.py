"""Load and validate a service profile from YAML."""

from __future__ import annotations

from pathlib import Path

import yaml
from pydantic import ValidationError

from vexproof.domain.models import ServiceProfile
from vexproof.errors import IngestError


def load_service_profile(path: Path) -> ServiceProfile:
    try:
        raw = yaml.safe_load(path.read_text(encoding="utf-8"))
    except OSError as exc:
        raise IngestError(f"cannot read service profile {path}: {exc}") from exc
    except yaml.YAMLError as exc:
        raise IngestError(f"service profile {path} is not valid YAML: {exc}") from exc
    if not isinstance(raw, dict):
        raise IngestError(f"service profile {path} must be a YAML mapping")
    try:
        return ServiceProfile.model_validate(raw)
    except ValidationError as exc:
        fields = ", ".join(".".join(str(p) for p in err["loc"]) for err in exc.errors())
        raise IngestError(f"service profile {path} has invalid fields: {fields}") from exc
