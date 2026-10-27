"""Plain test helpers with no vexproof imports, usable from the first chapter step onwards."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

FIXTURES = Path(__file__).parent / "fixtures"
OSV = "https://osv.test"
KEV = "https://kev.test/kev.json"
EPSS = "https://epss.test/epss"


def fixture_json(relative: str) -> Any:
    return json.loads((FIXTURES / relative).read_text(encoding="utf-8"))
