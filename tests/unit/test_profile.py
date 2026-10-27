from __future__ import annotations

from pathlib import Path

import pytest

from vexproof.domain.profile import load_service_profile
from vexproof.errors import IngestError

EXAMPLE = Path(__file__).parents[2] / "examples" / "service_profile.yaml"


def test_example_profile_loads() -> None:
    profile = load_service_profile(EXAMPLE)
    assert profile.internet_facing is True
    assert profile.criticality == "high"


def test_invalid_field_is_named(tmp_path: Path) -> None:
    bad = tmp_path / "p.yaml"
    bad.write_text(
        "service: x\ninternet_facing: true\nhandles_personal_data: false\ncriticality: extreme\n"
    )
    with pytest.raises(IngestError, match="criticality"):
        load_service_profile(bad)


@pytest.mark.parametrize("content", ["- just\n- a list\n", "service: [unclosed\n"])
def test_non_mapping_or_broken_yaml_rejected(tmp_path: Path, content: str) -> None:
    bad = tmp_path / "p.yaml"
    bad.write_text(content)
    with pytest.raises(IngestError):
        load_service_profile(bad)


def test_missing_file_rejected(tmp_path: Path) -> None:
    with pytest.raises(IngestError, match="cannot read"):
        load_service_profile(tmp_path / "absent.yaml")
