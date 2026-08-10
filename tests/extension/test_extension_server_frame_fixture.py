"""Keep the canonical server-frame fixture in sync with literal API replies."""

from __future__ import annotations

import ast
import json
from pathlib import Path

from mordred_hermes.extension import extension_api

_FIXTURE = Path(__file__).parent / "fixtures" / "server_frames.json"


def _literal_frame_types() -> set[str]:
    source = Path(extension_api.__file__)
    tree = ast.parse(source.read_text(encoding="utf-8"), filename=str(source))
    frame_types: set[str] = set()
    for node in ast.walk(tree):
        if not isinstance(node, ast.Dict):
            continue
        for key, value in zip(node.keys, node.values, strict=True):
            if not (isinstance(key, ast.Constant) and key.value == "type"):
                continue
            assert isinstance(value, ast.Constant) and isinstance(value.value, str), (
                f"api.py:{node.lineno} builds a dynamic frame type; add an explicit "
                "literal so protocol inventory remains auditable"
            )
            frame_types.add(value.value)
    return frame_types


def test_fixture_covers_every_literal_server_frame_type() -> None:
    frames = json.loads(_FIXTURE.read_text(encoding="utf-8"))
    assert isinstance(frames, list)
    fixture_types = {frame["type"] for frame in frames}

    assert fixture_types == _literal_frame_types()
