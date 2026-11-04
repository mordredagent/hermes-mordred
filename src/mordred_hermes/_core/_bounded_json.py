"""Bounded JSON decoding for externally supplied metadata and vault manifests."""

from __future__ import annotations

import json
from typing import Any, Final

_MAX_JSON_DEPTH: Final = 128


class JSONDepthError(ValueError):
    """JSON exceeds the supported maximum of 128 nested arrays/objects."""


class _BoundedJSONDecoder(json.JSONDecoder):
    """Refuse JSON beyond 128 containers before native JSON decoding."""

    def raw_decode(self, s: str, idx: int = 0) -> tuple[Any, int]:
        depth = 0
        quoted = False
        escaped = False
        for char in s[idx:]:
            if quoted:
                if escaped:
                    escaped = False
                elif char == "\\":
                    escaped = True
                elif char == '"':
                    quoted = False
            elif char == '"':
                quoted = True
            elif char in "[{":
                depth += 1
                if depth > _MAX_JSON_DEPTH:
                    raise JSONDepthError("JSON nesting exceeds 128 containers")
            elif char in "]}":
                depth -= 1
        return super().raw_decode(s, idx)
