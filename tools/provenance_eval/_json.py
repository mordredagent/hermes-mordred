"""Strict JSON field readers: typed values out, :class:`FormatError` for anything else."""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from enum import StrEnum
from typing import TypeVar

__all__ = [
    "FormatError",
    "read_bool",
    "read_bool_map",
    "read_enum",
    "read_int",
    "read_list",
    "read_obj",
    "read_opt_int",
    "read_opt_str",
    "read_str",
    "read_str_map",
    "read_strs",
]

_E = TypeVar("_E", bound=StrEnum)


class FormatError(ValueError):
    """Malformed or unsupported JSON input; the message is a content-free code."""


def read_obj(value: object) -> Mapping[str, object]:
    if not isinstance(value, dict) or not all(isinstance(key, str) for key in value):
        raise FormatError("expected_object")
    return value


def read_list(data: Mapping[str, object], key: str) -> Sequence[object]:
    value = data.get(key)
    if not isinstance(value, list):
        raise FormatError(f"expected_list:{key}")
    return value


def read_str(data: Mapping[str, object], key: str) -> str:
    value = data.get(key)
    if not isinstance(value, str):
        raise FormatError(f"expected_str:{key}")
    return value


def read_opt_str(data: Mapping[str, object], key: str) -> str | None:
    return None if data.get(key) is None else read_str(data, key)


def read_int(data: Mapping[str, object], key: str) -> int:
    value = data.get(key)
    if isinstance(value, bool) or not isinstance(value, int):
        raise FormatError(f"expected_int:{key}")
    return value


def read_opt_int(data: Mapping[str, object], key: str) -> int | None:
    return None if data.get(key) is None else read_int(data, key)


def read_bool(data: Mapping[str, object], key: str) -> bool:
    value = data.get(key)
    if not isinstance(value, bool):
        raise FormatError(f"expected_bool:{key}")
    return value


def read_strs(data: Mapping[str, object], key: str) -> tuple[str, ...]:
    values = read_list(data, key)
    if not all(isinstance(item, str) for item in values):
        raise FormatError(f"expected_strs:{key}")
    return tuple(str(item) for item in values)


def read_str_map(data: Mapping[str, object], key: str) -> dict[str, str]:
    raw = read_obj(data.get(key))
    if not all(isinstance(item, str) for item in raw.values()):
        raise FormatError(f"expected_str_map:{key}")
    return {name: str(item) for name, item in raw.items()}


def read_bool_map(data: Mapping[str, object], key: str) -> dict[str, bool]:
    raw = read_obj(data.get(key))
    if not all(isinstance(item, bool) for item in raw.values()):
        raise FormatError(f"expected_bool_map:{key}")
    return {name: bool(item) for name, item in raw.items()}


def read_enum(data: Mapping[str, object], key: str, enum: type[_E]) -> _E:
    try:
        return enum(read_str(data, key))
    except ValueError as exc:
        raise FormatError(f"bad_enum:{key}") from exc
