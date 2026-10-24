"""Inert database-domain values; safe to import below custody and SQL layers."""

from __future__ import annotations

import json
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Literal, Protocol, cast


class DatabaseRefused(RuntimeError):
    """Database authority or exclusion cannot be established safely."""


class DatabaseBusy(DatabaseRefused):
    """A runtime or maintenance operation already owns this database domain."""


@dataclass(frozen=True)
class RootIdentity:
    platform: Literal["darwin", "linux", "win32"]
    volume: int
    file_id: str
    owner: str


@dataclass(frozen=True)
class NativeSnapshot:
    root: RootIdentity
    provider: Literal["secure-enclave", "tpm", "cng"]
    generation: str
    record_sha256: str


@dataclass(frozen=True)
class Dependency:
    path: Path
    kind: Literal["database", "pending", "journal", "backup", "unknown"]
    generation: str | None


@dataclass(frozen=True)
class Inventory:
    entries: tuple[Dependency, ...]
    complete: bool


class GuardedConnection(Protocol):
    """Held SQL objects own rollback/close when their authority is revoked."""

    def invalidate(self) -> None: ...


class NativeDatabaseLock(Protocol):
    identity: RootIdentity

    def acquire(self, *, shared: bool, timeout: float) -> None: ...
    def check(self) -> None: ...
    def close(self) -> None: ...


def _binding_object(value: object, fields: set[str]) -> dict[str, object]:
    if not isinstance(value, dict) or set(value) != fields:
        raise DatabaseRefused("invalid database source binding fields")
    return cast(dict[str, object], value)


def _binding_pairs(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            raise DatabaseRefused("duplicate database source binding field")
        result[key] = value
    return result


def _binding_decimal(value: object) -> str:
    if not isinstance(value, str) or re.fullmatch(r"0|[1-9][0-9]{0,19}", value) is None or int(value) >= 1 << 64:
        raise DatabaseRefused("invalid database source POSIX identity")
    return value


def _binding_hex(value: object, size: int) -> str:
    if not isinstance(value, str) or re.fullmatch(r"[0-9a-f]{" + str(size) + r"}", value) is None:
        raise DatabaseRefused("invalid database source hexadecimal field")
    return value


def decode_database_source_binding(data: bytes) -> NativeSnapshot:
    """Decode the POSIX v1 source record without I/O, custody or SQL imports.

    Only canonical field encodings are admitted. Windows uses its checked native
    memory-role generation rather than this independently enrolled record.
    """
    if not isinstance(data, bytes) or not 0 < len(data) <= 4096 or not data.endswith(b"\n"):
        raise DatabaseRefused("invalid database source binding size or terminator")
    try:
        value = json.loads(data.decode("utf-8"), object_pairs_hook=_binding_pairs)
    except (UnicodeError, ValueError, RecursionError) as exc:
        raise DatabaseRefused("malformed database source binding") from exc
    record = _binding_object(value, {"version", "root", "provider", "generation", "record_sha256"})
    if type(record["version"]) is not int or record["version"] != 1:
        raise DatabaseRefused("unsupported database source binding version")
    root = _binding_object(record["root"], {"platform", "volume", "file_id", "owner"})
    volume = root["volume"]
    if type(volume) is not int or not 0 <= volume < 1 << 64:
        raise DatabaseRefused("invalid database source volume")
    platform: Literal["linux", "darwin"]
    provider: Literal["tpm", "secure-enclave"]
    if root["platform"] == "linux" and record["provider"] == "tpm":
        platform, provider = "linux", "tpm"
    elif root["platform"] == "darwin" and record["provider"] == "secure-enclave":
        platform, provider = "darwin", "secure-enclave"
    else:
        raise DatabaseRefused("unsupported database source platform/provider")
    identity = RootIdentity(platform, volume, _binding_decimal(root["file_id"]), _binding_decimal(root["owner"]))
    return NativeSnapshot(
        identity, provider, _binding_hex(record["generation"], 32), _binding_hex(record["record_sha256"], 64)
    )
