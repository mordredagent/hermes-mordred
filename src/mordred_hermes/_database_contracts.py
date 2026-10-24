"""Inert database-domain values; safe to import below custody and SQL layers."""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Literal, Protocol


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


class NativeDatabaseLock(Protocol):
    identity: RootIdentity

    def acquire(self, *, shared: bool, timeout: float) -> None: ...
    def check(self) -> None: ...
    def close(self) -> None: ...
