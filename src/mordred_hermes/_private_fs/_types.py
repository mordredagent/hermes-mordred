"""Internal storage contract, without platform imports."""

from __future__ import annotations

from contextlib import AbstractContextManager
from dataclasses import dataclass
from typing import Literal, Protocol

Reason = Literal["unsafe", "unsupported", "missing", "exists", "busy", "access_denied", "io"]
CommitState = Literal["not_committed", "uncertain"]


class PrivateFSError(OSError):
    """A classified refusal; uncertain publication must never be blindly retried."""

    def __init__(
        self,
        reason: Reason,
        operation: str,
        *,
        native_code: int | None = None,
        commit_state: CommitState = "not_committed",
    ) -> None:
        super().__init__(f"private filesystem {operation}: {reason} ({commit_state})")
        self.reason = reason
        self.operation = operation
        self.native_code = native_code
        self.commit_state = commit_state


@dataclass(frozen=True)
class FileIdentity:
    volume: int
    file_id: bytes


class PrivateTransaction(Protocol):
    def read_bytes(self, name: str, *, max_bytes: int) -> bytes: ...
    def create_bytes(self, name: str, data: bytes) -> None: ...
    def replace_bytes(self, name: str, data: bytes) -> None: ...


class PrivateDirectory(Protocol):
    def read_bytes(self, name: str, *, max_bytes: int) -> bytes: ...
    def transaction(self, *, blocking: bool = True) -> AbstractContextManager[PrivateTransaction]: ...


def validate_leaf(name: str) -> None:
    if (
        not name
        or name in (".", "..")
        or any(c in name for c in "/\\:\x00")
        or name == ".mordred-fs.lock"
        or name.startswith(".mordred-fs-tmp-")
    ):
        raise PrivateFSError("unsafe", "leaf")
