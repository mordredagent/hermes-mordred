"""Operation-local reset authority; a pending journal never authorizes writers."""

from __future__ import annotations

import os
import threading
from collections.abc import Iterator
from contextlib import contextmanager
from pathlib import Path
from weakref import WeakKeyDictionary

from .._core._database_contracts import DatabaseRefused
from .._core._database_lifecycle import ExclusiveLease
from . import _storage


class ResetAuthorization:
    def __init__(self) -> None:
        raise DatabaseRefused("reset authorization must be issued by a checked reset")


_issued: WeakKeyDictionary[ResetAuthorization, tuple[Path, ExclusiveLease, int, int]] = WeakKeyDictionary()


def check_reset_access(
    home: Path, authorization: ResetAuthorization | None = None, *, component: str | None = None
) -> None:
    if authorization is None:
        _storage.assert_keyvault_active(home / "mordred/keyvault")
        return
    record = _issued.get(authorization) if type(authorization) is ResetAuthorization else None
    if record is None or record[0] != home or record[2:] != (os.getpid(), threading.get_ident()):
        raise DatabaseRefused("reset authorization is closed or belongs to another profile")
    from ._database_authority import resolve_database_domain
    from ._reset_journal import _load_reset_journal

    domain = resolve_database_domain(home)
    ExclusiveLease.assert_held(record[1], domain.root)
    journal = _load_reset_journal(home / "mordred/keyvault")
    if journal.connected is None or journal.connected["home"] != str(home):
        raise DatabaseRefused("reset authorization requires the exact connected-data journal")
    if journal.connected["stage"] not in {"database", "mail", "telegram"} or (
        component is not None and journal.connected["stage"] != component
    ):
        raise DatabaseRefused("reset credential authority is outside its retirement stage")


@contextmanager
def reset_authorization(home: Path, lease: ExclusiveLease) -> Iterator[ResetAuthorization]:
    from ._database_authority import resolve_database_domain

    ExclusiveLease.assert_held(lease, resolve_database_domain(home).root)
    issued = object.__new__(ResetAuthorization)
    _issued[issued] = home, lease, os.getpid(), threading.get_ident()
    try:
        check_reset_access(home, issued)
        yield issued
    finally:
        _issued.pop(issued, None)
