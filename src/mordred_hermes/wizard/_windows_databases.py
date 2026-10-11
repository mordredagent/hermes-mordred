"""Observe retained, unsupported database protection without opening databases."""

from __future__ import annotations

from pathlib import Path

from .._config_io import CanonicalPaths, canonical_session
from .._private_fs import PrivateFSError
from ._windows_gates import classify_exception

_STATE_NAMES = frozenset(
    {"db-encryption.marker", "db-encryption.pending", "db-decryption.pending", "db-encryption.journal.json"}
)
_LIMIT = 4096


def state_names(home: Path) -> tuple[str, ...]:
    """Checked, bounded, nonblocking names in this home and its owning profile root.

    Resolve no links and create nothing. An unavailable/unsafe observation is
    never an assertion that database state is absent. This is not a database
    discovery or decryption implementation.
    """
    homes = (home.parent.parent, home) if home.parent.name.casefold() == "profiles" else (home,)
    found: set[str] = set()
    for base in homes:
        with canonical_session(CanonicalPaths(base), scope="policy", blocking=False) as canonical:
            if canonical.home_directory_identity() is None:
                continue
            try:
                with canonical.borrow_mordred_transaction() as tx:
                    names = tx.list_names(max_entries=_LIMIT)
            except PrivateFSError as exc:
                if exc.reason == "missing" and exc.operation == "mordred_transaction":
                    continue
                raise
            found.update(name.casefold() for name in names if name.casefold() in _STATE_NAMES)
    return tuple(sorted(found))


def refusal(home: Path) -> str | None:
    """Why Windows teardown must stop, or checked absence of known DB state."""
    try:
        retained = state_names(home)
    except (OSError, RuntimeError, ValueError) as exc:
        return (
            f"database protection state could not be verified ({classify_exception(exc)}); "
            "resolve the checked storage refusal and review a new uninstall plan"
        )
    if retained:
        return (
            "this home retains database protection state, which Windows cannot restore; "
            "decrypt or reconcile the home on macOS before using or uninstalling Mordred here"
        )
    return None
